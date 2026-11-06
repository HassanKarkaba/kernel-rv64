//! A bounded, allocation-free flattened-device-tree reader for the virt profile.
//! Parsing uses byte copies; no unchecked pointer or packed struct casts.
const MAX_DTB: usize = 2 * 1024 * 1024;
const MAX_DEPTH: usize = 24;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Bounds,
    Structure,
    Capacity,
    Unsupported,
    Missing,
    Geometry,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    pub size: u64,
}
impl Region {
    pub fn end(self) -> Option<u64> {
        self.base.checked_add(self.size)
    }
    pub fn contains(self, base: u64, size: u64) -> bool {
        base >= self.base
            && base
                .checked_add(size)
                .zip(self.end())
                .is_some_and(|(a, b)| a <= b)
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Device {
    pub region: Region,
    pub irq: u32,
}
#[derive(Debug)]
pub struct Platform {
    pub ram: Region,
    pub timebase: u64,
    pub hart: u64,
    pub uart: Device,
    pub plic: Region,
    pub plic_context: u32,
    pub virtio: [Device; 8],
    pub virtio_count: usize,
    pub reserved: [Region; 32],
    pub reserved_count: usize,
}
#[derive(Clone, Copy)]
struct Node<'a> {
    name: &'a [u8],
    kind: &'a [u8],
    compatible: &'a [u8],
    reg: &'a [u8],
    interrupts: &'a [u8],
    extended: &'a [u8],
    addr_cells: u32,
    size_cells: u32,
    parent_addr: u32,
    parent_size: u32,
    phandle: u32,
    enabled: bool,
    reserved: bool,
    translated: bool,
    saw_child: bool,
    irq_parent: u32,
}
impl Node<'_> {
    const EMPTY: Self = Self {
        name: &[],
        kind: &[],
        compatible: &[],
        reg: &[],
        interrupts: &[],
        extended: &[],
        addr_cells: 2,
        size_cells: 1,
        parent_addr: 2,
        parent_size: 1,
        phandle: 0,
        enabled: true,
        reserved: false,
        translated: false,
        saw_child: false,
        irq_parent: 0,
    };
    fn compatible(&self, name: &[u8]) -> bool {
        self.compatible.split(|b| *b == 0).any(|s| s == name)
    }
    fn region(&self) -> Result<Region, Error> {
        if self.translated {
            return Err(Error::Unsupported);
        }
        let stride = ((self.parent_addr + self.parent_size) * 4) as usize;
        if stride == 0 || self.reg.len() != stride {
            return Err(Error::Unsupported);
        }
        Ok(Region {
            base: cells(self.reg, self.parent_addr)?,
            size: cells(&self.reg[self.parent_addr as usize * 4..], self.parent_size)?,
        })
    }
}
fn be32(b: &[u8], at: usize) -> Result<u32, Error> {
    let s = b
        .get(at..at.checked_add(4).ok_or(Error::Bounds)?)
        .ok_or(Error::Bounds)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}
fn be64(b: &[u8], at: usize) -> Result<u64, Error> {
    Ok((u64::from(be32(b, at)?) << 32) | u64::from(be32(b, at + 4)?))
}
fn cells(b: &[u8], n: u32) -> Result<u64, Error> {
    match n {
        0 => Ok(0),
        1 => Ok(u64::from(be32(b, 0)?)),
        2 => be64(b, 0),
        _ => Err(Error::Unsupported),
    }
}
fn cstr(b: &[u8]) -> Result<(&[u8], usize), Error> {
    let end = b.iter().position(|x| *x == 0).ok_or(Error::Structure)?;
    Ok((&b[..end], end + 1))
}
fn aligned(n: usize) -> Result<usize, Error> {
    n.checked_add(3).map(|x| x & !3).ok_or(Error::Bounds)
}
fn overlap(a: core::ops::Range<usize>, b: core::ops::Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

pub fn total_size(header: &[u8]) -> Result<usize, Error> {
    if header.len() < 40 || be32(header, 0)? != 0xd00dfeed {
        return Err(Error::Header);
    }
    let n = be32(header, 4)? as usize;
    if !(40..=MAX_DTB).contains(&n) {
        return Err(Error::Bounds);
    }
    Ok(n)
}
pub fn parse(bytes: &[u8]) -> Result<Platform, Error> {
    let total = total_size(bytes)?;
    let bytes = bytes.get(..total).ok_or(Error::Bounds)?;
    if be32(bytes, 20)? < 17 || be32(bytes, 24)? > 17 {
        return Err(Error::Unsupported);
    }
    let st = be32(bytes, 8)? as usize;
    let ss = be32(bytes, 12)? as usize;
    let rs = be32(bytes, 16)? as usize;
    let sl = be32(bytes, 36)? as usize;
    let nl = be32(bytes, 32)? as usize;
    let se = st.checked_add(sl).ok_or(Error::Bounds)?;
    let ne = ss.checked_add(nl).ok_or(Error::Bounds)?;
    if st < 40
        || ss < 40
        || rs < 40
        || !st.is_multiple_of(4)
        || !rs.is_multiple_of(8)
        || se > total
        || ne > total
        || overlap(st..se, ss..ne)
    {
        return Err(Error::Bounds);
    }
    let structure = &bytes[st..se];
    let strings = &bytes[ss..ne];
    let mut p = Platform {
        ram: Region::default(),
        timebase: 0,
        hart: 0,
        uart: Device::default(),
        plic: Region::default(),
        plic_context: 0,
        virtio: [Device::default(); 8],
        virtio_count: 0,
        reserved: [Region::default(); 32],
        reserved_count: 0,
    };
    let mut r = rs;
    loop {
        let end = r.checked_add(16).ok_or(Error::Bounds)?;
        if end > total || overlap(r..end, st..se) || overlap(r..end, ss..ne) {
            return Err(Error::Bounds);
        }
        let region = Region {
            base: be64(bytes, r)?,
            size: be64(bytes, r + 8)?,
        };
        r = end;
        if region.base == 0 && region.size == 0 {
            break;
        }
        add_reserved(&mut p, region)?;
    }
    let mut stack = [Node::EMPTY; MAX_DEPTH];
    let mut depth = 0;
    let mut at = 0;
    let mut roots = 0;
    let mut cpus = 0;
    let mut cpu_phandle = 0;
    let mut plic_extended = &[][..];
    let mut plic_phandle = 0;
    let mut uart_parent = 0;
    let mut virtio_parents = [0; 8];
    let mut finished = false;
    while at < structure.len() {
        let token = be32(structure, at)?;
        at += 4;
        match token {
            1 => {
                if depth == MAX_DEPTH {
                    return Err(Error::Capacity);
                }
                let (name, used) = cstr(structure.get(at..).ok_or(Error::Bounds)?)?;
                at = aligned(at.checked_add(used).ok_or(Error::Bounds)?)?;
                if at > structure.len() {
                    return Err(Error::Bounds);
                }
                let parent = if depth == 0 {
                    Node::EMPTY
                } else {
                    stack[depth - 1]
                };
                if depth == 0 {
                    roots += 1;
                    if roots != 1 || !name.is_empty() {
                        return Err(Error::Structure);
                    }
                }
                if depth > 0 {
                    stack[depth - 1].saw_child = true;
                }
                stack[depth] = Node {
                    name,
                    parent_addr: parent.addr_cells,
                    parent_size: parent.size_cells,
                    enabled: parent.enabled,
                    translated: parent.translated,
                    irq_parent: parent.irq_parent,
                    reserved: parent.reserved || name == b"reserved-memory",
                    ..Node::EMPTY
                };
                depth += 1;
            }
            2 => {
                if depth == 0 {
                    return Err(Error::Structure);
                }
                depth -= 1;
                let n = stack[depth];
                if !n.enabled {
                    continue;
                }
                if n.kind == b"memory" {
                    if p.ram.size != 0 {
                        return Err(Error::Unsupported);
                    }
                    p.ram = n.region()?;
                }
                if n.kind == b"cpu" {
                    cpus += 1;
                    p.hart = cells(n.reg, n.parent_addr)?;
                }
                if n.compatible(b"riscv,cpu-intc") {
                    if cpu_phandle != 0 {
                        return Err(Error::Unsupported);
                    }
                    cpu_phandle = n.phandle;
                }
                if n.compatible(b"ns16550a") {
                    if p.uart.region.size != 0 {
                        return Err(Error::Unsupported);
                    }
                    uart_parent = n.irq_parent;
                    p.uart = Device {
                        region: n.region()?,
                        irq: single_irq(n.interrupts)?,
                    };
                }
                if n.compatible(b"riscv,plic0") || n.compatible(b"sifive,plic-1.0.0") {
                    if p.plic.size != 0 {
                        return Err(Error::Unsupported);
                    }
                    plic_phandle = n.phandle;
                    p.plic = n.region()?;
                    plic_extended = n.extended;
                }
                if n.compatible(b"virtio,mmio") {
                    if p.virtio_count == 8 {
                        return Err(Error::Capacity);
                    }
                    virtio_parents[p.virtio_count] = n.irq_parent;
                    p.virtio[p.virtio_count] = Device {
                        region: n.region()?,
                        irq: single_irq(n.interrupts)?,
                    };
                    p.virtio_count += 1;
                }
                if n.reserved && !n.reg.is_empty() {
                    add_reserved(&mut p, n.region()?)?;
                }
            }
            3 => {
                if depth == 0 {
                    return Err(Error::Structure);
                }
                let len = be32(structure, at)? as usize;
                let nameoff = be32(structure, at + 4)? as usize;
                at += 8;
                let end = at.checked_add(len).ok_or(Error::Bounds)?;
                let value = structure.get(at..end).ok_or(Error::Bounds)?;
                at = aligned(end)?;
                if at > structure.len() {
                    return Err(Error::Bounds);
                }
                let (name, _) = cstr(strings.get(nameoff..).ok_or(Error::Bounds)?)?;
                let n = &mut stack[depth - 1];
                if n.saw_child {
                    return Err(Error::Structure);
                }
                match name {
                    b"ranges" => n.translated |= !value.is_empty(),
                    b"interrupt-parent" => n.irq_parent = single_u32(value)?,
                    b"#address-cells" => {
                        n.addr_cells = single_u32(value)?;
                        if n.addr_cells > 4 {
                            return Err(Error::Unsupported);
                        }
                    }
                    b"#size-cells" => {
                        n.size_cells = single_u32(value)?;
                        if n.size_cells > 4 {
                            return Err(Error::Unsupported);
                        }
                    }
                    b"device_type" => n.kind = exact_string(value)?,
                    b"compatible" => {
                        if value.last() != Some(&0) {
                            return Err(Error::Structure);
                        }
                        n.compatible = value;
                    }
                    b"reg" => n.reg = value,
                    b"interrupts" => n.interrupts = value,
                    b"interrupts-extended" => n.extended = value,
                    b"phandle" => n.phandle = single_u32(value)?,
                    b"status" => {
                        let s = exact_string(value)?;
                        n.enabled &= s == b"okay" || s == b"ok";
                    }
                    b"timebase-frequency" if n.name == b"cpus" => {
                        p.timebase = u64::from(single_u32(value)?)
                    }
                    _ => {}
                }
            }
            4 => {}
            9 => {
                if depth != 0 || roots != 1 {
                    return Err(Error::Structure);
                }
                finished = true;
                break;
            }
            _ => return Err(Error::Structure),
        }
    }
    if !finished || structure[at..].iter().any(|b| *b != 0) {
        return Err(Error::Structure);
    }
    if cpus != 1
        || p.hart != 0
        || p.ram
            != (Region {
                base: 0x80000000,
                size: 256 * 1024 * 1024,
            })
    {
        return Err(Error::Geometry);
    }
    if p.timebase == 0
        || p.uart.region.size < 8
        || p.plic.size < 0x201008
        || p.virtio_count == 0
        || cpu_phandle == 0
    {
        return Err(Error::Missing);
    }
    if !plic_extended.len().is_multiple_of(8) {
        return Err(Error::Structure);
    }
    let mut context = None;
    for i in 0..plic_extended.len() / 8 {
        if be32(plic_extended, i * 8)? == cpu_phandle && be32(plic_extended, i * 8 + 4)? == 9 {
            if context.is_some() {
                return Err(Error::Unsupported);
            }
            context = Some(i as u32);
        }
    }
    p.plic_context = context.ok_or(Error::Missing)?;
    if plic_phandle == 0
        || uart_parent != plic_phandle
        || virtio_parents[..p.virtio_count]
            .iter()
            .any(|id| *id != plic_phandle)
        || u64::from(p.plic_context) * 0x1000 + 0x200008 > p.plic.size
        || u64::from(p.plic_context) * 0x80 + 0x2080 > p.plic.size
        || core::iter::once(p.uart.region)
            .chain(core::iter::once(p.plic))
            .chain(p.virtio[..p.virtio_count].iter().map(|d| d.region))
            .any(|r| {
                !r.base.is_multiple_of(4)
                    || r.size > 0x4000000
                    || r.end().is_none_or(|end| end > 0x40000000)
            })
    {
        return Err(Error::Unsupported);
    }
    if p.uart.irq == 0
        || p.uart.irq >= 1024
        || p.virtio[..p.virtio_count]
            .iter()
            .any(|d| d.irq == 0 || d.irq >= 1024 || d.region.size < 0x200)
    {
        return Err(Error::Unsupported);
    }
    Ok(p)
}
fn single_u32(v: &[u8]) -> Result<u32, Error> {
    if v.len() != 4 {
        return Err(Error::Structure);
    }
    be32(v, 0)
}
fn single_irq(v: &[u8]) -> Result<u32, Error> {
    single_u32(v)
}
fn exact_string(v: &[u8]) -> Result<&[u8], Error> {
    let (s, n) = cstr(v)?;
    if n != v.len() {
        return Err(Error::Structure);
    }
    Ok(s)
}
fn add_reserved(p: &mut Platform, r: Region) -> Result<(), Error> {
    if r.size == 0 || r.end().is_none() {
        return Err(Error::Bounds);
    }
    if p.reserved_count == p.reserved.len() {
        return Err(Error::Capacity);
    }
    p.reserved[p.reserved_count] = r;
    p.reserved_count += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_short_and_oversized_blob_without_pointer_use() {
        for n in 0..40 {
            assert_eq!(total_size(&[0; 40][..n]), Err(Error::Header));
        }
        let mut h = [0; 40];
        h[..4].copy_from_slice(&0xd00dfeedu32.to_be_bytes());
        h[4..8].copy_from_slice(&((MAX_DTB + 1) as u32).to_be_bytes());
        assert_eq!(total_size(&h), Err(Error::Bounds));
    }
    #[test]
    fn region_end_is_checked() {
        assert!(
            !Region {
                base: u64::MAX - 1,
                size: 4
            }
            .contains(u64::MAX, 1)
        );
        assert!(Region { base: 10, size: 10 }.contains(10, 10));
        assert!(!Region { base: 10, size: 10 }.contains(19, 2));
    }
}
