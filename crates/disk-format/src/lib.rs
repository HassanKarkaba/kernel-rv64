#![no_std]
#![forbid(unsafe_code)]

//! KFS version 1 codecs, bounded consistency scan and full-block redo protocol.
//! No disk structure is transmuted into a Rust structure. The caller owns I/O
//! serialization, DMA lifetime, and the transition to FAILED after an I/O error.

pub const BLOCK_SIZE: usize = 4096;
pub const SECTOR_SIZE: usize = 512;
pub const BLOCK_COUNT: u32 = 16384;
pub const IMAGE_SIZE: u64 = BLOCK_SIZE as u64 * BLOCK_COUNT as u64;
pub const INODE_COUNT: usize = 256;
pub const DATA_START: u32 = 32;
pub const MAX_FILE_SIZE: u32 = 4194304;
pub const JOURNAL_CAPACITY: usize = 16;
pub type Block = [u8; BLOCK_SIZE];
pub type Uuid = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Io,
    Size,
    Magic,
    Version,
    Checksum,
    Padding,
    Bounds,
    Name,
    Generation,
    Shape,
    Ownership,
    Namespace,
    Journal,
    SequenceExhausted,
    Capacity,
}
pub type Result<T> = core::result::Result<T, Error>;

pub trait BlockDevice {
    /// The implementation must reject out-of-range transfers and expose only
    /// successful, fully validated device completions.
    fn read_block(&mut self, block: u32, out: &mut Block) -> Result<()>;
    fn write_block(&mut self, block: u32, data: &Block) -> Result<()>;
    /// Writes exactly sector 8, never the remaining seven sectors of block 1.
    fn write_commit(&mut self, data: &[u8; SECTOR_SIZE]) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
    fn byte_len(&self) -> u64;
    /// Optional bounded diagnostic hook; must not perform filesystem I/O.
    /// 100..109 are TX-A..E begin/durable pairs; 110..113 are validated
    /// replay begin, homes durable, retirement begin, retirement durable.
    fn trace(&mut self, _event: u64, _sequence: u64) {}
}

pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}
fn u16_at(b: &[u8], p: usize) -> u16 {
    u16::from_le_bytes([b[p], b[p + 1]])
}
fn u32_at(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}
fn u64_at(b: &[u8], p: usize) -> u64 {
    u64::from_le_bytes([
        b[p],
        b[p + 1],
        b[p + 2],
        b[p + 3],
        b[p + 4],
        b[p + 5],
        b[p + 6],
        b[p + 7],
    ])
}
fn put32(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_le_bytes());
}
fn zero(b: &[u8]) -> bool {
    b.iter().all(|x| *x == 0)
}
fn check_crc(b: &[u8]) -> Result<()> {
    let n = b.len();
    if crc32c(&b[..n - 4]) != u32_at(b, n - 4) {
        return Err(Error::Checksum);
    }
    Ok(())
}
fn seal(b: &mut [u8]) {
    let n = b.len();
    let crc = crc32c(&b[..n - 4]);
    put32(b, n - 4, crc);
}
fn bit(b: &[u8; 2048], n: u32) -> bool {
    b[n as usize / 8] & (1 << (n % 8)) != 0
}
fn set_bit(b: &mut [u8; 2048], n: u32) {
    b[n as usize / 8] |= 1 << (n % 8);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superblock {
    pub uuid: Uuid,
}
impl Superblock {
    pub fn decode(b: &Block) -> Result<Self> {
        if &b[..8] != b"KFS00001" {
            return Err(Error::Magic);
        }
        check_crc(b)?;
        if u32_at(b, 8) != 1 {
            return Err(Error::Version);
        }
        let fields = [
            (12, 4096),
            (40, 512),
            (44, 256),
            (48, 256),
            (52, 16),
            (56, 1),
            (60, 2),
            (64, 3),
            (68, 19),
            (72, 20),
            (76, 8),
            (80, 28),
            (84, 4),
            (88, 32),
            (92, 0),
        ];
        if u64_at(b, 16) != u64::from(BLOCK_COUNT)
            || fields.iter().any(|(p, v)| u32_at(b, *p) != *v)
        {
            return Err(Error::Bounds);
        }
        if !zero(&b[96..4092]) {
            return Err(Error::Padding);
        }
        let mut uuid = [0; 16];
        uuid.copy_from_slice(&b[24..40]);
        Ok(Self { uuid })
    }
    pub fn encode(&self, out: &mut Block) {
        out.fill(0);
        out[..8].copy_from_slice(b"KFS00001");
        for (p, v) in [
            (8, 1),
            (12, 4096),
            (40, 512),
            (44, 256),
            (48, 256),
            (52, 16),
            (56, 1),
            (60, 2),
            (64, 3),
            (68, 19),
            (72, 20),
            (76, 8),
            (80, 28),
            (84, 4),
            (88, 32),
        ] {
            put32(out, p, v);
        }
        put64(out, 16, u64::from(BLOCK_COUNT));
        out[24..40].copy_from_slice(&self.uuid);
        seal(out);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inode {
    pub live: bool,
    pub size: u32,
    pub generation: u64,
    pub direct: [u32; 12],
    pub indirect: u32,
}
impl Inode {
    pub const EMPTY: Self = Self {
        live: false,
        size: 0,
        generation: 0,
        direct: [0; 12],
        indirect: 0,
    };
    pub fn decode(b: &[u8; 128]) -> Result<Self> {
        check_crc(b)?;
        if b[0] > 1 || !zero(&b[1..4]) || !zero(&b[68..124]) {
            return Err(Error::Padding);
        }
        let mut inode = Self {
            live: b[0] == 1,
            size: u32_at(b, 4),
            generation: u64_at(b, 8),
            direct: [0; 12],
            indirect: u32_at(b, 64),
        };
        for (i, p) in inode.direct.iter_mut().enumerate() {
            *p = u32_at(b, 16 + i * 4);
        }
        if inode.size > MAX_FILE_SIZE {
            return Err(Error::Size);
        }
        if inode.live && inode.generation == 0 {
            return Err(Error::Generation);
        }
        if !inode.live
            && (inode.size != 0 || inode.indirect != 0 || inode.direct.iter().any(|p| *p != 0))
        {
            return Err(Error::Shape);
        }
        Ok(inode)
    }
    pub fn encode(&self, out: &mut [u8; 128]) -> Result<()> {
        out.fill(0);
        out[0] = u8::from(self.live);
        put32(out, 4, self.size);
        put64(out, 8, self.generation);
        for (i, p) in self.direct.iter().enumerate() {
            put32(out, 16 + i * 4, *p);
        }
        put32(out, 64, self.indirect);
        seal(out);
        Self::decode(out).map(|_| ())
    }
}

pub fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 47
        && name != b"."
        && name != b".."
        && name
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c))
}
pub fn valid_path(path: &[u8]) -> bool {
    path.first() == Some(&b'/') && valid_name(&path[1..])
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub inode: u16,
    pub generation: u64,
    pub name: [u8; 47],
    pub name_len: u8,
}
impl DirectoryEntry {
    pub fn decode(b: &[u8; 64]) -> Result<Option<Self>> {
        if zero(b) {
            return Ok(None);
        }
        check_crc(b)?;
        let inode = u16_at(b, 0);
        let len = usize::from(b[2]);
        if inode == 0 || usize::from(inode) > INODE_COUNT || len == 0 || len > 47 {
            return Err(Error::Bounds);
        }
        if b[3] != 0 || !zero(&b[12 + len..60]) {
            return Err(Error::Padding);
        }
        if !valid_name(&b[12..12 + len]) {
            return Err(Error::Name);
        }
        let generation = u64_at(b, 4);
        if generation == 0 {
            return Err(Error::Generation);
        }
        let mut name = [0; 47];
        name[..len].copy_from_slice(&b[12..12 + len]);
        Ok(Some(Self {
            inode,
            generation,
            name,
            name_len: len as u8,
        }))
    }
    pub fn encode(&self, b: &mut [u8; 64]) -> Result<()> {
        let len = usize::from(self.name_len);
        if len > 47 {
            return Err(Error::Name);
        }
        b.fill(0);
        b[..2].copy_from_slice(&self.inode.to_le_bytes());
        b[2] = self.name_len;
        put64(b, 4, self.generation);
        b[12..12 + len].copy_from_slice(&self.name[..len]);
        seal(b);
        Self::decode(b).map(|_| ())
    }
}

pub fn decode_bitmap(b: &Block, bits: &mut [u8; 2048]) -> Result<u64> {
    check_crc(b)?;
    if !zero(&b[2056..4092]) {
        return Err(Error::Padding);
    }
    bits.copy_from_slice(&b[..2048]);
    if bits[..4] != [255; 4] {
        return Err(Error::Ownership);
    }
    Ok(u64_at(b, 2048))
}
pub fn encode_bitmap(bits: &[u8; 2048], sequence: u64, out: &mut Block) -> Result<()> {
    if bits[..4] != [255; 4] {
        return Err(Error::Ownership);
    }
    out.fill(0);
    out[..2048].copy_from_slice(bits);
    put64(out, 2048, sequence);
    seal(out);
    Ok(())
}

/// The caller should allocate this bounded scratch outside a small trap stack.
pub struct ScanScratch {
    actual: [u8; 2048],
    expected: [u8; 2048],
    live: [bool; 256],
    generations: [u64; 256],
    linked: [bool; 256],
    names: [[u8; 47]; 256],
    lengths: [u8; 256],
    block: Block,
    indirect: Block,
}
impl Default for ScanScratch {
    fn default() -> Self {
        Self::new()
    }
}
impl ScanScratch {
    pub const fn new() -> Self {
        Self {
            actual: [0; 2048],
            expected: [0; 2048],
            live: [false; 256],
            generations: [0; 256],
            linked: [false; 256],
            names: [[0; 47]; 256],
            lengths: [0; 256],
            block: [0; 4096],
            indirect: [0; 4096],
        }
    }
    fn claim(&mut self, p: u32) -> Result<()> {
        if !(DATA_START..BLOCK_COUNT).contains(&p) {
            return Err(Error::Bounds);
        }
        if bit(&self.expected, p) {
            return Err(Error::Ownership);
        }
        set_bit(&mut self.expected, p);
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountInfo {
    pub uuid: Uuid,
    pub sequence: u64,
    pub files: u16,
    pub used_blocks: u32,
}
pub fn scan<D: BlockDevice>(dev: &mut D, s: &mut ScanScratch) -> Result<MountInfo> {
    if dev.byte_len() != IMAGE_SIZE {
        return Err(Error::Size);
    }
    dev.read_block(0, &mut s.block)?;
    let sb = Superblock::decode(&s.block)?;
    dev.read_block(1, &mut s.block)?;
    if !zero(&s.block) {
        return Err(Error::Journal);
    }
    dev.read_block(19, &mut s.block)?;
    let sequence = decode_bitmap(&s.block, &mut s.actual)?;
    s.expected.fill(0);
    s.expected[..4].fill(255);
    s.live.fill(false);
    s.linked.fill(false);
    s.lengths.fill(0);
    for ix in 0..256usize {
        // Reading the containing table block per inode keeps scratch independent
        // of any mutable device buffer. The capacity is finite and bounded.
        dev.read_block(20 + (ix / 32) as u32, &mut s.block)?;
        let mut record = [0; 128];
        record.copy_from_slice(&s.block[ix % 32 * 128..(ix % 32 + 1) * 128]);
        let inode = Inode::decode(&record)?;
        s.live[ix] = inode.live;
        s.generations[ix] = inode.generation;
        if !inode.live {
            continue;
        }
        let count = inode.size.div_ceil(4096) as usize;
        if (count > 12) != (inode.indirect != 0) {
            return Err(Error::Shape);
        }
        if inode.indirect != 0 {
            s.claim(inode.indirect)?;
            dev.read_block(inode.indirect, &mut s.indirect)?;
        }
        for n in 0..1024usize {
            let p = if n < 12 {
                inode.direct[n]
            } else if inode.indirect != 0 {
                u32_at(&s.indirect, (n - 12) * 4)
            } else {
                0
            };
            if n < count {
                s.claim(p)?;
            } else if p != 0 {
                return Err(Error::Shape);
            }
            if n + 1 == count && inode.size % 4096 != 0 {
                dev.read_block(p, &mut s.block)?;
                if !zero(&s.block[(inode.size % 4096) as usize..]) {
                    return Err(Error::Padding);
                }
            }
        }
        if inode.indirect != 0 && !zero(&s.indirect[1012 * 4..]) {
            return Err(Error::Shape);
        }
    }
    let mut files = 0u16;
    for ix in 0..256usize {
        dev.read_block(28 + (ix / 64) as u32, &mut s.block)?;
        let mut record = [0; 64];
        record.copy_from_slice(&s.block[ix % 64 * 64..(ix % 64 + 1) * 64]);
        if let Some(e) = DirectoryEntry::decode(&record)? {
            let ino = usize::from(e.inode) - 1;
            if !s.live[ino] || s.linked[ino] || s.generations[ino] != e.generation {
                return Err(Error::Namespace);
            }
            for prior in 0..ix {
                if s.lengths[prior] == e.name_len && s.names[prior] == e.name {
                    return Err(Error::Namespace);
                }
            }
            s.linked[ino] = true;
            s.names[ix] = e.name;
            s.lengths[ix] = e.name_len;
            files += 1;
        }
    }
    if s.live != s.linked {
        return Err(Error::Namespace);
    }
    if s.actual != s.expected {
        return Err(Error::Ownership);
    }
    Ok(MountInfo {
        uuid: sb.uuid,
        sequence,
        files,
        used_blocks: s.actual.iter().map(|x| x.count_ones()).sum(),
    })
}

/// Complete private transaction; at most 16 unique after-images, sorted by home.
/// Insertion never touches disk. Block 19 and the new sequence are mandatory.
pub struct Transaction {
    pub uuid: Uuid,
    pub sequence: u64,
    count: usize,
    targets: [u32; 16],
    images: [Block; 16],
    work: Block,
    descriptor: Block,
    commit_sector: [u8; 512],
}
impl Transaction {
    pub const fn new(uuid: Uuid, sequence: u64) -> Self {
        Self {
            uuid,
            sequence,
            count: 0,
            targets: [0; 16],
            images: [[0; 4096]; 16],
            work: [0; 4096],
            descriptor: [0; 4096],
            commit_sector: [0; 512],
        }
    }
    pub fn count(&self) -> usize {
        self.count
    }
    pub fn reset(&mut self, uuid: Uuid, sequence: u64) {
        self.uuid = uuid;
        self.sequence = sequence;
        self.count = 0;
    }
    pub fn image(&self, target: u32) -> Option<&Block> {
        (0..self.count)
            .find(|i| self.targets[*i] == target)
            .map(|i| &self.images[i])
    }
    pub fn image_mut(&mut self, target: u32) -> Option<&mut Block> {
        let index = (0..self.count).find(|i| self.targets[*i] == target)?;
        Some(&mut self.images[index])
    }
    pub fn insert(&mut self, target: u32, image: &Block) -> Result<()> {
        if !(19..BLOCK_COUNT).contains(&target) {
            return Err(Error::Bounds);
        }
        let pos = (0..self.count)
            .find(|i| self.targets[*i] >= target)
            .unwrap_or(self.count);
        if pos < self.count && self.targets[pos] == target {
            self.images[pos] = *image;
            return Ok(());
        }
        if self.count == 16 {
            return Err(Error::Capacity);
        }
        for i in (pos..self.count).rev() {
            self.targets[i + 1] = self.targets[i];
            self.images[i + 1] = self.images[i];
        }
        self.targets[pos] = target;
        self.images[pos] = *image;
        self.count += 1;
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        if self.sequence == 0 || self.count == 0 || self.count > 16 || self.targets[0] != 19 {
            return Err(Error::Journal);
        }
        let mut bits = [0; 2048];
        if decode_bitmap(&self.images[0], &mut bits)? != self.sequence {
            return Err(Error::Journal);
        }
        for i in 0..self.count {
            if !(19..BLOCK_COUNT).contains(&self.targets[i])
                || (i > 0 && self.targets[i - 1] >= self.targets[i])
            {
                return Err(Error::Journal);
            }
        }
        Ok(())
    }
    fn prepare(&mut self) -> Result<()> {
        self.validate()?;
        self.descriptor.fill(0);
        self.descriptor[..8].copy_from_slice(b"KJDES001");
        self.descriptor[8..24].copy_from_slice(&self.uuid);
        put64(&mut self.descriptor, 24, self.sequence);
        put32(&mut self.descriptor, 32, self.count as u32);
        put32(&mut self.descriptor, 36, 1);
        for i in 0..self.count {
            let p = 64 + i * 16;
            put32(&mut self.descriptor, p, self.targets[i]);
            put32(&mut self.descriptor, p + 4, i as u32);
            put32(&mut self.descriptor, p + 8, crc32c(&self.images[i]));
        }
        seal(&mut self.descriptor);
        Ok(())
    }
    /// Five stages, five flushes. Success is returned only after retirement.
    /// Any error must move the caller's mount state to FAILED; do not retry.
    /// Large encoding buffers belong to this transaction, not the kernel stack.
    pub fn commit<D: BlockDevice>(&mut self, dev: &mut D) -> Result<()> {
        if dev.byte_len() != IMAGE_SIZE {
            return Err(Error::Size);
        }
        self.prepare()?;
        dev.read_block(0, &mut self.work)?;
        if Superblock::decode(&self.work)?.uuid != self.uuid {
            return Err(Error::Journal);
        }
        dev.read_block(19, &mut self.work)?;
        check_crc(&self.work)?;
        if !zero(&self.work[2056..4092]) || self.work[..4] != [255; 4] {
            return Err(Error::Padding);
        }
        let old = u64_at(&self.work, 2048);
        if old == u64::MAX {
            return Err(Error::SequenceExhausted);
        }
        if old + 1 != self.sequence {
            return Err(Error::Journal);
        }
        dev.trace(100, self.sequence);
        self.commit_sector.fill(0);
        dev.write_commit(&self.commit_sector)?;
        dev.flush()?;
        dev.trace(101, self.sequence);
        dev.trace(102, self.sequence);
        dev.write_block(2, &self.descriptor)?;
        for i in 0..self.count {
            dev.write_block(3 + i as u32, &self.images[i])?;
        }
        dev.flush()?;
        dev.trace(103, self.sequence);
        dev.trace(104, self.sequence);
        self.commit_sector[..8].copy_from_slice(b"KJCOM001");
        self.commit_sector[8..24].copy_from_slice(&self.uuid);
        put32(&mut self.commit_sector, 24, 1);
        put32(&mut self.commit_sector, 28, self.count as u32);
        put64(&mut self.commit_sector, 32, self.sequence);
        put32(&mut self.commit_sector, 40, u32_at(&self.descriptor, 4092));
        seal(&mut self.commit_sector);
        dev.write_commit(&self.commit_sector)?;
        dev.flush()?;
        dev.trace(105, self.sequence);
        dev.trace(106, self.sequence);
        for i in 0..self.count {
            dev.write_block(self.targets[i], &self.images[i])?;
        }
        dev.flush()?;
        dev.trace(107, self.sequence);
        dev.trace(108, self.sequence);
        self.commit_sector.fill(0);
        dev.write_commit(&self.commit_sector)?;
        dev.flush()?;
        dev.trace(109, self.sequence);
        Ok(())
    }
}

/// Validates the entire redo set before modifying any home block. After replay,
/// call `scan`; recovery alone does not establish metadata consistency.
pub fn recover<D: BlockDevice>(dev: &mut D, tx: &mut Transaction) -> Result<bool> {
    if dev.byte_len() != IMAGE_SIZE {
        return Err(Error::Size);
    }
    let mut block = [0; 4096];
    dev.read_block(0, &mut block)?;
    let sb = Superblock::decode(&block)?;
    dev.read_block(1, &mut block)?;
    if !zero(&block[512..]) {
        return Err(Error::Padding);
    }
    if zero(&block[..512]) {
        return Ok(false);
    }
    let mut commit = [0; 512];
    commit.copy_from_slice(&block[..512]);
    check_crc(&commit)?;
    if &commit[..8] != b"KJCOM001"
        || commit[8..24] != sb.uuid
        || u32_at(&commit, 24) != 1
        || !zero(&commit[44..508])
    {
        return Err(Error::Journal);
    }
    let count = u32_at(&commit, 28) as usize;
    let seq = u64_at(&commit, 32);
    if count == 0 || count > 16 || seq == 0 {
        return Err(Error::Journal);
    }
    dev.read_block(2, &mut block)?;
    check_crc(&block)?;
    if &block[..8] != b"KJDES001"
        || block[8..24] != sb.uuid
        || u64_at(&block, 24) != seq
        || u32_at(&block, 32) as usize != count
        || u32_at(&block, 36) != 1
        || u32_at(&block, 4092) != u32_at(&commit, 40)
        || !zero(&block[40..64])
        || !zero(&block[64 + count * 16..4092])
    {
        return Err(Error::Journal);
    }
    tx.uuid = sb.uuid;
    tx.sequence = seq;
    tx.count = count;
    for i in 0..count {
        let p = 64 + i * 16;
        let target = u32_at(&block, p);
        if !(19..BLOCK_COUNT).contains(&target)
            || (i > 0 && tx.targets[i - 1] >= target)
            || u32_at(&block, p + 4) != i as u32
            || u32_at(&block, p + 12) != 0
        {
            return Err(Error::Journal);
        }
        tx.targets[i] = target;
        dev.read_block(3 + i as u32, &mut tx.images[i])?;
        if crc32c(&tx.images[i]) != u32_at(&block, p + 8) {
            return Err(Error::Checksum);
        }
    }
    tx.validate()?;
    dev.trace(110, seq);
    for i in 0..count {
        dev.write_block(tx.targets[i], &tx.images[i])?;
    }
    dev.flush()?;
    dev.trace(111, seq);
    dev.trace(112, seq);
    dev.write_commit(&[0; 512])?;
    dev.flush()?;
    dev.trace(113, seq);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_vector() {
        assert_eq!(crc32c(b"123456789"), 0xe3069283);
    }
    #[test]
    fn superblock_canonical() {
        let sb = Superblock { uuid: [7; 16] };
        let mut b = [0; 4096];
        sb.encode(&mut b);
        assert_eq!(Superblock::decode(&b), Ok(sb));
        b[100] = 1;
        seal(&mut b);
        assert_eq!(Superblock::decode(&b), Err(Error::Padding));
    }
    #[test]
    fn free_inode_retains_generation() {
        let i = Inode {
            generation: 42,
            ..Inode::EMPTY
        };
        let mut b = [0; 128];
        assert_eq!(i.encode(&mut b), Ok(()));
        assert_eq!(Inode::decode(&b), Ok(i));
    }
    #[test]
    fn directory_syntax() {
        for n in [b"a".as_slice(), b"a-b_c.9"] {
            assert!(valid_name(n));
        }
        for n in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b"] {
            assert!(!valid_name(n));
        }
    }
    #[test]
    fn zero_directory_is_exception() {
        assert_eq!(DirectoryEntry::decode(&[0; 64]), Ok(None));
    }
    #[test]
    fn transaction_bounds() {
        let mut t = Transaction::new([0; 16], 1);
        assert_eq!(t.insert(18, &[0; 4096]), Err(Error::Bounds));
        for n in 19..35 {
            assert_eq!(t.insert(n, &[0; 4096]), Ok(()));
        }
        assert_eq!(t.insert(35, &[0; 4096]), Err(Error::Capacity));
        assert_eq!(t.insert(20, &[1; 4096]), Ok(()));
    }
}
