//! Strict ELF validation; the returned load plan borrows the immutable snapshot.
use kernel_abi::{EXEC_END, Error, MAX_EXEC_BYTES, USER_START};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct Segment {
    pub offset: usize,
    pub address: u64,
    pub file_size: usize,
    pub memory_size: u64,
    pub flags: u32,
    pub page_start: u64,
    pub page_end: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LoadPlan {
    pub entry: u64,
    pub segments: [Segment; 16],
    pub count: usize,
}
impl LoadPlan {
    pub const EMPTY: Self = Self {
        entry: 0,
        segments: [Segment {
            offset: 0,
            address: 0,
            file_size: 0,
            memory_size: 0,
            flags: 0,
            page_start: 0,
            page_end: 0,
        }; 16],
        count: 0,
    };
}

fn bytes<const N: usize>(image: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let end = offset.checked_add(N).ok_or(Error::NotExecutable)?;
    image
        .get(offset..end)
        .ok_or(Error::NotExecutable)?
        .try_into()
        .map_err(|_| Error::NotExecutable)
}
fn u16_at(image: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(bytes(image, offset)?))
}
fn u32_at(image: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(bytes(image, offset)?))
}
fn u64_at(image: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(bytes(image, offset)?))
}

pub fn validate(image: &[u8]) -> Result<LoadPlan, Error> {
    let mut plan = LoadPlan::EMPTY;
    validate_into(image, &mut plan)?;
    Ok(plan)
}

/// Validate into caller-owned storage, avoiding multiple aggregate return copies
/// on an unoptimized kernel stack. On error the partially written plan is invalid
/// and must not be used; validation itself performs no external mutation.
pub fn validate_into(image: &[u8], plan: &mut LoadPlan) -> Result<(), Error> {
    plan.count = 0;
    plan.entry = 0;
    if image.len() > MAX_EXEC_BYTES {
        return Err(Error::TooBig);
    }
    if image.len() < 64
        || &image[..4] != b"\x7fELF"
        || image[4] != 2
        || image[5] != 1
        || image[6] != 1
        || image[7] != 0
        || u16_at(image, 16)? != 2
        || u16_at(image, 18)? != 243
        || u32_at(image, 20)? != 1
        || u32_at(image, 48)? > 1
        || u16_at(image, 52)? != 64
        || u16_at(image, 54)? != 56
    {
        return Err(Error::NotExecutable);
    }
    let n = usize::from(u16_at(image, 56)?);
    if !(1..=16).contains(&n) {
        return Err(Error::NotExecutable);
    }
    let phoff = usize::try_from(u64_at(image, 32)?).map_err(|_| Error::NotExecutable)?;
    if phoff.checked_add(n * 56).ok_or(Error::NotExecutable)? > image.len() {
        return Err(Error::NotExecutable);
    }
    plan.entry = u64_at(image, 24)?;
    let mut stack_seen = false;
    for i in 0..n {
        let p = phoff + 56 * i;
        let kind = u32_at(image, p)?;
        let flags = u32_at(image, p + 4)?;
        match kind {
            0 => continue,
            0x6474_e551 => {
                if stack_seen || flags & 1 != 0 {
                    return Err(Error::NotExecutable);
                }
                stack_seen = true;
                continue;
            }
            1 => {}
            _ => return Err(Error::NotExecutable),
        }
        if !matches!(flags, 4..=6) {
            return Err(Error::NotExecutable);
        }
        let offset64 = u64_at(image, p + 8)?;
        let address = u64_at(image, p + 16)?;
        let file_size64 = u64_at(image, p + 32)?;
        let memory_size = u64_at(image, p + 40)?;
        if memory_size == 0
            || file_size64 > memory_size
            || u64_at(image, p + 48)? != 4096
            || offset64 % 4096 != address % 4096
        {
            return Err(Error::NotExecutable);
        }
        let file_end = offset64
            .checked_add(file_size64)
            .ok_or(Error::NotExecutable)?;
        if file_end > image.len() as u64 {
            return Err(Error::NotExecutable);
        }
        let end = address
            .checked_add(memory_size)
            .ok_or(Error::NotExecutable)?;
        let page_start = address & !4095;
        let page_end = end.checked_add(4095).ok_or(Error::NotExecutable)? & !4095;
        if page_start < USER_START || page_end > EXEC_END {
            return Err(Error::NotExecutable);
        }
        for old in &plan.segments[..plan.count] {
            if page_start < old.page_end && old.page_start < page_end {
                return Err(Error::NotExecutable);
            }
        }
        plan.segments[plan.count] = Segment {
            offset: usize::try_from(offset64).map_err(|_| Error::NotExecutable)?,
            address,
            file_size: usize::try_from(file_size64).map_err(|_| Error::NotExecutable)?,
            memory_size,
            flags,
            page_start,
            page_end,
        };
        plan.count += 1;
    }
    if !plan.segments[..plan.count]
        .iter()
        .any(|s| s.flags == 5 && plan.entry >= s.address && plan.entry < s.address + s.memory_size)
    {
        return Err(Error::NotExecutable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn elf() -> [u8; 8192] {
        let mut b = [0u8; 8192];
        b[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\0");
        for (o, v) in [(16, 2u16), (18, 243), (52, 64), (54, 56), (56, 2)] {
            b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        }
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&0x10000u64.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        for (i, flags) in [5u32, 6].iter().enumerate() {
            let p = 64 + i * 56;
            b[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
            b[p + 4..p + 8].copy_from_slice(&flags.to_le_bytes());
            for (o, v) in [
                (8, (i * 4096) as u64),
                (16, 0x10000 + (i * 4096) as u64),
                (32, 4096),
                (40, 4096),
                (48, 4096),
            ] {
                b[p + o..p + o + 8].copy_from_slice(&v.to_le_bytes());
            }
        }
        b
    }
    #[test]
    fn accepts_static_rx_rw() {
        assert_eq!(validate(&elf()).unwrap().count, 2);
    }
    #[test]
    fn in_place_plan_reuses_storage_and_revalidates_every_input() {
        let good = elf();
        let mut plan = LoadPlan::EMPTY;
        validate_into(&good, &mut plan).unwrap();
        assert_eq!(plan, validate(&good).unwrap());
        assert_eq!(
            validate_into(&good[..63], &mut plan),
            Err(Error::NotExecutable)
        );
        assert_eq!(plan.count, 0);
        validate_into(&good, &mut plan).unwrap();
        assert_eq!(plan.count, 2);
    }
    #[test]
    fn rejects_overlapping_rounded_segments() {
        let mut b = elf();
        b[136..144].copy_from_slice(&0x10000u64.to_le_bytes());
        assert_eq!(validate(&b), Err(Error::NotExecutable));
    }
    #[test]
    fn rejects_privilege_and_arithmetic_tricks() {
        let original = elf();
        for (o, value) in [(68, 7u32), (48, 4), (120, 3)] {
            let mut b = original;
            b[o..o + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(validate(&b), Err(Error::NotExecutable));
        }
        let mut b = original;
        b[72..80].copy_from_slice(&(u64::MAX - 4095).to_le_bytes());
        assert_eq!(validate(&b), Err(Error::NotExecutable));
        let mut b = original;
        b[24..32].copy_from_slice(&0x11000u64.to_le_bytes());
        assert_eq!(validate(&b), Err(Error::NotExecutable));
        assert_eq!(validate(&original[..63]), Err(Error::NotExecutable));
    }
}
