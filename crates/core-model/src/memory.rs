//! Checked ranges and exact anonymous allocation records. The caller owns all
//! page tables and physical frames and must reserve them before `commit`.
use kernel_abi::{ANON_END, ANON_START, Error, PAGE_SIZE, USER_END, USER_START};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    Read,
    Write,
}

/// Validate every page before a consuming operation. Zero length deliberately
/// ignores the pointer; the descriptor owner must still validate access rights.
pub fn validate_range(
    mut address: u64,
    length: u64,
    access: Access,
    mut page_allows: impl FnMut(u64, Access) -> bool,
) -> Result<(), Error> {
    if length == 0 {
        return Ok(());
    }
    let end = address.checked_add(length).ok_or(Error::Fault)?;
    if address < USER_START || end > USER_END {
        return Err(Error::Fault);
    }
    address &= !(PAGE_SIZE as u64 - 1);
    while address < end {
        if !page_allows(address, access) {
            return Err(Error::Fault);
        }
        address += PAGE_SIZE as u64;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Extent {
    pub base: u64,
    pub pages: u16,
}

pub struct Extents {
    entries: [Extent; 256],
}
impl Default for Extents {
    fn default() -> Self {
        Self::new()
    }
}
impl Extents {
    pub const fn new() -> Self {
        Self {
            entries: [Extent { base: 0, pages: 0 }; 256],
        }
    }
    /// Reset in place without constructing a 4096-byte aggregate on a kernel stack.
    pub fn clear(&mut self) {
        self.entries.fill(Extent { base: 0, pages: 0 });
    }
    /// Admission is nonmutating, so a failed frame reservation requires no rollback here.
    pub fn candidate(&self, pages: u64) -> Result<Extent, Error> {
        if !(1..=256).contains(&pages) {
            return Err(Error::Invalid);
        }
        if self.entries.iter().all(|e| e.pages != 0) {
            return Err(Error::NoMemory);
        }
        let size = pages * PAGE_SIZE as u64;
        let mut base = ANON_START;
        loop {
            if base + size > ANON_END {
                return Err(Error::NoMemory);
            }
            let conflict = self.entries.iter().filter(|e| e.pages != 0).find(|e| {
                base < e.base + u64::from(e.pages) * PAGE_SIZE as u64 && e.base < base + size
            });
            match conflict {
                Some(e) => base = e.base + u64::from(e.pages) * PAGE_SIZE as u64,
                None => {
                    return Ok(Extent {
                        base,
                        pages: pages as u16,
                    });
                }
            }
        }
    }
    /// Rechecks the candidate so stale reservations cannot overlap a later allocation.
    pub fn commit(&mut self, extent: Extent) -> Result<(), Error> {
        if self.candidate(u64::from(extent.pages))? != extent {
            return Err(Error::Invalid);
        }
        *self
            .entries
            .iter_mut()
            .find(|e| e.pages == 0)
            .ok_or(Error::NoMemory)? = extent;
        Ok(())
    }
    pub fn find(&self, base: u64, pages: u64) -> Result<usize, Error> {
        if !(1..=256).contains(&pages) {
            return Err(Error::Invalid);
        }
        self.entries
            .iter()
            .position(|e| e.base == base && u64::from(e.pages) == pages)
            .ok_or(Error::Invalid)
    }
    /// Invoke only after removing mappings, fencing translations, and releasing frames.
    pub fn remove(&mut self, base: u64, pages: u64) -> Result<(), Error> {
        let slot = self.find(base, pages)?;
        self.entries[slot] = Extent::default();
        Ok(())
    }
    pub fn iter(&self) -> impl Iterator<Item = &Extent> {
        self.entries.iter().filter(|e| e.pages != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_last_page_before_effects() {
        let mut seen = 0;
        assert_eq!(
            validate_range(0x10fff, 2, Access::Write, |_, _| {
                seen += 1;
                seen == 1
            }),
            Err(Error::Fault)
        );
        assert_eq!(seen, 2);
        assert_eq!(
            validate_range(u64::MAX, 2, Access::Read, |_, _| true),
            Err(Error::Fault)
        );
        assert_eq!(
            validate_range(u64::MAX, 0, Access::Read, |_, _| panic!()),
            Ok(())
        );
    }
    #[test]
    fn lowest_gap_exact_free_and_rollback() {
        let mut e = Extents::new();
        let first = e.candidate(2).unwrap();
        e.commit(first).unwrap();
        let second = e.candidate(1).unwrap();
        e.commit(second).unwrap();
        assert_eq!(e.remove(first.base + 4096, 1), Err(Error::Invalid));
        assert_eq!(e.remove(first.base, 1), Err(Error::Invalid));
        e.remove(first.base, 2).unwrap();
        assert_eq!(e.candidate(1).unwrap().base, ANON_START);
        assert_eq!(e.candidate(3).unwrap().base, second.base + 4096);
        assert_eq!(e.iter().count(), 1);
    }
}
