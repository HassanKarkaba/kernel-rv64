//! Generation-safe identity, process publication and descriptor admission.
//! Resource owners close descriptors and reclaim memory before publishing exit.
use kernel_abi::{Error, ExitRecord, MAX_FDS, MAX_PROCESSES};

pub const MAX_GENERATION: u64 = (1 << 55) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Pid(u64);
impl Pid {
    pub fn new(slot: usize, generation: u64) -> Result<Self, Error> {
        if !(1..=64).contains(&slot) || !(1..=MAX_GENERATION).contains(&generation) {
            return Err(Error::Invalid);
        }
        Ok(Self(generation << 8 | slot as u64))
    }
    pub fn decode(raw: u64) -> Result<Self, Error> {
        Self::new((raw & 255) as usize, raw >> 8)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
    pub const fn slot(self) -> usize {
        (self.0 & 255) as usize
    }
    pub const fn generation(self) -> u64 {
        self.0 >> 8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Free,
    Constructing,
    Ready,
    Running,
    Blocked,
    Zombie,
}
#[derive(Clone, Copy, Debug)]
pub struct Process {
    pub pid: Option<Pid>,
    pub parent: Option<Pid>,
    pub state: State,
    pub auto_reap: bool,
    pub shutdown: bool,
    pub status: Option<ExitRecord>,
}
impl Process {
    const EMPTY: Self = Self {
        pid: None,
        parent: None,
        state: State::Free,
        auto_reap: false,
        shutdown: false,
        status: None,
    };
}
pub struct Table {
    slots: [Process; 64],
    generations: [u64; 64],
    init: Pid,
}
impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}
impl Table {
    pub fn new() -> Self {
        let init = Pid(257);
        let mut table = Self {
            slots: [Process::EMPTY; 64],
            generations: [0; 64],
            init,
        };
        table.generations[0] = 1;
        table.slots[0] = Process {
            pid: Some(init),
            state: State::Ready,
            shutdown: true,
            ..Process::EMPTY
        };
        table
    }
    pub fn init(&self) -> Pid {
        self.init
    }
    pub fn get(&self, pid: Pid) -> Result<&Process, Error> {
        let process = &self.slots[pid.slot() - 1];
        if process.pid != Some(pid) {
            return Err(Error::NoChild);
        }
        Ok(process)
    }
    fn get_mut(&mut self, pid: Pid) -> Result<&mut Process, Error> {
        let process = &mut self.slots[pid.slot() - 1];
        if process.pid != Some(pid) {
            return Err(Error::NoChild);
        }
        Ok(process)
    }
    pub fn reserve(&mut self, parent: Pid) -> Result<Pid, Error> {
        let parent_state = self.get(parent)?.state;
        if matches!(
            parent_state,
            State::Free | State::Constructing | State::Zombie
        ) {
            return Err(Error::NoChild);
        }
        let i = (0..MAX_PROCESSES)
            .find(|i| self.slots[*i].state == State::Free && self.generations[*i] < MAX_GENERATION)
            .ok_or(Error::Again)?;
        self.generations[i] += 1;
        let pid = Pid::new(i + 1, self.generations[i])?;
        self.slots[i] = Process {
            pid: Some(pid),
            parent: Some(parent),
            state: State::Constructing,
            ..Process::EMPTY
        };
        Ok(pid)
    }
    pub fn publish(&mut self, pid: Pid) -> Result<(), Error> {
        self.transition(pid, State::Constructing, State::Ready)
    }
    pub fn abort(&mut self, pid: Pid) -> Result<(), Error> {
        if self.get(pid)?.state != State::Constructing {
            return Err(Error::Invalid);
        }
        self.slots[pid.slot() - 1] = Process::EMPTY;
        Ok(())
    }
    /// This checked transition does not touch the ready queue. Both owners must
    /// be changed in one local-interrupt critical section by the scheduler.
    pub fn transition(&mut self, pid: Pid, from: State, to: State) -> Result<(), Error> {
        let valid = matches!(
            (from, to),
            (State::Constructing, State::Ready)
                | (State::Ready, State::Running)
                | (State::Running, State::Ready)
                | (State::Running, State::Blocked)
                | (State::Blocked, State::Ready)
        );
        let process = self.get_mut(pid)?;
        if !valid || process.state != from {
            return Err(Error::Invalid);
        }
        process.state = to;
        Ok(())
    }
    /// Memory/descriptors must already be released. Current kernel stack reclamation
    /// is deferred to the scheduler, outside this metadata table.
    pub fn finish_exit(&mut self, pid: Pid, status: ExitRecord) -> Result<(), Error> {
        if pid == self.init {
            return Err(Error::Permission);
        }
        if status.pid != pid.raw()
            || matches!(
                self.get(pid)?.state,
                State::Free | State::Constructing | State::Zombie
            )
        {
            return Err(Error::Invalid);
        }
        for child in &mut self.slots {
            if child.parent == Some(pid) {
                child.parent = Some(self.init);
                child.auto_reap = true;
            }
        }
        let process = self.get_mut(pid)?;
        process.state = State::Zombie;
        process.status = Some(status);
        Ok(())
    }
    /// Select without consuming. Validate and perform the complete copyout
    /// before calling `reap`, under the caller's process ownership discipline.
    pub fn wait_candidate(&self, parent: Pid, raw: u64) -> Result<Option<Pid>, Error> {
        self.get(parent)?;
        let requested = if raw == 0 {
            None
        } else {
            Some(Pid::decode(raw).map_err(|_| Error::NoChild)?)
        };
        let mut found = false;
        let mut zombie = None;
        for p in &self.slots {
            if p.parent != Some(parent)
                || p.auto_reap
                || matches!(p.state, State::Free | State::Constructing)
                || requested.is_some_and(|id| p.pid != Some(id))
            {
                continue;
            }
            found = true;
            if p.state == State::Zombie && (zombie.is_none() || p.pid < zombie) {
                zombie = p.pid;
            }
        }
        if found {
            Ok(zombie)
        } else {
            Err(Error::NoChild)
        }
    }
    pub fn reap(&mut self, parent: Pid, pid: Pid) -> Result<ExitRecord, Error> {
        let process = self.get(pid)?;
        if process.parent != Some(parent) || process.auto_reap || process.state != State::Zombie {
            return Err(Error::NoChild);
        }
        let status = process.status.ok_or(Error::Invalid)?;
        self.slots[pid.slot() - 1] = Process::EMPTY;
        Ok(status)
    }
    pub fn auto_reap(&mut self, pid: Pid) -> Result<(), Error> {
        let p = self.get(pid)?;
        if !p.auto_reap || p.state != State::Zombie {
            return Err(Error::Invalid);
        }
        self.slots[pid.slot() - 1] = Process::EMPTY;
        Ok(())
    }
    pub fn published(&self) -> impl Iterator<Item = &Process> {
        self.slots
            .iter()
            .filter(|p| !matches!(p.state, State::Free | State::Constructing))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor {
    pub object: u32,
    pub readable: bool,
    pub writable: bool,
}
pub struct Descriptors {
    entries: [Option<Descriptor>; MAX_FDS],
}
impl Default for Descriptors {
    fn default() -> Self {
        Self::new()
    }
}
impl Descriptors {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_FDS],
        }
    }
    pub fn get(&self, fd: u64) -> Result<Descriptor, Error> {
        self.entries
            .get(usize::try_from(fd).map_err(|_| Error::BadDescriptor)?)
            .copied()
            .flatten()
            .ok_or(Error::BadDescriptor)
    }
    pub fn free_slot(&self) -> Result<usize, Error> {
        self.entries
            .iter()
            .position(Option::is_none)
            .ok_or(Error::DescriptorTableFull)
    }
    pub fn two_free_slots(&self) -> Result<[usize; 2], Error> {
        let mut free = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, x)| x.is_none())
            .map(|(i, _)| i);
        Ok([
            free.next().ok_or(Error::DescriptorTableFull)?,
            free.next().ok_or(Error::DescriptorTableFull)?,
        ])
    }
    pub fn install(&mut self, slot: usize, descriptor: Descriptor) -> Result<(), Error> {
        let entry = self.entries.get_mut(slot).ok_or(Error::BadDescriptor)?;
        if entry.is_some() {
            return Err(Error::Busy);
        }
        *entry = Some(descriptor);
        Ok(())
    }
    /// The owner decrements the removed object's reference count.
    pub fn close(&mut self, fd: u64) -> Result<Descriptor, Error> {
        let descriptor = self.get(fd)?;
        self.entries[fd as usize] = None;
        Ok(descriptor)
    }
    /// Snapshot first; owners increment references atomically before child publication.
    pub fn stdio_snapshot(
        &self,
        map: [Option<usize>; 3],
    ) -> Result<[Option<Descriptor>; 3], Error> {
        let mut result = [None; 3];
        for (i, fd) in map.iter().enumerate() {
            if let Some(fd) = fd {
                let descriptor = self.get(*fd as u64)?;
                if (i == 0 && !descriptor.readable) || (i != 0 && !descriptor.writable) {
                    return Err(Error::BadDescriptor);
                }
                result[i] = Some(descriptor);
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_pid_and_failed_copyout_do_not_reap() {
        let mut t = Table::new();
        let init = t.init();
        let child = t.reserve(init).unwrap();
        t.publish(child).unwrap();
        t.finish_exit(child, ExitRecord::normal(child.raw(), 42))
            .unwrap();
        assert_eq!(t.wait_candidate(init, child.raw()), Ok(Some(child)));
        // A rejected output pointer performs no reap operation.
        assert_eq!(t.wait_candidate(init, 0), Ok(Some(child)));
        assert_eq!(t.reap(init, child).unwrap().code, 42);
        let next = t.reserve(init).unwrap();
        assert_eq!(next.slot(), child.slot());
        assert_ne!(next, child);
        assert_eq!(t.wait_candidate(init, child.raw()), Err(Error::NoChild));
    }
    #[test]
    fn orphan_cleanup_excludes_explicit_wait() {
        let mut t = Table::new();
        let init = t.init();
        let p = t.reserve(init).unwrap();
        t.publish(p).unwrap();
        let c = t.reserve(p).unwrap();
        t.publish(c).unwrap();
        t.finish_exit(p, ExitRecord::normal(p.raw(), 0)).unwrap();
        assert!(t.get(c).unwrap().auto_reap);
        assert!(!t.get(c).unwrap().shutdown);
        assert_eq!(t.wait_candidate(init, c.raw()), Err(Error::NoChild));
        t.finish_exit(c, ExitRecord::normal(c.raw(), 0)).unwrap();
        t.auto_reap(c).unwrap();
        assert_eq!(t.published().count(), 2);
    }
    #[test]
    fn admission_bound_and_retirement() {
        let mut t = Table::new();
        let init = t.init();
        for _ in 1..64 {
            t.reserve(init).unwrap();
        }
        assert_eq!(t.reserve(init), Err(Error::Again));
        let mut t = Table::new();
        t.generations[1] = MAX_GENERATION;
        assert_eq!(t.reserve(init).unwrap().slot(), 3);
        assert!(Pid::decode(1).is_err());
        assert!(Pid::decode(u64::MAX).is_err());
    }
    #[test]
    fn descriptor_snapshot_preserves_rights_and_lowest_slot() {
        let mut d = Descriptors::new();
        let read = Descriptor {
            object: 10,
            readable: true,
            writable: false,
        };
        d.install(0, read).unwrap();
        assert_eq!(
            d.stdio_snapshot([None, Some(0), None]),
            Err(Error::BadDescriptor)
        );
        assert_eq!(
            d.stdio_snapshot([Some(0), None, None]),
            Ok([Some(read), None, None])
        );
        assert_eq!(d.two_free_slots(), Ok([1, 2]));
        d.close(0).unwrap();
        assert_eq!(d.close(0), Err(Error::BadDescriptor));
        assert_eq!(d.free_slot(), Ok(0));
    }
}
