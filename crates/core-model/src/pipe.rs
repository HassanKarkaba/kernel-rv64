//! FIFO pipe state. A blocked operation retains its validated memory and copied
//! input in its process. The scheduler owns sleeping/waking, under the same
//! interrupt-disabled critical section as these predicate checks.
use crate::scheduler::Queue;
use kernel_abi::{Error, MAX_IO};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Transfer {
    Complete(usize),
    Blocked,
}

pub struct Pipe {
    bytes: [u8; 4096],
    head: usize,
    len: usize,
    readers: u16,
    writers: u16,
    read_waiters: Queue<64>,
    write_waiters: Queue<64>,
}
impl Default for Pipe {
    fn default() -> Self {
        Self::new()
    }
}
impl Pipe {
    pub const fn new() -> Self {
        Self {
            bytes: [0; 4096],
            head: 0,
            len: 0,
            readers: 1,
            writers: 1,
            read_waiters: Queue::new(),
            write_waiters: Queue::new(),
        }
    }
    /// Reinitialize an unowned slot without creating a large stack aggregate.
    pub fn reset(&mut self) {
        self.bytes.fill(0);
        self.head = 0;
        self.len = 0;
        self.readers = 1;
        self.writers = 1;
        self.read_waiters.clear();
        self.write_waiters.clear();
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn readers(&self) -> u16 {
        self.readers
    }
    pub fn writers(&self) -> u16 {
        self.writers
    }
    pub fn first_reader(&self) -> Option<u64> {
        self.read_waiters.front()
    }
    pub fn first_writer(&self) -> Option<u64> {
        self.write_waiters.front()
    }
    pub fn add_reader(&mut self) -> Result<(), Error> {
        self.readers = self.readers.checked_add(1).ok_or(Error::FileTableFull)?;
        Ok(())
    }
    pub fn add_writer(&mut self) -> Result<(), Error> {
        self.writers = self.writers.checked_add(1).ok_or(Error::FileTableFull)?;
        Ok(())
    }
    /// Returns true when writers must be woken to observe EPIPE.
    pub fn close_reader(&mut self) -> Result<bool, Error> {
        self.readers = self.readers.checked_sub(1).ok_or(Error::BadDescriptor)?;
        Ok(self.readers == 0)
    }
    /// Returns true when readers must be woken to observe buffered bytes or EOF.
    pub fn close_writer(&mut self) -> Result<bool, Error> {
        self.writers = self.writers.checked_sub(1).ok_or(Error::BadDescriptor)?;
        Ok(self.writers == 0)
    }
    pub fn releasable(&self) -> bool {
        self.readers == 0
            && self.writers == 0
            && self.read_waiters.is_empty()
            && self.write_waiters.is_empty()
    }
    pub fn cancel_wait(&mut self, pid: u64) {
        self.read_waiters.remove(pid);
        self.write_waiters.remove(pid);
    }
    pub fn try_read(&mut self, pid: u64, output: &mut [u8]) -> Result<Transfer, Error> {
        if output.len() > MAX_IO {
            return Err(Error::Invalid);
        }
        if output.is_empty() {
            return Ok(Transfer::Complete(0));
        }
        if pid == 0 {
            return Err(Error::Invalid);
        }
        let behind = self.read_waiters.front().is_some_and(|first| first != pid);
        if behind || (self.len == 0 && self.writers != 0) {
            if !self.read_waiters.contains(pid) {
                self.read_waiters.push(pid)?;
            }
            return Ok(Transfer::Blocked);
        }
        self.read_waiters.remove(pid);
        let n = output.len().min(self.len);
        for byte in &mut output[..n] {
            *byte = self.bytes[self.head];
            self.head = (self.head + 1) % 4096;
        }
        self.len -= n;
        Ok(Transfer::Complete(n))
    }
    pub fn try_write(&mut self, pid: u64, input: &[u8]) -> Result<Transfer, Error> {
        if input.len() > MAX_IO {
            return Err(Error::Invalid);
        }
        if input.is_empty() {
            return Ok(Transfer::Complete(0));
        }
        if pid == 0 {
            return Err(Error::Invalid);
        }
        if self.readers == 0 {
            self.write_waiters.remove(pid);
            return Err(Error::BrokenPipe);
        }
        let available = 4096 - self.len;
        let behind = self.write_waiters.front().is_some_and(|first| first != pid);
        if behind || available == 0 || (input.len() <= 512 && available < input.len()) {
            if !self.write_waiters.contains(pid) {
                self.write_waiters.push(pid)?;
            }
            return Ok(Transfer::Blocked);
        }
        self.write_waiters.remove(pid);
        let n = available.min(input.len());
        for byte in &input[..n] {
            self.bytes[(self.head + self.len) % 4096] = *byte;
            self.len += 1;
        }
        Ok(Transfer::Complete(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn in_place_reset_discards_old_bytes_owners_and_waiters() {
        let mut p = Pipe::new();
        p.try_write(1, &[9; 4096]).unwrap();
        assert_eq!(p.try_write(2, &[1]), Ok(Transfer::Blocked));
        let mut bytes = [0; 4096];
        p.try_read(3, &mut bytes).unwrap();
        assert_eq!(p.try_read(4, &mut bytes), Ok(Transfer::Blocked));
        p.add_reader().unwrap();
        p.add_writer().unwrap();
        p.reset();
        assert_eq!((p.readers(), p.writers(), p.len()), (1, 1, 0));
        assert_eq!((p.first_reader(), p.first_writer()), (None, None));
        assert_eq!(p.try_write(5, b"new"), Ok(Transfer::Complete(3)));
        assert_eq!(p.try_read(6, &mut bytes), Ok(Transfer::Complete(3)));
        assert_eq!(&bytes[..3], b"new");
    }
    #[test]
    fn atomic_writer_cannot_be_bypassed() {
        let mut p = Pipe::new();
        assert_eq!(p.try_write(1, &[1; 4000]), Ok(Transfer::Complete(4000)));
        assert_eq!(p.try_write(2, &[2; 512]), Ok(Transfer::Blocked));
        assert_eq!(p.try_write(3, &[3; 1]), Ok(Transfer::Blocked));
        let mut read = [0; 511];
        p.try_read(4, &mut read).unwrap();
        assert_eq!(p.try_write(3, &[3; 1]), Ok(Transfer::Blocked));
        assert_eq!(p.try_write(2, &[2; 512]), Ok(Transfer::Complete(512)));
        assert_eq!(p.try_write(3, &[3; 1]), Ok(Transfer::Complete(1)));
    }
    #[test]
    fn short_writes_eof_and_wraparound_preserve_bytes() {
        let mut p = Pipe::new();
        p.try_write(1, &[7; 4000]).unwrap();
        assert_eq!(p.try_write(1, &[8; 600]), Ok(Transfer::Complete(96)));
        p.close_writer().unwrap();
        let mut b = [0; 4096];
        assert_eq!(p.try_read(2, &mut b), Ok(Transfer::Complete(4096)));
        assert!(b[..4000].iter().all(|x| *x == 7));
        assert!(b[4000..].iter().all(|x| *x == 8));
        assert_eq!(p.try_read(2, &mut b), Ok(Transfer::Complete(0)));
        p.add_writer().unwrap();
        p.try_write(1, &[9; 512]).unwrap();
        p.try_read(2, &mut b).unwrap();
        assert_eq!(&b[..512], &[9; 512]);
        p.close_reader().unwrap();
        assert_eq!(p.try_write(1, &[1]), Err(Error::BrokenPipe));
    }
    #[test]
    fn blocked_operation_keeps_pipe_alive_after_close() {
        let mut p = Pipe::new();
        let mut b = [0; 1];
        p.try_read(1, &mut b).unwrap();
        p.close_reader().unwrap();
        p.close_writer().unwrap();
        assert!(!p.releasable());
        p.cancel_wait(1);
        assert!(p.releasable());
    }
}
