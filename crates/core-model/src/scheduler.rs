//! Single-owner queue and checked guest-time arithmetic. Callers disable local
//! interrupts while atomically changing their process state and these queues.
use kernel_abi::Error;

#[derive(Clone)]
pub struct Queue<const N: usize> {
    values: [u64; N],
    head: usize,
    len: usize,
}
impl<const N: usize> Default for Queue<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> Queue<N> {
    pub const fn new() -> Self {
        Self {
            values: [0; N],
            head: 0,
            len: 0,
        }
    }
    pub fn clear(&mut self) {
        self.values.fill(0);
        self.head = 0;
        self.len = 0;
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn contains(&self, pid: u64) -> bool {
        (0..self.len).any(|i| self.values[(self.head + i) % N] == pid)
    }
    pub fn push(&mut self, pid: u64) -> Result<(), Error> {
        if pid == 0 || self.contains(pid) {
            return Err(Error::Invalid);
        }
        if self.len == N {
            return Err(Error::Again);
        }
        self.values[(self.head + self.len) % N] = pid;
        self.len += 1;
        Ok(())
    }
    pub fn front(&self) -> Option<u64> {
        if self.len == 0 {
            None
        } else {
            Some(self.values[self.head])
        }
    }
    pub fn pop(&mut self) -> Option<u64> {
        let pid = self.front()?;
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(pid)
    }
    pub fn remove(&mut self, pid: u64) -> bool {
        let Some(i) = (0..self.len).find(|i| self.values[(self.head + i) % N] == pid) else {
            return false;
        };
        for j in i..self.len - 1 {
            self.values[(self.head + j) % N] = self.values[(self.head + j + 1) % N];
        }
        self.len -= 1;
        true
    }
}

pub fn deadline(now: u64, milliseconds: u64, frequency: u64) -> Result<u64, Error> {
    if milliseconds > 60_000 || frequency == 0 {
        return Err(Error::Invalid);
    }
    let ticks = (u128::from(milliseconds) * u128::from(frequency)).div_ceil(1000);
    let ticks = u64::try_from(ticks).map_err(|_| Error::Invalid)?;
    now.checked_add(ticks).ok_or(Error::Invalid)
}
pub fn nanoseconds(ticks: u64, frequency: u64) -> Result<i64, Error> {
    if frequency == 0 {
        return Err(Error::Invalid);
    }
    Ok(((u128::from(ticks) * 1_000_000_000 / u128::from(frequency)).min(i64::MAX as u128)) as i64)
}

/// A nonblocking syscall must use `expired`, never `dispatch`, on return.
#[derive(Debug, Clone, Copy)]
pub struct Quantum {
    pub ends: u64,
}
impl Quantum {
    pub fn dispatch(now: u64, frequency: u64) -> Result<Self, Error> {
        Ok(Self {
            ends: deadline(now, 5, frequency)?,
        })
    }
    pub fn expired(self, now: u64) -> bool {
        now >= self.ends
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fifo_round_robin_never_bypasses_peers() {
        let mut q = Queue::<64>::new();
        for pid in 1..=8 {
            q.push(pid).unwrap();
        }
        for i in 0..800 {
            let p = q.pop().unwrap();
            assert_eq!(p, i % 8 + 1);
            q.push(p).unwrap();
        }
        assert_eq!(q.push(1), Err(Error::Invalid));
        assert!(q.remove(4));
        assert!(!q.remove(4));
        for p in [1, 2, 3, 5, 6, 7, 8] {
            assert_eq!(q.pop(), Some(p));
        }
    }
    #[test]
    fn positive_sleep_never_rounds_down_and_quantum_is_absolute() {
        assert_eq!(deadline(10, 1, 1), Ok(11));
        assert_eq!(deadline(u64::MAX, 1, 1), Err(Error::Invalid));
        let q = Quantum::dispatch(10, 1000).unwrap();
        assert!(!q.expired(14));
        assert!(q.expired(15));
        assert_eq!(nanoseconds(u64::MAX, 1), Ok(i64::MAX));
    }
}
