#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
//! Fallible first-fit arena. Free nodes live only in unallocated storage.
//! Owned allocations cannot be cloned, and freeing consumes their ownership.
use core::{
    marker::PhantomData,
    mem::{align_of, size_of},
    ptr::NonNull,
};
#[repr(C)]
struct Node {
    size: usize,
    next: Option<NonNull<Node>>,
}
const UNIT: usize = size_of::<Node>();
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Exhausted,
    WrongArena,
}
pub struct Allocation<'a> {
    pointer: NonNull<u8>,
    length: usize,
    base: usize,
    span: usize,
    arena: usize,
    _lifetime: PhantomData<&'a mut [u8]>,
}
impl Allocation<'_> {
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.pointer.as_ptr()
    }
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: this handle exclusively owns a live, zero-initialized allocation.
        unsafe { core::slice::from_raw_parts(self.pointer.as_ptr(), self.length) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: unique handle and mutable borrow prevent aliases or concurrent free.
        unsafe { core::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.length) }
    }
}
pub struct Heap<'a> {
    head: Option<NonNull<Node>>,
    base: usize,
    end: usize,
    free_bytes: usize,
    _lifetime: PhantomData<&'a mut [u8]>,
}
fn align(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
}
impl<'a> Heap<'a> {
    pub fn new(storage: &'a mut [u8]) -> Result<Self, Error> {
        let start = storage.as_mut_ptr() as usize;
        let base = align(start, align_of::<Node>()).ok_or(Error::Invalid)?;
        let end =
            start.checked_add(storage.len()).ok_or(Error::Invalid)? & !(align_of::<Node>() - 1);
        if end < base || end - base < UNIT {
            return Err(Error::Invalid);
        }
        let pointer = NonNull::new(base as *mut Node).ok_or(Error::Invalid)?;
        // SAFETY: aligned node fits in exclusively borrowed storage; no allocation exists yet.
        unsafe {
            pointer.as_ptr().write(Node {
                size: end - base,
                next: None,
            });
        }
        Ok(Self {
            head: Some(pointer),
            base,
            end,
            free_bytes: end - base,
            _lifetime: PhantomData,
        })
    }
    pub fn free_bytes(&self) -> usize {
        self.free_bytes
    }
    pub fn allocate(&mut self, length: usize, alignment: usize) -> Result<Allocation<'a>, Error> {
        if !alignment.is_power_of_two() {
            return Err(Error::Invalid);
        }
        let alignment = alignment.max(align_of::<Node>());
        let requested = length.max(1);
        let mut previous: Option<NonNull<Node>> = None;
        let mut current = self.head;
        while let Some(node) = current {
            let base = node.as_ptr() as usize;
            // SAFETY: list nodes are aligned, ordered, unallocated and inside this arena.
            let (size, next) = unsafe { (node.as_ref().size, node.as_ref().next) };
            let data = align(base, alignment).ok_or(Error::Exhausted)?;
            let end = align(
                data.checked_add(requested).ok_or(Error::Exhausted)?,
                align_of::<Node>(),
            )
            .ok_or(Error::Exhausted)?;
            let span = end.checked_sub(base).ok_or(Error::Exhausted)?.max(UNIT);
            if span <= size {
                let span = if size - span < UNIT { size } else { span };
                let tail = base + span;
                let replacement = if tail < base + size {
                    let new = NonNull::new(tail as *mut Node).ok_or(Error::Invalid)?;
                    unsafe {
                        new.as_ptr().write(Node {
                            size: size - span,
                            next,
                        });
                    }
                    Some(new)
                } else {
                    next
                };
                if let Some(mut prev) = previous {
                    unsafe {
                        prev.as_mut().next = replacement;
                    }
                } else {
                    self.head = replacement;
                }
                self.free_bytes -= span;
                let pointer = NonNull::new(data as *mut u8).ok_or(Error::Invalid)?;
                // Clear before exposing the allocation, including stale free-list bytes.
                unsafe {
                    core::ptr::write_bytes(pointer.as_ptr(), 0, length);
                }
                return Ok(Allocation {
                    pointer,
                    length,
                    base,
                    span,
                    arena: self.base,
                    _lifetime: PhantomData,
                });
            }
            previous = current;
            current = next;
        }
        Err(Error::Exhausted)
    }
    pub fn release(&mut self, allocation: Allocation<'a>) -> Result<(), Error> {
        if allocation.arena != self.base
            || allocation.base < self.base
            || allocation.base + allocation.span > self.end
        {
            return Err(Error::WrongArena);
        }
        let base = allocation.base;
        let span = allocation.span;
        let mut previous: Option<NonNull<Node>> = None;
        let mut next = self.head;
        while let Some(node) = next {
            if node.as_ptr() as usize >= base {
                break;
            }
            previous = next;
            next = unsafe { node.as_ref().next };
        }
        // Non-clonable handles make duplicate/overlapping release unreachable in safe Rust.
        let mut node = NonNull::new(base as *mut Node).ok_or(Error::Invalid)?;
        unsafe {
            node.as_ptr().write(Node { size: span, next });
        }
        if let Some(mut prev) = previous {
            unsafe {
                prev.as_mut().next = Some(node);
            }
        } else {
            self.head = Some(node);
        }
        if let Some(after) = next
            && base + span == after.as_ptr() as usize
        {
            unsafe {
                node.as_mut().size += after.as_ref().size;
                node.as_mut().next = after.as_ref().next;
            }
        }
        if let Some(mut before) = previous
            && unsafe { before.as_ptr() as usize + before.as_ref().size } == base
        {
            unsafe {
                before.as_mut().size += node.as_ref().size;
                before.as_mut().next = node.as_ref().next;
            }
        }
        self.free_bytes += span;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[repr(align(4096))]
    struct Arena([u8; 16384]);
    #[test]
    fn first_fit_alignment_zeroing_and_adjacent_coalescing() {
        let mut bytes = Arena([0xa5; 16384]);
        let mut heap = Heap::new(&mut bytes.0).unwrap();
        let baseline = heap.free_bytes();
        let mut a = heap.allocate(100, 64).unwrap();
        let first = a.as_mut_ptr() as usize;
        let mut b = heap.allocate(1000, 4096).unwrap();
        assert_eq!(b.as_mut_ptr() as usize % 4096, 0);
        assert!(a.as_slice().iter().all(|x| *x == 0));
        a.as_mut_slice().fill(0x77);
        heap.release(a).unwrap();
        let mut c = heap.allocate(100, 64).unwrap();
        assert_eq!(c.as_mut_ptr() as usize, first);
        assert!(c.as_slice().iter().all(|x| *x == 0));
        heap.release(b).unwrap();
        heap.release(c).unwrap();
        assert_eq!(heap.free_bytes(), baseline);
        assert!(heap.allocate(baseline, 8).is_ok());
    }
    #[test]
    fn failed_admission_keeps_free_list_unchanged() {
        let mut bytes = Arena([0; 16384]);
        let mut heap = Heap::new(&mut bytes.0).unwrap();
        let n = heap.free_bytes();
        assert!(matches!(heap.allocate(1, 3), Err(Error::Invalid)));
        assert!(matches!(
            heap.allocate(usize::MAX, 8),
            Err(Error::Exhausted)
        ));
        assert_eq!(heap.free_bytes(), n);
        let a = heap.allocate(n, 8).unwrap();
        assert!(matches!(heap.allocate(1, 8), Err(Error::Exhausted)));
        heap.release(a).unwrap();
        assert_eq!(heap.free_bytes(), n);
    }
    #[test]
    fn different_arena_never_accepts_another_ownership_token() {
        let mut a = Arena([0; 16384]);
        let mut b = Arena([0; 16384]);
        let mut one = Heap::new(&mut a.0).unwrap();
        let mut two = Heap::new(&mut b.0).unwrap();
        let n = two.free_bytes();
        assert_eq!(
            two.release(one.allocate(128, 16).unwrap()),
            Err(Error::WrongArena)
        );
        assert_eq!(two.free_bytes(), n);
    }
    #[test]
    fn tiny_fragmented_releases_preserve_neighbors_and_coalesce_both_sides() {
        #[repr(align(16))]
        struct Small([u8; 64]);
        let mut bytes = Small([0xa5; 64]);
        let mut heap = Heap::new(&mut bytes.0).unwrap();
        let mut a = heap.allocate(1, 1).unwrap();
        let mut b = heap.allocate(2, 2).unwrap();
        let mut c = heap.allocate(3, 1).unwrap();
        let mut d = heap.allocate(4, 4).unwrap();
        a.as_mut_slice().fill(1);
        b.as_mut_slice().fill(2);
        c.as_mut_slice().fill(3);
        d.as_mut_slice().fill(4);
        assert_eq!(heap.free_bytes(), 0);
        heap.release(b).unwrap();
        heap.release(d).unwrap();
        assert_eq!(a.as_slice(), &[1]);
        assert_eq!(c.as_slice(), &[3; 3]);
        heap.release(c).unwrap();
        heap.release(a).unwrap();
        assert_eq!(heap.free_bytes(), 64);
        let whole = heap.allocate(64, 16).unwrap();
        assert!(whole.as_slice().iter().all(|byte| *byte == 0));
        heap.release(whole).unwrap();
        let empty = heap.allocate(0, 1).unwrap();
        assert!(empty.as_slice().is_empty());
        heap.release(empty).unwrap();
        assert_eq!(heap.free_bytes(), 64);
    }
}
