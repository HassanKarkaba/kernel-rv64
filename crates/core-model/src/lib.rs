#![no_std]
#![forbid(unsafe_code)]

//! Bounded, allocation-free kernel algorithms. Hardware mapping, interrupt
//! masking, context switching and DMA are deliberately owned by the kernel.

pub mod elf;
pub mod memory;
pub mod pipe;
pub mod process;
pub mod scheduler;
pub mod shell;
