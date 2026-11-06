#![no_std]
#![forbid(unsafe_code)]

//! The version-one wire ABI. All encoders initialize padding, and all decoders
//! use byte operations rather than alignment-dependent casts.

pub const VERSION: u32 = 1;
pub const PAGE_SIZE: usize = 4096;
pub const MAX_IO: usize = 4096;
pub const MAX_FDS: usize = 32;
pub const MAX_PROCESSES: usize = 64;
pub const MAX_FILES: usize = 256;
pub const MAX_ARGS: usize = 16;
pub const MAX_ARG_BYTES: usize = 1024;
pub const MAX_EXEC_BYTES: usize = 2 * 1024 * 1024;
pub const USER_START: u64 = 0x0001_0000;
pub const EXEC_END: u64 = 0x1000_0000;
pub const ANON_START: u64 = 0x1000_0000;
pub const ANON_END: u64 = 0x1800_0000;
pub const USER_END: u64 = 0x4000_0000;
pub const STACK_SIZE: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(i64)]
pub enum Error {
    Permission = 1,
    NotFound = 2,
    Io = 5,
    TooBig = 7,
    NotExecutable = 8,
    BadDescriptor = 9,
    NoChild = 10,
    Again = 11,
    NoMemory = 12,
    Fault = 14,
    Busy = 16,
    Exists = 17,
    Invalid = 22,
    FileTableFull = 23,
    DescriptorTableFull = 24,
    FileTooBig = 27,
    NoSpace = 28,
    IllegalSeek = 29,
    ReadOnly = 30,
    BrokenPipe = 32,
    NameTooLong = 36,
    NotImplemented = 38,
    BufferTooSmall = 105,
}

impl Error {
    pub const fn return_value(self) -> i64 {
        -(self as i64)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u64)]
pub enum Syscall {
    AbiInfo = 0,
    Exit = 1,
    GetPid = 2,
    Yield = 3,
    Sleep = 4,
    Clock = 5,
    PageAlloc = 6,
    PageFree = 7,
    Spawn = 8,
    Wait = 9,
    Open = 10,
    Close = 11,
    Read = 12,
    Write = 13,
    Seek = 14,
    Fsync = 15,
    Stat = 16,
    List = 17,
    Unlink = 18,
    Rename = 19,
    Pipe = 20,
    Dup = 21,
    ProcessList = 22,
    Shutdown = 23,
}

impl Syscall {
    pub fn decode(number: u64) -> Result<Self, Error> {
        const CALLS: [Syscall; 24] = [
            Syscall::AbiInfo,
            Syscall::Exit,
            Syscall::GetPid,
            Syscall::Yield,
            Syscall::Sleep,
            Syscall::Clock,
            Syscall::PageAlloc,
            Syscall::PageFree,
            Syscall::Spawn,
            Syscall::Wait,
            Syscall::Open,
            Syscall::Close,
            Syscall::Read,
            Syscall::Write,
            Syscall::Seek,
            Syscall::Fsync,
            Syscall::Stat,
            Syscall::List,
            Syscall::Unlink,
            Syscall::Rename,
            Syscall::Pipe,
            Syscall::Dup,
            Syscall::ProcessList,
            Syscall::Shutdown,
        ];
        CALLS
            .get(usize::try_from(number).map_err(|_| Error::NotImplemented)?)
            .copied()
            .ok_or(Error::NotImplemented)
    }

    pub const fn argument_count(self) -> usize {
        match self {
            Self::GetPid | Self::Yield | Self::Clock | Self::Shutdown => 0,
            Self::AbiInfo
            | Self::Exit
            | Self::Sleep
            | Self::PageAlloc
            | Self::Close
            | Self::Fsync
            | Self::Pipe
            | Self::Dup => 1,
            Self::PageFree | Self::Seek | Self::List | Self::Unlink | Self::ProcessList => 2,
            Self::Wait | Self::Open | Self::Read | Self::Write | Self::Stat => 3,
            Self::Rename => 4,
            Self::Spawn => 5,
        }
    }

    /// Stage-one validation only. Handles and pointers are validated by their owners.
    pub fn validate_scalars(self, a: &[u64; 6]) -> Result<(), Error> {
        if a[self.argument_count()..].iter().any(|x| *x != 0) {
            return Err(Error::Invalid);
        }
        match self {
            Self::Sleep if a[0] > 60_000 => Err(Error::Invalid),
            Self::PageAlloc if !(1..=256).contains(&a[0]) => Err(Error::Invalid),
            Self::PageFree if !(1..=256).contains(&a[1]) => Err(Error::Invalid),
            Self::Spawn if a[3] > 16 => Err(Error::TooBig),
            Self::Wait if a[2] > 1 || a[0] > i64::MAX as u64 => Err(Error::Invalid),
            Self::Open => OpenFlags::new(a[2]).map(|_| ()),
            Self::List if a[1] > MAX_FILES as u64 => Err(Error::Invalid),
            Self::ProcessList if a[1] > MAX_PROCESSES as u64 => Err(Error::Invalid),
            // Read/write length is checked after descriptor validation, per 2B.
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct OpenFlags(u16);
impl OpenFlags {
    pub const CREATE: u64 = 0x100;
    pub const EXCLUSIVE: u64 = 0x200;
    pub const TRUNCATE: u64 = 0x400;
    pub fn new(value: u64) -> Result<Self, Error> {
        if value & !0x703 != 0
            || value & 3 == 0
            || (value & Self::EXCLUSIVE != 0 && value & Self::CREATE == 0)
            || (value & Self::TRUNCATE != 0 && value & 2 == 0)
        {
            return Err(Error::Invalid);
        }
        Ok(Self(value as u16))
    }
    pub const fn bits(self) -> u16 {
        self.0
    }
    pub const fn readable(self) -> bool {
        self.0 & 1 != 0
    }
    pub const fn writable(self) -> bool {
        self.0 & 2 != 0
    }
    pub const fn create(self) -> bool {
        self.0 & 0x100 != 0
    }
    pub const fn exclusive(self) -> bool {
        self.0 & 0x200 != 0
    }
    pub const fn truncate(self) -> bool {
        self.0 & 0x400 != 0
    }
}

/// Return the canonical name without its leading slash.
pub fn path_name(path: &[u8]) -> Result<&[u8], Error> {
    if path.len() > 48 {
        return Err(Error::NameTooLong);
    }
    if path.len() < 2 || path[0] != b'/' {
        return Err(Error::Invalid);
    }
    let name = &path[1..];
    if name == b"."
        || name == b".."
        || !name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-' | b'.'))
    {
        return Err(Error::Invalid);
    }
    Ok(name)
}

pub fn validate_arguments(args: &[&[u8]]) -> Result<usize, Error> {
    if args.len() > MAX_ARGS {
        return Err(Error::TooBig);
    }
    let mut total = 0;
    for arg in args {
        if arg.len() > 255 {
            return Err(Error::TooBig);
        }
        if arg.contains(&0) {
            return Err(Error::Invalid);
        }
        total += arg.len() + 1;
        if total > MAX_ARG_BYTES {
            return Err(Error::TooBig);
        }
    }
    Ok(total)
}

fn put32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get64(input: &[u8], offset: usize) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&input[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

pub fn abi_info() -> [u8; 32] {
    let mut out = [0; 32];
    for (i, value) in [0x3149_4241, 1, 4096, 4096, 32, 64].iter().enumerate() {
        put32(&mut out, 4 * i, *value);
    }
    put64(&mut out, 24, 0x0f);
    out
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ArgSlice {
    pub pointer: u64,
    pub length: u64,
}
impl ArgSlice {
    pub fn decode(bytes: &[u8; 16]) -> Self {
        Self {
            pointer: get64(bytes, 0),
            length: get64(bytes, 8),
        }
    }
    pub fn encode(self) -> [u8; 16] {
        let mut out = [0; 16];
        put64(&mut out, 0, self.pointer);
        put64(&mut out, 8, self.length);
        out
    }
}

pub fn decode_stdio(bytes: &[u8; 12]) -> Result<[Option<usize>; 3], Error> {
    let mut out = [None; 3];
    for (i, entry) in out.iter_mut().enumerate() {
        let mut word = [0; 4];
        word.copy_from_slice(&bytes[i * 4..i * 4 + 4]);
        match i32::from_le_bytes(word) {
            -1 => {}
            0..=31 => *entry = Some(i32::from_le_bytes(word) as usize),
            _ => return Err(Error::BadDescriptor),
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ExitRecord {
    pub pid: u64,
    pub kind: u32,
    pub code: u32,
    pub cause: u64,
    pub fault_address: u64,
}
impl ExitRecord {
    pub const fn normal(pid: u64, code: u64) -> Self {
        Self {
            pid,
            kind: 0,
            code: code as u32,
            cause: 0,
            fault_address: 0,
        }
    }
    pub fn fault(pid: u64, cause: u64, address: u64) -> Self {
        let relevant = matches!(cause, 1 | 5 | 7 | 12 | 13 | 15);
        Self {
            pid,
            kind: 1,
            code: 0,
            cause,
            fault_address: if relevant && (USER_START..USER_END).contains(&address) {
                address
            } else {
                0
            },
        }
    }
    pub fn encode(self) -> [u8; 32] {
        let mut out = [0; 32];
        put64(&mut out, 0, self.pid);
        put32(&mut out, 8, self.kind);
        put32(&mut out, 12, self.code);
        put64(&mut out, 16, self.cause);
        put64(&mut out, 24, self.fault_address);
        out
    }
}

pub fn file_stat(inode: u32, generation: u64, size: u64) -> [u8; 32] {
    let mut out = [0; 32];
    put32(&mut out, 0, inode);
    put32(&mut out, 4, 1);
    put64(&mut out, 8, generation);
    put64(&mut out, 16, size);
    put32(&mut out, 24, 1);
    out
}

pub fn directory_record(inode: u32, size: u64, name: &[u8]) -> Result<[u8; 64], Error> {
    if name.is_empty()
        || name.len() > 47
        || name == b"."
        || name == b".."
        || !name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-' | b'.'))
    {
        return Err(Error::Invalid);
    }
    let mut out = [0; 64];
    put32(&mut out, 0, inode);
    put32(&mut out, 4, name.len() as u32);
    put64(&mut out, 8, size);
    out[16..16 + name.len()].copy_from_slice(name);
    Ok(out)
}

pub fn process_record(pid: u64, parent: u64, state: u32, pages: u32) -> Result<[u8; 32], Error> {
    if !(1..=4).contains(&state) || (state == 4 && pages != 0) {
        return Err(Error::Invalid);
    }
    let mut out = [0; 32];
    put64(&mut out, 0, pid);
    put64(&mut out, 8, parent);
    put32(&mut out, 16, state);
    put32(&mut out, 20, pages);
    Ok(out)
}

pub fn pipe_result(read: u32, write: u32) -> [u8; 8] {
    let mut out = [0; 8];
    put32(&mut out, 0, read);
    put32(&mut out, 4, write);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn syscall_number_precedes_scalar_validation() {
        assert_eq!(Syscall::decode(24), Err(Error::NotImplemented));
        assert_eq!(Syscall::decode(u64::MAX), Err(Error::NotImplemented));
        assert_eq!(
            Syscall::GetPid.validate_scalars(&[1, 0, 0, 0, 0, 0]),
            Err(Error::Invalid)
        );
        assert_eq!(
            Syscall::Read.validate_scalars(&[99, 0, 8192, 0, 0, 0]),
            Ok(())
        );
    }
    #[test]
    fn flags_do_not_widen_rights() {
        assert!(OpenFlags::new(0x701).is_err());
        assert!(OpenFlags::new(0x202).is_err());
        assert!(OpenFlags::new(0x8003).is_err());
        let f = OpenFlags::new(0x703).unwrap();
        assert!(f.readable() && f.writable() && f.create() && f.exclusive() && f.truncate());
    }
    #[test]
    fn path_and_argument_partitions() {
        for path in [b"/".as_slice(), b"/.", b"/..", b"/a/b", b"/a\0", b"abc"] {
            assert_eq!(path_name(path), Err(Error::Invalid));
        }
        assert_eq!(path_name(b"/..."), Ok(b"...".as_slice()));
        assert_eq!(path_name(&[b'a'; 49]), Err(Error::NameTooLong));
        assert_eq!(validate_arguments(&[b"", b"x"]), Ok(3));
        assert_eq!(validate_arguments(&[b"\0"]), Err(Error::Invalid));
        assert_eq!(validate_arguments(&[&[1; 256]]), Err(Error::TooBig));
    }
    #[test]
    fn output_padding_and_fault_redaction() {
        assert_eq!(&abi_info()[..8], &[0x41, 0x42, 0x49, 0x31, 1, 0, 0, 0]);
        assert_eq!(&file_stat(1, 2, 3)[28..], &[0; 4]);
        assert_eq!(&directory_record(1, 2, b"a").unwrap()[17..], &[0; 47]);
        assert_eq!(ExitRecord::fault(257, 13, 0x80200000).fault_address, 0);
        assert_eq!(ExitRecord::fault(257, 2, 0x10000).fault_address, 0);
        assert_eq!(ExitRecord::fault(257, 13, 0x10000).fault_address, 0x10000);
    }
    #[test]
    fn unaligned_wire_inputs_are_copied() {
        let wire = ArgSlice {
            pointer: 0x12345678,
            length: 99,
        }
        .encode();
        assert_eq!(ArgSlice::decode(&wire).length, 99);
        assert_eq!(decode_stdio(&[255; 12]), Ok([None; 3]));
        assert_eq!(decode_stdio(&[254; 12]), Err(Error::BadDescriptor));
    }
}
