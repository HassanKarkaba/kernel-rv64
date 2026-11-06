#![no_std]
#![forbid(unsafe_code)]
//! Serialized, bounded KFS operations. A caller must hold its filesystem mutex
//! across a complete call, including blocked device I/O. Descriptor possession,
//! access rights, offsets, copyout validation, and open-reference counts belong
//! to the process/open-description layer. No operation allocates from a heap.

use disk_format::{
    self as disk, Block, BlockDevice, DirectoryEntry, Inode, ScanScratch, Transaction, Uuid,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    NameTooLong,
    NotFound,
    Exists,
    Busy,
    NoSpace,
    FileTooLarge,
    BufferTooSmall,
    ReadOnly,
    Io,
    Stale,
    Disk(disk::Error),
}
pub type Result<T> = core::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Unmounted,
    Recovering,
    Healthy,
    ReadOnly,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStat {
    pub inode: u16,
    pub generation: u64,
    pub size: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub stat: FileStat,
    pub name: [u8; 47],
    pub name_len: u8,
}
impl Entry {
    pub const EMPTY: Self = Self {
        stat: FileStat {
            inode: 0,
            generation: 0,
            size: 0,
        },
        name: [0; 47],
        name_len: 0,
    };
}

pub struct FileSystem<D: BlockDevice> {
    device: D,
    state: State,
    uuid: Uuid,
    sequence: u64,
    transaction: Transaction,
    entries: [Entry; 256],
    pointers: [u32; 1024],
    bits: [u8; 2048],
    block: Block,
    buffer: Block,
}
impl<D: BlockDevice> FileSystem<D> {
    pub const fn new(device: D) -> Self {
        Self {
            device,
            state: State::Unmounted,
            uuid: [0; 16],
            sequence: 0,
            transaction: Transaction::new([0; 16], 0),
            entries: [Entry::EMPTY; 256],
            pointers: [0; 1024],
            bits: [0; 2048],
            block: [0; 4096],
            buffer: [0; 4096],
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }
    pub fn into_device(self) -> D {
        self.device
    }
    pub fn mount(&mut self, scratch: &mut ScanScratch) -> Result<()> {
        self.state = State::Recovering;
        let result = (|| {
            disk::recover(&mut self.device, &mut self.transaction)?;
            disk::scan(&mut self.device, scratch)
        })();
        match result {
            Ok(info) => {
                self.uuid = info.uuid;
                self.sequence = info.sequence;
                self.state = if info.sequence == u64::MAX {
                    State::ReadOnly
                } else {
                    State::Healthy
                };
                Ok(())
            }
            Err(e) => {
                self.state = State::Failed;
                Err(Error::Disk(e))
            }
        }
    }
    fn readable(&self) -> Result<()> {
        match self.state {
            State::Healthy | State::ReadOnly => Ok(()),
            _ => Err(Error::Io),
        }
    }
    fn mutable(&self) -> Result<()> {
        match self.state {
            State::Healthy => Ok(()),
            State::ReadOnly => Err(Error::ReadOnly),
            _ => Err(Error::Io),
        }
    }
    fn name(name: &[u8]) -> Result<()> {
        if name.len() > 47 {
            return Err(Error::NameTooLong);
        }
        if !disk::valid_name(name) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn read_work(&mut self, target: u32) -> Result<()> {
        self.device
            .read_block(target, &mut self.block)
            .map_err(|e| {
                self.state = State::Failed;
                Error::Disk(e)
            })
    }
    fn corrupt<T>(&mut self, result: disk::Result<T>) -> Result<T> {
        result.map_err(|e| {
            self.state = State::Failed;
            Error::Disk(e)
        })
    }
    fn inode(&mut self, number: u16) -> Result<Inode> {
        if number == 0 || number > 256 {
            return Err(Error::Stale);
        }
        let index = usize::from(number) - 1;
        self.read_work(20 + (index / 32) as u32)?;
        let mut r = [0; 128];
        r.copy_from_slice(&self.block[index % 32 * 128..(index % 32 + 1) * 128]);
        self.corrupt(Inode::decode(&r))
    }
    fn identity(&mut self, number: u16, generation: u64) -> Result<Inode> {
        let inode = self.inode(number)?;
        if !inode.live || inode.generation != generation {
            return Err(Error::Stale);
        }
        Ok(inode)
    }
    fn entry(&mut self, index: usize) -> Result<Option<DirectoryEntry>> {
        self.read_work(28 + (index / 64) as u32)?;
        let mut r = [0; 64];
        r.copy_from_slice(&self.block[index % 64 * 64..(index % 64 + 1) * 64]);
        self.corrupt(DirectoryEntry::decode(&r))
    }
    fn find(&mut self, name: &[u8]) -> Result<(usize, DirectoryEntry)> {
        for i in 0..256 {
            if let Some(entry) = self.entry(i)?
                && &entry.name[..usize::from(entry.name_len)] == name
            {
                return Ok((i, entry));
            }
        }
        Err(Error::NotFound)
    }
    pub fn lookup(&mut self, name: &[u8]) -> Result<FileStat> {
        Self::name(name)?;
        self.readable()?;
        let (_, e) = self.find(name)?;
        self.stat(e.inode, e.generation)
    }
    pub fn stat(&mut self, number: u16, generation: u64) -> Result<FileStat> {
        self.readable()?;
        let i = self.identity(number, generation)?;
        Ok(FileStat {
            inode: number,
            generation,
            size: i.size,
        })
    }
    pub fn list(&mut self, out: &mut [Entry]) -> Result<usize> {
        self.readable()?;
        let mut count = 0usize;
        for i in 0..256 {
            if let Some(e) = self.entry(i)? {
                let inode = self.identity(e.inode, e.generation)?;
                self.entries[count] = Entry {
                    stat: FileStat {
                        inode: e.inode,
                        generation: e.generation,
                        size: inode.size,
                    },
                    name: e.name,
                    name_len: e.name_len,
                };
                count += 1;
            }
        }
        if out.len() < count {
            return Err(Error::BufferTooSmall);
        }
        self.entries[..count].sort_unstable_by(|a, b| {
            a.name[..usize::from(a.name_len)].cmp(&b.name[..usize::from(b.name_len)])
        });
        out[..count].copy_from_slice(&self.entries[..count]);
        Ok(count)
    }
    fn load_pointers(&mut self, inode: &Inode) -> Result<()> {
        self.pointers.fill(0);
        self.pointers[..12].copy_from_slice(&inode.direct);
        if inode.indirect != 0 {
            self.read_work(inode.indirect)?;
            for i in 0..1012 {
                let p = 4 * i;
                self.pointers[12 + i] = u32::from_le_bytes([
                    self.block[p],
                    self.block[p + 1],
                    self.block[p + 2],
                    self.block[p + 3],
                ]);
            }
        }
        Ok(())
    }
    pub fn read(
        &mut self,
        number: u16,
        generation: u64,
        offset: u32,
        out: &mut [u8],
    ) -> Result<usize> {
        if out.len() > 4096 {
            return Err(Error::Invalid);
        }
        if out.is_empty() {
            return Ok(0);
        }
        self.readable()?;
        let inode = self.identity(number, generation)?;
        if offset > inode.size {
            return Err(Error::Invalid);
        }
        let size = out.len().min((inode.size - offset) as usize);
        self.load_pointers(&inode)?;
        let mut done = 0usize;
        while done < size {
            let pos = offset as usize + done;
            self.read_work(self.pointers[pos / 4096])?;
            let n = (4096 - pos % 4096).min(size - done);
            self.buffer[done..done + n].copy_from_slice(&self.block[pos % 4096..pos % 4096 + n]);
            done += n;
        }
        out[..size].copy_from_slice(&self.buffer[..size]);
        Ok(size)
    }
    fn start(&mut self) -> Result<()> {
        self.mutable()?;
        self.read_work(19)?;
        let result = disk::decode_bitmap(&self.block, &mut self.bits);
        let seq = self.corrupt(result)?;
        if seq != self.sequence {
            self.state = State::Failed;
            return Err(Error::Io);
        }
        self.transaction.reset(self.uuid, seq + 1);
        Ok(())
    }
    fn stage(&mut self, target: u32) -> Result<()> {
        if self.transaction.image(target).is_none() {
            self.read_work(target)?;
            self.transaction
                .insert(target, &self.block)
                .map_err(Error::Disk)?;
        }
        Ok(())
    }
    fn stage_inode(&mut self, number: u16, inode: &Inode) -> Result<()> {
        let ix = usize::from(number) - 1;
        let target = 20 + (ix / 32) as u32;
        let mut record = [0; 128];
        inode.encode(&mut record).map_err(Error::Disk)?;
        self.stage(target)?;
        if let Some(b) = self.transaction.image_mut(target) {
            b[ix % 32 * 128..(ix % 32 + 1) * 128].copy_from_slice(&record);
            Ok(())
        } else {
            Err(Error::Io)
        }
    }
    fn stage_entry(&mut self, index: usize, entry: Option<&DirectoryEntry>) -> Result<()> {
        let target = 28 + (index / 64) as u32;
        let mut record = [0; 64];
        if let Some(e) = entry {
            e.encode(&mut record).map_err(Error::Disk)?;
        }
        self.stage(target)?;
        if let Some(b) = self.transaction.image_mut(target) {
            b[index % 64 * 64..(index % 64 + 1) * 64].copy_from_slice(&record);
            Ok(())
        } else {
            Err(Error::Io)
        }
    }
    fn finish(&mut self) -> Result<()> {
        disk::encode_bitmap(&self.bits, self.sequence + 1, &mut self.block).map_err(Error::Disk)?;
        self.transaction
            .insert(19, &self.block)
            .map_err(Error::Disk)?;
        if let Err(e) = self.transaction.commit(&mut self.device) {
            self.state = State::Failed;
            return Err(Error::Disk(e));
        }
        self.sequence += 1;
        if self.sequence == u64::MAX {
            self.state = State::ReadOnly;
        }
        Ok(())
    }
    fn allocate(&mut self) -> Result<u32> {
        for n in 32..16384u32 {
            if self.bits[n as usize / 8] & (1 << (n % 8)) == 0 {
                self.bits[n as usize / 8] |= 1 << (n % 8);
                return Ok(n);
            }
        }
        Err(Error::NoSpace)
    }
    fn free_blocks(&mut self, inode: &Inode) -> Result<()> {
        self.load_pointers(inode)?;
        for p in self.pointers[..inode.size.div_ceil(4096) as usize]
            .iter()
            .copied()
            .chain(core::iter::once(inode.indirect))
        {
            if p != 0 {
                if !(32..16384).contains(&p) {
                    self.state = State::Failed;
                    return Err(Error::Io);
                }
                self.bits[p as usize / 8] &= !(1 << (p % 8));
            }
        }
        Ok(())
    }
    pub fn create(&mut self, name: &[u8]) -> Result<FileStat> {
        Self::name(name)?;
        self.mutable()?;
        match self.find(name) {
            Ok(_) => return Err(Error::Exists),
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }
        let mut selected = None;
        for n in 1..=256 {
            let i = self.inode(n)?;
            if !i.live && i.generation < u64::MAX {
                selected = Some((n, i.generation + 1));
                break;
            }
        }
        let (number, generation) = selected.ok_or(Error::NoSpace)?;
        let mut slot = None;
        for n in 0..256 {
            if self.entry(n)?.is_none() {
                slot = Some(n);
                break;
            }
        }
        let slot = slot.ok_or(Error::NoSpace)?;
        self.start()?;
        let inode = Inode {
            live: true,
            generation,
            ..Inode::EMPTY
        };
        let mut e = DirectoryEntry {
            inode: number,
            generation,
            name: [0; 47],
            name_len: name.len() as u8,
        };
        e.name[..name.len()].copy_from_slice(name);
        self.stage_inode(number, &inode)?;
        self.stage_entry(slot, Some(&e))?;
        self.finish()?;
        Ok(FileStat {
            inode: number,
            generation,
            size: 0,
        })
    }
    pub fn truncate(&mut self, number: u16, generation: u64) -> Result<()> {
        self.mutable()?;
        let mut inode = self.identity(number, generation)?;
        if inode.size == 0 {
            return Ok(());
        }
        self.start()?;
        self.free_blocks(&inode)?;
        inode.size = 0;
        inode.direct.fill(0);
        inode.indirect = 0;
        self.stage_inode(number, &inode)?;
        self.finish()
    }
    pub fn write(
        &mut self,
        number: u16,
        generation: u64,
        offset: u32,
        data: &[u8],
    ) -> Result<usize> {
        if data.len() > 4096 {
            return Err(Error::Invalid);
        }
        if data.is_empty() {
            return Ok(0);
        }
        self.mutable()?;
        let mut inode = self.identity(number, generation)?;
        if offset > inode.size {
            return Err(Error::Invalid);
        }
        let end = offset
            .checked_add(data.len() as u32)
            .ok_or(Error::FileTooLarge)?;
        if end > disk::MAX_FILE_SIZE {
            return Err(Error::FileTooLarge);
        }
        let old_count = inode.size.div_ceil(4096) as usize;
        let new_size = inode.size.max(end);
        let new_count = new_size.div_ceil(4096) as usize;
        self.load_pointers(&inode)?;
        self.start()?;
        for index in old_count..new_count {
            self.pointers[index] = self.allocate()?;
        }
        if new_count > 12 && inode.indirect == 0 {
            inode.indirect = self.allocate()?;
        }
        let mut done = 0usize;
        while done < data.len() {
            let pos = offset as usize + done;
            let index = pos / 4096;
            let target = self.pointers[index];
            if index < old_count {
                self.read_work(target)?;
            } else {
                self.block.fill(0);
            }
            let n = (4096 - pos % 4096).min(data.len() - done);
            self.block[pos % 4096..pos % 4096 + n].copy_from_slice(&data[done..done + n]);
            if index + 1 == new_count && new_size % 4096 != 0 {
                self.block[(new_size % 4096) as usize..].fill(0);
            }
            self.transaction
                .insert(target, &self.block)
                .map_err(Error::Disk)?;
            done += n;
        }
        inode.direct.copy_from_slice(&self.pointers[..12]);
        inode.size = new_size;
        if inode.indirect != 0 {
            self.block.fill(0);
            for i in 0..1012 {
                self.block[i * 4..i * 4 + 4].copy_from_slice(&self.pointers[12 + i].to_le_bytes());
            }
            self.transaction
                .insert(inode.indirect, &self.block)
                .map_err(Error::Disk)?;
        }
        self.stage_inode(number, &inode)?;
        self.finish()?;
        Ok(data.len())
    }
    pub fn unlink<F: Fn(u16, u64) -> bool>(&mut self, name: &[u8], is_open: F) -> Result<()> {
        Self::name(name)?;
        self.mutable()?;
        let (slot, e) = self.find(name)?;
        if is_open(e.inode, e.generation) {
            return Err(Error::Busy);
        }
        let inode = self.identity(e.inode, e.generation)?;
        self.start()?;
        self.free_blocks(&inode)?;
        self.stage_inode(
            e.inode,
            &Inode {
                generation: e.generation,
                ..Inode::EMPTY
            },
        )?;
        self.stage_entry(slot, None)?;
        self.finish()
    }
    pub fn rename<F: Fn(u16, u64) -> bool>(
        &mut self,
        source: &[u8],
        destination: &[u8],
        is_open: F,
    ) -> Result<()> {
        Self::name(source)?;
        Self::name(destination)?;
        self.mutable()?;
        let (source_slot, mut source_entry) = self.find(source)?;
        if source == destination {
            return Ok(());
        }
        let destination_entry = match self.find(destination) {
            Ok(e) => Some(e),
            Err(Error::NotFound) => None,
            Err(e) => return Err(e),
        };
        if let Some((_, e)) = destination_entry
            && is_open(e.inode, e.generation)
        {
            return Err(Error::Busy);
        }
        self.start()?;
        if let Some((slot, e)) = destination_entry {
            let inode = self.identity(e.inode, e.generation)?;
            self.free_blocks(&inode)?;
            self.stage_inode(
                e.inode,
                &Inode {
                    generation: e.generation,
                    ..Inode::EMPTY
                },
            )?;
            self.stage_entry(slot, None)?;
        }
        source_entry.name.fill(0);
        source_entry.name[..destination.len()].copy_from_slice(destination);
        source_entry.name_len = destination.len() as u8;
        self.stage_entry(source_slot, Some(&source_entry))?;
        self.finish()
    }
    pub fn fsync(&mut self) -> Result<()> {
        self.readable()
    }
    pub fn flush(&mut self) -> Result<()> {
        self.readable()?;
        self.device.flush().map_err(|e| {
            self.state = State::Failed;
            Error::Disk(e)
        })
    }
}

#[cfg(test)]
mod tests;
