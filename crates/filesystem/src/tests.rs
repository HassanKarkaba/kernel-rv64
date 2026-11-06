extern crate std;
use self::std::{boxed::Box, collections::BTreeMap, vec::Vec};
use super::*;
use disk::{BlockDevice, IMAGE_SIZE, Inode, Superblock};

type Sector = [u8; 512];
#[derive(Clone)]
struct MemoryDisk {
    stable: BTreeMap<usize, Sector>,
    current: BTreeMap<usize, Sector>,
    pending: Vec<(usize, Sector)>,
    event: usize,
    cut: Option<usize>,
}
impl MemoryDisk {
    fn formatted() -> Self {
        let mut result = Self {
            stable: BTreeMap::new(),
            current: BTreeMap::new(),
            pending: Vec::new(),
            event: 0,
            cut: None,
        };
        let mut block = [0; 4096];
        Superblock { uuid: [0x42; 16] }.encode(&mut block);
        result.write_block(0, &block).unwrap();
        let mut bits = [0; 2048];
        bits[..4].fill(255);
        disk::encode_bitmap(&bits, 0, &mut block).unwrap();
        result.write_block(19, &block).unwrap();
        block.fill(0);
        let mut record = [0; 128];
        Inode::EMPTY.encode(&mut record).unwrap();
        for i in 0..32 {
            block[i * 128..(i + 1) * 128].copy_from_slice(&record);
        }
        for target in 20..28 {
            result.write_block(target, &block).unwrap();
        }
        result.flush().unwrap();
        result.event = 0;
        result
    }
    fn event(&mut self) -> disk::Result<()> {
        if self.cut == Some(self.event) {
            return Err(disk::Error::Io);
        }
        self.event += 1;
        Ok(())
    }
    fn sector(&mut self, number: usize, data: Sector) -> disk::Result<()> {
        self.event()?;
        self.current.insert(number, data);
        self.pending.push((number, data));
        Ok(())
    }
    fn crash(mut self, policy: usize) -> Self {
        for (index, (sector, bytes)) in self.pending.drain(..).enumerate() {
            if policy == 1 || (policy == 2 && index % 2 == 0) || (policy == 3 && index % 2 == 1) {
                self.stable.insert(sector, bytes);
            }
        }
        self.current = self.stable.clone();
        self.event = 0;
        self.cut = None;
        self
    }
}
impl BlockDevice for MemoryDisk {
    fn byte_len(&self) -> u64 {
        IMAGE_SIZE
    }
    fn read_block(&mut self, number: u32, out: &mut Block) -> disk::Result<()> {
        if number >= 16384 {
            return Err(disk::Error::Bounds);
        }
        out.fill(0);
        for i in 0..8 {
            if let Some(s) = self.current.get(&(number as usize * 8 + i)) {
                out[i * 512..(i + 1) * 512].copy_from_slice(s);
            }
        }
        Ok(())
    }
    fn write_block(&mut self, number: u32, block: &Block) -> disk::Result<()> {
        if number >= 16384 {
            return Err(disk::Error::Bounds);
        }
        for i in 0..8 {
            let mut s = [0; 512];
            s.copy_from_slice(&block[i * 512..(i + 1) * 512]);
            self.sector(number as usize * 8 + i, s)?;
        }
        Ok(())
    }
    fn write_commit(&mut self, bytes: &Sector) -> disk::Result<()> {
        self.sector(8, *bytes)
    }
    fn flush(&mut self) -> disk::Result<()> {
        self.event()?;
        for (sector, bytes) in self.pending.drain(..) {
            self.stable.insert(sector, bytes);
        }
        Ok(())
    }
}
fn mounted(device: MemoryDisk) -> Box<FileSystem<MemoryDisk>> {
    let mut fs = Box::new(FileSystem::new(device));
    let mut scratch = Box::new(ScanScratch::new());
    fs.mount(&mut scratch).unwrap();
    fs
}
fn assert_scan(fs: &mut FileSystem<MemoryDisk>) {
    let mut scratch = Box::new(ScanScratch::new());
    disk::scan(fs.device_mut(), &mut scratch).unwrap();
}

#[test]
fn create_write_cross_block_read_truncate_and_generation_reuse() {
    let mut fs = mounted(MemoryDisk::formatted());
    let a = fs.create(b"alpha").unwrap();
    assert_eq!(a.inode, 1);
    assert_eq!(a.generation, 1);
    assert_eq!(fs.write(a.inode, a.generation, 0, &[7; 4096]), Ok(4096));
    assert_eq!(fs.write(a.inode, a.generation, 4090, &[9; 32]), Ok(32));
    let mut bytes = [0; 40];
    assert_eq!(fs.read(a.inode, a.generation, 4082, &mut bytes), Ok(40));
    assert_eq!(&bytes[..8], &[7; 8]);
    assert_eq!(&bytes[8..], &[9; 32]);
    assert_scan(&mut fs);
    assert_eq!(fs.unlink(b"alpha", |_, _| true), Err(Error::Busy));
    fs.truncate(a.inode, a.generation).unwrap();
    assert_eq!(fs.stat(a.inode, a.generation).unwrap().size, 0);
    assert_scan(&mut fs);
    fs.unlink(b"alpha", |_, _| false).unwrap();
    let b = fs.create(b"beta").unwrap();
    assert_eq!(b.inode, a.inode);
    assert_eq!(b.generation, a.generation + 1);
    assert_eq!(fs.stat(a.inode, a.generation), Err(Error::Stale));
    assert_scan(&mut fs);
}
#[test]
fn indirect_boundary_and_atomic_rename() {
    let mut fs = mounted(MemoryDisk::formatted());
    let a = fs.create(b"z").unwrap();
    for i in 0..13 {
        fs.write(a.inode, a.generation, i * 4096, &[i as u8; 4096])
            .unwrap();
    }
    assert_scan(&mut fs);
    let b = fs.create(b"a").unwrap();
    fs.write(b.inode, b.generation, 0, b"replace").unwrap();
    assert_eq!(fs.rename(b"z", b"a", |_, _| true), Err(Error::Busy));
    assert_eq!(fs.rename(b"z", b"z", |_, _| true), Ok(()));
    fs.rename(b"z", b"a", |_, _| false).unwrap();
    assert_eq!(fs.lookup(b"a").unwrap().inode, a.inode);
    assert_eq!(fs.lookup(b"z"), Err(Error::NotFound));
    assert_scan(&mut fs);
    let mut list = [Entry::EMPTY; 256];
    assert_eq!(fs.list(&mut list), Ok(1));
    assert_eq!(list[0].name[0], b'a');
    fs.truncate(a.inode, a.generation).unwrap();
    assert_scan(&mut fs);
}
#[test]
fn rejection_has_no_disk_effect() {
    let mut fs = mounted(MemoryDisk::formatted());
    let a = fs.create(b"a").unwrap();
    let before = fs.device.stable.clone();
    let seq = fs.sequence();
    assert_eq!(fs.create(b"a"), Err(Error::Exists));
    assert_eq!(fs.create(b".."), Err(Error::Invalid));
    assert_eq!(
        fs.write(a.inode, a.generation, 1, b"x"),
        Err(Error::Invalid)
    );
    assert_eq!(
        fs.write(a.inode, a.generation, 0, &[0; 4097]),
        Err(Error::Invalid)
    );
    assert_eq!(fs.sequence(), seq);
    assert_eq!(fs.device.stable, before);
    let mut empty = [];
    assert_eq!(fs.list(&mut empty), Err(Error::BufferTooSmall));
    assert_scan(&mut fs);
}
#[test]
fn every_sector_and_barrier_cut_preserves_a_complete_mutation() {
    let mut setup = mounted(MemoryDisk::formatted());
    let a = setup.create(b"result").unwrap();
    setup.write(a.inode, a.generation, 0, b"before").unwrap();
    let baseline = setup.into_device();
    let mut complete = mounted(baseline.clone());
    complete.device.event = 0;
    complete.write(a.inode, a.generation, 0, b"after!").unwrap();
    let events = complete.device.event;
    for cut in 0..=events {
        for policy in 0..4 {
            let mut fs = mounted(baseline.clone());
            fs.device.event = 0;
            fs.device.cut = Some(cut);
            let acknowledged = fs.write(a.inode, a.generation, 0, b"after!").is_ok();
            if !acknowledged {
                assert_eq!(fs.state(), State::Failed);
                assert_eq!(fs.lookup(b"result"), Err(Error::Io));
            }
            let device = fs.into_device().crash(policy);
            let mut recovered = mounted(device);
            let mut data = [0; 6];
            recovered.read(a.inode, a.generation, 0, &mut data).unwrap();
            assert!(
                data == *b"before" || data == *b"after!",
                "cut={cut} policy={policy}"
            );
            if acknowledged {
                assert_eq!(data, *b"after!");
            }
            assert_scan(&mut recovered);
        }
    }
}
#[test]
fn sequence_exhaustion_is_read_only() {
    let mut disk = MemoryDisk::formatted();
    let mut bits = [0; 2048];
    bits[..4].fill(255);
    let mut block = [0; 4096];
    disk::encode_bitmap(&bits, u64::MAX, &mut block).unwrap();
    disk.write_block(19, &block).unwrap();
    disk.flush().unwrap();
    let mut fs = mounted(disk);
    assert_eq!(fs.state(), State::ReadOnly);
    assert_eq!(fs.create(b"a"), Err(Error::ReadOnly));
    assert_eq!(fs.fsync(), Ok(()));
}
