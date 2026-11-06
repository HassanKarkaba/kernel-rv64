#![no_std]
#![no_main]
use core::fmt::{self, Write};
use kernel_core::shell::{self, Command, Parsed};
use user_runtime as rt;
rt::entry!(main);

struct TemporaryName {
    bytes: [u8; 48],
    len: usize,
}
impl Write for TemporaryName {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.len + s.len() > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + s.len()].copy_from_slice(s.as_bytes());
        self.len += s.len();
        Ok(())
    }
}
fn text(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("?")
}
fn report(error: i64) {
    if error == -5 {
        rt::println!("error EIO: storage recovery is required");
    } else {
        rt::println!("error {}", error);
    }
}
fn reap_tracked(tracked: &mut [u64; 63]) {
    for entry in tracked {
        if *entry == 0 {
            continue;
        }
        match rt::wait(*entry, true) {
            Ok(status) => {
                rt::println!(
                    "child {} ended kind={} code={}",
                    status.pid,
                    status.kind,
                    status.code
                );
                *entry = 0;
            }
            Err(-11) => {}
            Err(error) => {
                report(error);
                if error == -10 {
                    *entry = 0;
                }
            }
        }
    }
}
fn spawn(parsed: &Parsed, start: usize, end: usize, stdio: [i32; 3]) -> rt::Result<u64> {
    let mut args: [&[u8]; 16] = [&[]; 16];
    for (i, a) in args[..end - start - 1].iter_mut().enumerate() {
        *a = parsed.token(start + i + 1);
    }
    rt::spawn(parsed.token(start), &args[..end - start - 1], stdio)
}
fn wait_foreground(pid: u64) -> rt::Result<()> {
    let status = rt::wait(pid, false)?;
    rt::println!(
        "child {} ended kind={} code={}",
        pid,
        status.kind,
        status.code
    );
    Ok(())
}
fn run(parsed: &Parsed, pipe: Option<usize>, tracked: &mut [u64; 63]) -> rt::Result<()> {
    if let Some(separator) = pipe {
        let registry = tracked.iter().position(|p| *p == 0).ok_or(-11)?;
        let endpoints = rt::pipe()?;
        let first = spawn(parsed, 1, separator, [0, endpoints[1] as i32, 2]);
        let first = match first {
            Ok(pid) => pid,
            Err(e) => {
                let _ = rt::close(endpoints[0]);
                let _ = rt::close(endpoints[1]);
                return Err(e);
            }
        };
        let second = spawn(
            parsed,
            separator + 1,
            parsed.count,
            [endpoints[0] as i32, 1, 2],
        );
        // Endpoint closure must precede waits, including the partial spawn path.
        let _ = rt::close(endpoints[0]);
        let _ = rt::close(endpoints[1]);
        match second {
            Ok(pid) => {
                let a = wait_foreground(first);
                let b = wait_foreground(pid);
                a.and(b)
            }
            Err(error) => {
                tracked[registry] = first;
                rt::println!(
                    "second spawn failed {}; surviving child {} is tracked",
                    error,
                    first
                );
                Err(error)
            }
        }
    } else {
        let pid = spawn(parsed, 1, parsed.count, [0, 1, 2])?;
        wait_foreground(pid)
    }
}
fn replace(path: &[u8], bytes: &[u8], counter: &mut u64) -> rt::Result<()> {
    let mut name = TemporaryName {
        bytes: [0; 48],
        len: 0,
    };
    let mut descriptor = None;
    // The flat namespace contains at most 256 files, so 257 distinct candidates suffice.
    for _ in 0..257 {
        *counter = counter.checked_add(1).ok_or(-28)?;
        name.len = 0;
        write!(&mut name, "/.tmp-{}", counter).map_err(|_| -22)?;
        match rt::open(&name.bytes[..name.len], 2 | 0x100 | 0x200) {
            Ok(fd) => {
                descriptor = Some(fd);
                break;
            }
            Err(-17) => continue,
            Err(error) => return Err(error),
        }
    }
    let fd = descriptor.ok_or(-28)?;
    let written = rt::write_all(fd, bytes).map_err(|e| e.error);
    let closed = rt::close(fd);
    let result = written
        .map(|_| ())
        .and(closed)
        .and_then(|_| rt::rename(&name.bytes[..name.len], path));
    if result.is_err() {
        rt::println!(
            "replacement failed; temporary file may remain: {}",
            text(&name.bytes[..name.len])
        );
    }
    result
}
fn cat(path: &[u8]) -> rt::Result<()> {
    let fd = rt::open(path, 1)?;
    let result = (|| {
        let mut buffer = [0; 4096];
        loop {
            let n = rt::read(fd, &mut buffer)?;
            if n == 0 {
                break;
            }
            rt::write_all(1, &buffer[..n]).map_err(|e| e.error)?;
        }
        Ok(())
    })();
    let closed = rt::close(fd);
    result.and(closed)
}
fn ls() -> rt::Result<()> {
    let mut records = [[0u8; 64]; 256];
    let count = rt::list(&mut records)?;
    for record in &records[..count] {
        let len = u32::from_le_bytes(record[4..8].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(record[8..16].try_into().unwrap());
        rt::println!("/{} {}", text(&record[16..16 + len]), size);
    }
    Ok(())
}
fn ps() -> rt::Result<()> {
    let mut records = [[0u8; 32]; 64];
    let count = rt::process_list(&mut records)?;
    rt::println!("PID PARENT STATE PAGES");
    for record in &records[..count] {
        let pid = u64::from_le_bytes(record[..8].try_into().unwrap());
        let parent = u64::from_le_bytes(record[8..16].try_into().unwrap());
        let state = u32::from_le_bytes(record[16..20].try_into().unwrap());
        let pages = u32::from_le_bytes(record[20..24].try_into().unwrap());
        rt::println!("{} {} {} {}", pid, parent, state, pages);
    }
    Ok(())
}
fn execute(parsed: &Parsed, tracked: &mut [u64; 63], counter: &mut u64) -> rt::Result<()> {
    match parsed.command().map_err(|e| e.return_value())? {
        Command::Empty => Ok(()),
        Command::Help => {
            rt::println!(
                "help | ls | cat /name | write /name text | rm /name | mv /old /new\nrun /program args [ | /program args ] | ps | shutdown\nUse double quotes and backslash escapes. Ctrl-C is an ordinary byte."
            );
            Ok(())
        }
        Command::List => ls(),
        Command::Processes => ps(),
        Command::Cat => cat(parsed.token(1)),
        Command::Write => replace(parsed.token(1), parsed.token(2), counter),
        Command::Remove => rt::unlink(parsed.token(1)),
        Command::Move => rt::rename(parsed.token(1), parsed.token(2)),
        Command::Run { pipe } => run(parsed, pipe, tracked),
        Command::Shutdown => rt::shutdown(),
    }
}
fn main(_: &[&[u8]]) -> i32 {
    let mut line = [0u8; 1024];
    let mut counter = 0;
    let mut tracked = [0; 63];
    let mut previous_cr = false;
    rt::println!("RISC-V shell; type help");
    loop {
        reap_tracked(&mut tracked);
        rt::print!("> ");
        let mut length = 0;
        let mut rejected = false;
        loop {
            let mut byte = [0; 1];
            match rt::read(0, &mut byte) {
                Ok(0) => continue,
                Ok(_) => {}
                Err(e) => {
                    report(e);
                    continue;
                }
            }
            let b = byte[0];
            if b == b'\n' && previous_cr {
                previous_cr = false;
                continue;
            }
            previous_cr = b == b'\r';
            if matches!(b, b'\r' | b'\n') {
                rt::println!();
                break;
            }
            if matches!(b, 8 | 127) {
                if !rejected && length != 0 {
                    length -= 1;
                    let _ = rt::write_all(1, b"\x08 \x08");
                }
            } else if length == 1024 {
                rejected = true;
            } else if (32..=126).contains(&b) {
                line[length] = b;
                length += 1;
                let _ = rt::write(1, &byte);
            } else {
                rejected = true;
            }
        }
        if rejected {
            rt::println!("invalid or oversized line; no command executed");
            continue;
        }
        match shell::parse(&line[..length]) {
            Ok(parsed) => {
                if let Err(error) = execute(&parsed, &mut tracked, &mut counter) {
                    report(error);
                }
            }
            Err(error) => report(error.return_value()),
        }
        reap_tracked(&mut tracked);
    }
}
