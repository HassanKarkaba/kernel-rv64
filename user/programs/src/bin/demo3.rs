#![no_std]
#![no_main]
use user_runtime as rt;
rt::entry!(main);
fn main(_: &[&[u8]]) -> i32 {
    let mut pids = [0; 3];
    let paths: [&[u8]; 3] = [b"/compute", b"/writer", b"/fault"];
    let mut failed = false;
    for (i, path) in paths.iter().enumerate() {
        match rt::spawn(path, &[], [0, 1, 2]) {
            Ok(pid) => pids[i] = pid,
            Err(e) => {
                rt::println!("spawn error {}", e);
                failed = true;
                break;
            }
        }
    }
    for (i, pid) in pids.iter().enumerate() {
        if *pid == 0 {
            continue;
        }
        match rt::wait(*pid, false) {
            Ok(status)
                if (i == 2 && status.kind == 1)
                    || (i != 2 && status.kind == 0 && status.code == 0) => {}
            _ => failed = true,
        }
    }
    if failed {
        1
    } else {
        rt::println!("demo3 verified peer progress and fault containment");
        0
    }
}
