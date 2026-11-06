//! Bounded shell grammar. Parse and validate the complete line before invoking
//! any spawn or filesystem operation.
use kernel_abi::{Error, path_name, validate_arguments};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Token {
    start: usize,
    len: usize,
    pipe: bool,
}
pub struct Parsed {
    bytes: [u8; 1024],
    tokens: [Token; 32],
    pub count: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Empty,
    Help,
    List,
    Cat,
    Write,
    Remove,
    Move,
    Run { pipe: Option<usize> },
    Processes,
    Shutdown,
}
impl Parsed {
    pub fn token(&self, index: usize) -> &[u8] {
        let t = self.tokens[index];
        &self.bytes[t.start..t.start + t.len]
    }
    pub fn command(&self) -> Result<Command, Error> {
        if self.count == 0 {
            return Ok(Command::Empty);
        }
        let pipe = (0..self.count).find(|i| self.tokens[*i].pipe);
        let c = self.token(0);
        if c != b"run" && pipe.is_some() {
            return Err(Error::Invalid);
        }
        match c {
            b"help" if self.count == 1 => Ok(Command::Help),
            b"ls" if self.count == 1 => Ok(Command::List),
            b"ps" if self.count == 1 => Ok(Command::Processes),
            b"shutdown" if self.count == 1 => Ok(Command::Shutdown),
            b"cat" | b"rm" if self.count == 2 => {
                path_name(self.token(1))?;
                Ok(if c == b"cat" {
                    Command::Cat
                } else {
                    Command::Remove
                })
            }
            b"write" | b"mv" if self.count == 3 => {
                path_name(self.token(1))?;
                if c == b"mv" {
                    path_name(self.token(2))?;
                }
                Ok(if c == b"write" {
                    Command::Write
                } else {
                    Command::Move
                })
            }
            b"run" if self.count >= 2 => {
                let left_end = pipe.unwrap_or(self.count);
                self.program(1, left_end)?;
                if let Some(separator) = pipe {
                    self.program(separator + 1, self.count)?;
                }
                Ok(Command::Run { pipe })
            }
            _ => Err(Error::Invalid),
        }
    }
    fn program(&self, start: usize, end: usize) -> Result<(), Error> {
        if start >= end || end - start - 1 > 16 {
            return Err(Error::Invalid);
        }
        path_name(self.token(start))?;
        let mut args: [&[u8]; 16] = [&[]; 16];
        for (i, a) in args[..end - start - 1].iter_mut().enumerate() {
            *a = self.token(start + i + 1);
        }
        validate_arguments(&args[..end - start - 1])?;
        Ok(())
    }
}

pub fn parse(line: &[u8]) -> Result<Parsed, Error> {
    if line.len() > 1024 || !line.iter().all(|b| (32..=126).contains(b)) {
        return Err(Error::Invalid);
    }
    let mut out = Parsed {
        bytes: [0; 1024],
        tokens: [Token::default(); 32],
        count: 0,
    };
    let mut read = 0;
    let mut write = 0;
    let mut seen_pipe = false;
    while read < line.len() {
        if line[read] == b' ' {
            read += 1;
            continue;
        }
        if out.count == 32 {
            return Err(Error::TooBig);
        }
        let start = write;
        if line[read] == b'|' {
            if seen_pipe {
                return Err(Error::Invalid);
            }
            seen_pipe = true;
            read += 1;
            out.tokens[out.count] = Token {
                start,
                len: 0,
                pipe: true,
            };
            out.count += 1;
            continue;
        }
        let mut quoted = false;
        while read < line.len() {
            let b = line[read];
            if !quoted && matches!(b, b' ' | b'|') {
                break;
            }
            read += 1;
            if b == b'"' {
                quoted = !quoted;
                continue;
            }
            let next = if b == b'\\' {
                if read == line.len() {
                    return Err(Error::Invalid);
                }
                let byte = line[read];
                read += 1;
                byte
            } else {
                b
            };
            out.bytes[write] = next;
            write += 1;
        }
        if quoted {
            return Err(Error::Invalid);
        }
        out.tokens[out.count] = Token {
            start,
            len: write - start,
            pipe: false,
        };
        out.count += 1;
    }
    // Empty pipeline legs, built-in arity and all argument bounds are checked
    // here so callers cannot accidentally act on a partly accepted parse.
    out.command()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoted_and_escaped_pipes_are_arguments() {
        let p = parse(br#"run /p "a | b" \| "" | /q"#).unwrap();
        assert_eq!(p.command(), Ok(Command::Run { pipe: Some(5) }));
        assert_eq!(p.token(2), b"a | b");
        assert_eq!(p.token(3), b"|");
        assert_eq!(p.token(4), b"");
    }
    #[test]
    fn invalid_complete_lines_never_admit_commands() {
        for line in [
            b"write /x a b".as_slice(),
            b"ls | /p",
            b"run /p |",
            b"run /p | /q | /r",
            b"run /p \"x",
            b"run /p \\",
            b"cat /x/y",
            b"run /p\targ",
        ] {
            assert!(parse(line).is_err());
        }
        assert!(parse(&[b'a'; 1025]).is_err());
    }
    #[test]
    fn empty_text_is_a_valid_replacement() {
        let p = parse(b"write /x \"\"").unwrap();
        assert_eq!(p.command(), Ok(Command::Write));
        assert_eq!(p.token(2), b"");
    }
}
