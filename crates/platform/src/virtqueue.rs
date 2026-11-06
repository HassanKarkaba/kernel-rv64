//! Pure validation at the device boundary. DMA reads occur in the driver.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Read,
    Write,
    Flush,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionError {
    Descriptor,
    Length,
    Io,
    Unsupported,
    Status,
}

pub fn validate_completion(
    operation: Operation,
    data_len: u32,
    expected_id: u32,
    used_id: u32,
    used_len: u32,
    status: u8,
) -> Result<(), CompletionError> {
    if used_id != expected_id {
        return Err(CompletionError::Descriptor);
    }
    let writable = match operation {
        Operation::Read => data_len.checked_add(1).ok_or(CompletionError::Length)?,
        _ => 1,
    };
    if used_len == 0 || used_len > writable || (status == 0 && used_len != writable) {
        return Err(CompletionError::Length);
    }
    match status {
        0 => Ok(()),
        1 => Err(CompletionError::Io),
        2 => Err(CompletionError::Unsupported),
        _ => Err(CompletionError::Status),
    }
}

pub fn valid_transfer(operation: Operation, sector: u64, len: usize) -> bool {
    match operation {
        Operation::Flush => sector == 0 && len == 0,
        _ => {
            (len == 512 || len == 4096)
                && sector
                    .checked_add((len / 512) as u64)
                    .is_some_and(|end| end <= 131072)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_completion_never_exposes_success() {
        assert_eq!(
            validate_completion(Operation::Read, 4096, 0, 0, 4097, 0),
            Ok(())
        );
        assert_eq!(
            validate_completion(Operation::Read, 4096, 0, 1, 4097, 0),
            Err(CompletionError::Descriptor)
        );
        assert_eq!(
            validate_completion(Operation::Read, 4096, 0, 0, 4096, 0),
            Err(CompletionError::Length)
        );
        assert_eq!(
            validate_completion(Operation::Write, 4096, 0, 0, 4097, 0),
            Err(CompletionError::Length)
        );
        assert_eq!(
            validate_completion(Operation::Read, 4096, 0, 0, 1, 1),
            Err(CompletionError::Io)
        );
        assert_eq!(
            validate_completion(Operation::Flush, 0, 0, 0, 1, 255),
            Err(CompletionError::Status)
        );
        assert!(!valid_transfer(Operation::Read, u64::MAX, 512));
        assert!(!valid_transfer(Operation::Write, 131071, 4096));
        assert!(valid_transfer(Operation::Write, 131071, 512));
    }
}
