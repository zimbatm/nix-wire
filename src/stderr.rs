//! Nix daemon stderr message codes.
//!
//! During operation processing, the daemon sends stderr messages
//! terminated by STDERR_LAST (success) or STDERR_ERROR (failure).

/// Stderr message codes sent by the daemon during operation processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum StderrCode {
    /// Log line: followed by a length-prefixed string.
    Next = 0x6f6c6d67,

    /// Data read request: daemon needs data from client source.
    /// Followed by u64 length.
    Read = 0x64617461,

    /// Data write: daemon sends data to client sink.
    /// Followed by a length-prefixed string.
    Write = 0x64617416,

    /// Success: operation completed, response data follows.
    Last = 0x616c7473,

    /// Error: operation failed.
    /// Followed by error type string, error level u64, error name string,
    /// error message string, u64 have-pos, and optional position info.
    Error = 0x63787470,

    /// Start activity: structured logging.
    StartActivity = 0x53545254,

    /// Stop activity: structured logging.
    StopActivity = 0x53544f50,

    /// Result: structured logging result.
    Result = 0x52534c54,
}

impl StderrCode {
    /// Try to parse a u64 into a known stderr code.
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0x6f6c6d67 => Some(Self::Next),
            0x64617461 => Some(Self::Read),
            0x64617416 => Some(Self::Write),
            0x616c7473 => Some(Self::Last),
            0x63787470 => Some(Self::Error),
            0x53545254 => Some(Self::StartActivity),
            0x53544f50 => Some(Self::StopActivity),
            0x52534c54 => Some(Self::Result),
            _ => None,
        }
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Next => "STDERR_NEXT",
            Self::Read => "STDERR_READ",
            Self::Write => "STDERR_WRITE",
            Self::Last => "STDERR_LAST",
            Self::Error => "STDERR_ERROR",
            Self::StartActivity => "STDERR_START_ACTIVITY",
            Self::StopActivity => "STDERR_STOP_ACTIVITY",
            Self::Result => "STDERR_RESULT",
        }
    }

    /// Whether this code terminates the stderr message loop.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Last | Self::Error)
    }
}

impl std::fmt::Display for StderrCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_codes_roundtrip() {
        let codes = [
            StderrCode::Next,
            StderrCode::Read,
            StderrCode::Write,
            StderrCode::Last,
            StderrCode::Error,
            StderrCode::StartActivity,
            StderrCode::StopActivity,
            StderrCode::Result,
        ];
        for code in codes {
            let val = code as u64;
            assert_eq!(
                StderrCode::from_u64(val),
                Some(code),
                "roundtrip failed for {:?}",
                code
            );
        }
    }

    #[test]
    fn terminal_codes() {
        assert!(StderrCode::Last.is_terminal());
        assert!(StderrCode::Error.is_terminal());
        assert!(!StderrCode::Next.is_terminal());
        assert!(!StderrCode::StartActivity.is_terminal());
    }

    #[test]
    fn code_count() {
        assert_eq!(
            [
                StderrCode::Next,
                StderrCode::Read,
                StderrCode::Write,
                StderrCode::Last,
                StderrCode::Error,
                StderrCode::StartActivity,
                StderrCode::StopActivity,
                StderrCode::Result,
            ]
            .len(),
            8
        );
    }

    #[test]
    fn unknown_code() {
        assert_eq!(StderrCode::from_u64(0), None);
        assert_eq!(StderrCode::from_u64(0xdeadbeef), None);
    }
}
