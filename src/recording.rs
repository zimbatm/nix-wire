//! Recording file format for captured Nix daemon sessions.
//!
//! Binary, little-endian throughout.
//!
//! ## Header (24 bytes)
//! ```text
//! magic:    [u8; 8]  = b"NIXWREC\0"
//! version:  u16      = 1
//! flags:    u16      = 0 (reserved)
//! epoch_ns: u64      = unix timestamp in nanos at session start
//! reserved: u32      = 0
//! ```
//!
//! ## Records (variable length, sequential until EOF)
//! ```text
//! offset_ns:  u64    # nanos since epoch_ns
//! direction:  u8     # 0 = client->daemon, 1 = daemon->client
//! length:     u32    # byte count of following data
//! data:       [u8]   # raw wire bytes
//! ```

use std::io::{self, Read, Write};

use anyhow::{bail, Context, Result};

pub const RECORDING_MAGIC: &[u8; 8] = b"NIXWREC\0";
pub const RECORDING_VERSION: u16 = 1;

/// Header of a recording file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u16,
    pub flags: u16,
    pub epoch_ns: u64,
}

impl Header {
    /// Create a new header with the current time.
    pub fn new(epoch_ns: u64) -> Self {
        Self {
            version: RECORDING_VERSION,
            flags: 0,
            epoch_ns,
        }
    }

    /// Write the header to a stream.
    pub fn write_to(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(RECORDING_MAGIC)?;
        w.write_all(&self.version.to_le_bytes())?;
        w.write_all(&self.flags.to_le_bytes())?;
        w.write_all(&self.epoch_ns.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?; // reserved
        Ok(())
    }

    /// Read the header from a stream.
    pub fn read_from(r: &mut impl Read) -> Result<Self> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)
            .context("failed to read recording magic")?;
        if &magic != RECORDING_MAGIC {
            bail!(
                "not a nix-wire recording (magic: {:?}, expected: {:?})",
                magic,
                RECORDING_MAGIC
            );
        }

        let mut buf2 = [0u8; 2];
        r.read_exact(&mut buf2)?;
        let version = u16::from_le_bytes(buf2);
        if version != RECORDING_VERSION {
            bail!(
                "unsupported recording version {} (expected {})",
                version,
                RECORDING_VERSION
            );
        }

        r.read_exact(&mut buf2)?;
        let flags = u16::from_le_bytes(buf2);

        let mut buf8 = [0u8; 8];
        r.read_exact(&mut buf8)?;
        let epoch_ns = u64::from_le_bytes(buf8);

        let mut buf4 = [0u8; 4];
        r.read_exact(&mut buf4)?; // reserved

        Ok(Self {
            version,
            flags,
            epoch_ns,
        })
    }
}

/// Direction of data flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    /// Client -> Daemon
    ClientToDaemon = 0,
    /// Daemon -> Client
    DaemonToClient = 1,
}

impl Direction {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::ClientToDaemon),
            1 => Some(Self::DaemonToClient),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ClientToDaemon => "C->D",
            Self::DaemonToClient => "D->C",
        }
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// A single recorded chunk of wire data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Nanoseconds since session epoch.
    pub offset_ns: u64,
    /// Direction of data flow.
    pub direction: Direction,
    /// Raw wire bytes.
    pub data: Vec<u8>,
}

impl Record {
    /// Write a record to a stream.
    pub fn write_to(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(&self.offset_ns.to_le_bytes())?;
        w.write_all(&[self.direction as u8])?;
        let len = self.data.len() as u32;
        w.write_all(&len.to_le_bytes())?;
        w.write_all(&self.data)?;
        Ok(())
    }

    /// Read a record from a stream. Returns None on EOF.
    pub fn read_from(r: &mut impl Read) -> Result<Option<Self>> {
        let mut buf8 = [0u8; 8];
        match r.read_exact(&mut buf8) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let offset_ns = u64::from_le_bytes(buf8);

        let mut dir_byte = [0u8; 1];
        r.read_exact(&mut dir_byte)?;
        let direction = Direction::from_u8(dir_byte[0])
            .ok_or_else(|| anyhow::anyhow!("invalid direction byte: {}", dir_byte[0]))?;

        let mut buf4 = [0u8; 4];
        r.read_exact(&mut buf4)?;
        let len = u32::from_le_bytes(buf4) as usize;

        let mut data = vec![0u8; len];
        r.read_exact(&mut data)?;

        Ok(Some(Self {
            offset_ns,
            direction,
            data,
        }))
    }
}

/// Writer that appends records to a recording file.
pub struct RecordingWriter<W: Write> {
    inner: W,
}

impl<W: Write> RecordingWriter<W> {
    /// Create a new recording writer, writing the header.
    pub fn new(mut inner: W, epoch_ns: u64) -> Result<Self> {
        let header = Header::new(epoch_ns);
        header.write_to(&mut inner)?;
        Ok(Self { inner })
    }

    /// Write a record.
    pub fn write_record(&mut self, record: &Record) -> Result<()> {
        record.write_to(&mut self.inner)
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> Result<()> {
        self.inner.flush()?;
        Ok(())
    }
}

/// Reader that iterates over records in a recording file.
pub struct RecordingReader<R: Read> {
    inner: R,
    header: Header,
}

impl<R: Read> RecordingReader<R> {
    /// Open a recording, reading and validating the header.
    pub fn new(mut inner: R) -> Result<Self> {
        let header = Header::read_from(&mut inner)?;
        Ok(Self { inner, header })
    }

    /// Get the file header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Read the next record, or None on EOF.
    pub fn next_record(&mut self) -> Result<Option<Record>> {
        Record::read_from(&mut self.inner)
    }

    /// Read all remaining records.
    pub fn read_all(&mut self) -> Result<Vec<Record>> {
        let mut records = Vec::new();
        while let Some(record) = self.next_record()? {
            records.push(record);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn header_roundtrip() {
        let header = Header::new(1_700_000_000_000_000_000);
        let mut buf = Vec::new();
        header.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), 24);

        let parsed = Header::read_from(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(header, parsed);
    }

    #[test]
    fn bad_magic() {
        let buf = b"NOTVALID0000000000000000";
        let err = Header::read_from(&mut Cursor::new(buf.as_slice())).unwrap_err();
        assert!(
            format!("{err}").contains("not a nix-wire recording"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn record_roundtrip() {
        let record = Record {
            offset_ns: 42_000_000,
            direction: Direction::ClientToDaemon,
            data: vec![0x63, 0x78, 0x69, 0x6e, 0, 0, 0, 0],
        };
        let mut buf = Vec::new();
        record.write_to(&mut buf).unwrap();
        // 8 (offset) + 1 (dir) + 4 (len) + 8 (data) = 21
        assert_eq!(buf.len(), 21);

        let parsed = Record::read_from(&mut Cursor::new(&buf)).unwrap().unwrap();
        assert_eq!(record, parsed);
    }

    #[test]
    fn eof_returns_none() {
        let buf: &[u8] = &[];
        let result = Record::read_from(&mut Cursor::new(buf)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn full_session_roundtrip() {
        let epoch_ns = 1_700_000_000_000_000_000;
        let records = vec![
            Record {
                offset_ns: 0,
                direction: Direction::ClientToDaemon,
                data: vec![1, 2, 3, 4],
            },
            Record {
                offset_ns: 1_000_000,
                direction: Direction::DaemonToClient,
                data: vec![5, 6, 7, 8, 9],
            },
            Record {
                offset_ns: 2_000_000,
                direction: Direction::ClientToDaemon,
                data: vec![10],
            },
        ];

        // Write
        let mut buf = Vec::new();
        let mut writer = RecordingWriter::new(&mut buf, epoch_ns).unwrap();
        for r in &records {
            writer.write_record(r).unwrap();
        }

        // Read
        let mut reader = RecordingReader::new(Cursor::new(&buf)).unwrap();
        assert_eq!(reader.header().epoch_ns, epoch_ns);
        let parsed = reader.read_all().unwrap();
        assert_eq!(records, parsed);
    }

    #[test]
    fn direction_display() {
        assert_eq!(Direction::ClientToDaemon.to_string(), "C->D");
        assert_eq!(Direction::DaemonToClient.to_string(), "D->C");
    }
}
