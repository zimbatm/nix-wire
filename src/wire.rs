//! Low-level Nix wire protocol primitives.
//!
//! All integers are u64 little-endian on the wire.
//! Strings are length-prefixed and padded to 8-byte alignment:
//! `[u64 length][bytes][zero-padding to 8-byte boundary]`.

use std::io::{Read, Write};

use anyhow::{bail, Context, Result};

/// Read a u64 in little-endian from the stream.
pub fn read_u64(r: &mut impl Read) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)
        .context("failed to read u64 from wire")?;
    Ok(u64::from_le_bytes(buf))
}

/// Write a u64 in little-endian to the stream.
pub fn write_u64(w: &mut impl Write, val: u64) -> Result<()> {
    w.write_all(&val.to_le_bytes())
        .context("failed to write u64 to wire")?;
    Ok(())
}

/// Read a u32 in little-endian from the stream.
pub fn read_u32(r: &mut impl Read) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)
        .context("failed to read u32 from wire")?;
    Ok(u32::from_le_bytes(buf))
}

/// Write a u32 in little-endian to the stream.
pub fn write_u32(w: &mut impl Write, val: u32) -> Result<()> {
    w.write_all(&val.to_le_bytes())
        .context("failed to write u32 to wire")?;
    Ok(())
}

/// Read a length-prefixed string from the wire protocol.
///
/// Format: `[u64 length][bytes][zero-padding to 8-byte alignment]`.
pub fn read_string(r: &mut impl Read) -> Result<String> {
    let bytes = read_bytes(r)?;
    String::from_utf8(bytes).context("wire string is not valid UTF-8")
}

/// Read length-prefixed bytes from the wire protocol.
///
/// After reading the data, reads and discards zero-padding to 8-byte alignment.
pub fn read_bytes(r: &mut impl Read) -> Result<Vec<u8>> {
    let len = read_u64(r)?;
    if len > 64 * 1024 * 1024 {
        bail!("wire string too long: {} bytes", len);
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)
        .context("failed to read wire string data")?;
    let padding = (8 - (len % 8)) % 8;
    if padding > 0 {
        let mut pad = [0u8; 8];
        r.read_exact(&mut pad[..padding as usize])
            .context("failed to read wire string padding")?;
    }
    Ok(buf)
}

/// Write a length-prefixed string to the wire protocol.
pub fn write_string(w: &mut impl Write, s: &str) -> Result<()> {
    write_bytes(w, s.as_bytes())
}

/// Write length-prefixed bytes to the wire protocol.
///
/// After writing the data, writes zero-padding to 8-byte alignment.
pub fn write_bytes(w: &mut impl Write, data: &[u8]) -> Result<()> {
    let len = data.len() as u64;
    write_u64(w, len)?;
    w.write_all(data)
        .context("failed to write wire string data")?;
    let padding = (8 - (len % 8)) % 8;
    if padding > 0 {
        let pad = [0u8; 8];
        w.write_all(&pad[..padding as usize])
            .context("failed to write wire string padding")?;
    }
    Ok(())
}

/// Read a StringSet (set of strings) from the wire protocol.
///
/// Format: `[u64 count][string1][string2]...`
pub fn read_string_set(r: &mut impl Read) -> Result<Vec<String>> {
    let count = read_u64(r)?;
    let mut result = Vec::with_capacity(count as usize);
    for _ in 0..count {
        result.push(read_string(r)?);
    }
    Ok(result)
}

/// Try to extract a store path from a byte slice.
/// Looks for `/nix/store/` prefix followed by a 32-char hash and name.
pub fn extract_store_path(data: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(data).ok()?;
    if s.starts_with("/nix/store/") && s.len() >= 44 {
        Some(s)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_u64() {
        let mut buf = Vec::new();
        write_u64(&mut buf, 0x6e697863).unwrap();
        assert_eq!(buf, [0x63, 0x78, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00]);
        let val = read_u64(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(val, 0x6e697863);
    }

    #[test]
    fn roundtrip_string() {
        let mut buf = Vec::new();
        write_string(&mut buf, "hello").unwrap();
        // length(8) + "hello"(5) + padding(3) = 16
        assert_eq!(buf.len(), 8 + 5 + 3);
        let s = read_string(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn roundtrip_string_aligned() {
        let mut buf = Vec::new();
        write_string(&mut buf, "helloooo").unwrap();
        // length(8) + "helloooo"(8) + padding(0) = 16
        assert_eq!(buf.len(), 8 + 8);
        let s = read_string(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(s, "helloooo");
    }

    #[test]
    fn roundtrip_empty_string() {
        let mut buf = Vec::new();
        write_string(&mut buf, "").unwrap();
        // length(8) + padding(0) = 8
        assert_eq!(buf.len(), 8);
        let s = read_string(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn roundtrip_string_set() {
        let mut buf = Vec::new();
        write_u64(&mut buf, 2).unwrap(); // count
        write_string(&mut buf, "foo").unwrap();
        write_string(&mut buf, "bar").unwrap();
        // count(8) + len(8)+"foo"(3)+pad(5) + len(8)+"bar"(3)+pad(5) = 40
        assert_eq!(buf.len(), 8 + 16 + 16);
        let set = read_string_set(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(set, vec!["foo", "bar"]);
    }

    #[test]
    fn extract_store_path_valid() {
        let path = "/nix/store/aaaabbbbccccddddeeeeffffgggghhhh-foo";
        assert_eq!(extract_store_path(path.as_bytes()), Some(path));
    }

    #[test]
    fn extract_store_path_invalid() {
        assert_eq!(extract_store_path(b"not a store path"), None);
    }
}
