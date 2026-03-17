//! Async equivalents of wire protocol primitives.
//!
//! Wraps `tokio::io::AsyncBufRead` for reading Nix wire protocol data.
//! Unlike the sync `StreamAccum` in the old decoder, each method simply
//! awaits until data arrives or returns an error -- no `try_*` / `Option`
//! pattern needed.

use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, ReadBuf};

/// Maximum wire string/chunk length before we consider the stream desynchronized.
const MAX_WIRE_STRING_LEN: u64 = 256 * 1024 * 1024; // 256 MiB

/// Async reader for Nix wire protocol primitives.
///
/// Wraps an `AsyncBufRead` to provide peek support (needed for the stderr
/// loop which peeks without consuming to detect non-stderr-code values).
pub struct AsyncWireReader<R> {
    inner: R,
}

impl<R: AsyncBufRead + Unpin> AsyncWireReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Access the inner reader.
    pub fn inner_ref(&self) -> &R {
        &self.inner
    }

    /// Read a u64 in little-endian from the stream.
    pub async fn read_u64(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.inner
            .read_exact(&mut buf)
            .await
            .context("failed to read u64 from wire")?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Read a u32 in little-endian from the stream.
    pub async fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.inner
            .read_exact(&mut buf)
            .await
            .context("failed to read u32 from wire")?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Peek at the next u64 without consuming it.
    ///
    /// Returns `Ok(Some(val))` if 8 bytes are available, `Ok(None)` if EOF
    /// is reached before 8 bytes are available (i.e. the stream ended).
    pub async fn peek_u64(&mut self) -> Result<Option<u64>> {
        // Fill the buffer until we have at least 8 bytes or hit EOF
        loop {
            let buf = self.inner.fill_buf().await.context("failed to peek u64")?;
            if buf.len() >= 8 {
                let val = u64::from_le_bytes(buf[..8].try_into().unwrap());
                return Ok(Some(val));
            }
            if buf.is_empty() {
                return Ok(None); // EOF
            }
            // Not enough data yet and not EOF -- the BufReader should have more
            // data coming. For in-memory readers (like &[u8]), fill_buf returns
            // all remaining data at once, so if we have <8 bytes and it's not
            // empty, we're at a partial EOF.
            if buf.len() < 8 {
                return Ok(None); // partial data at end of stream
            }
        }
    }

    /// Consume exactly `n` bytes from the internal buffer, discarding them.
    ///
    /// The caller must ensure that `n` bytes have already been peeked /
    /// are available in the buffer.
    pub fn consume(&mut self, n: usize) {
        self.inner.consume(n);
    }

    /// Read length-prefixed, 8-byte-padded bytes from the wire protocol.
    ///
    /// Format: `[u64 length][bytes][zero-padding to 8-byte boundary]`.
    pub async fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u64().await?;
        if len > MAX_WIRE_STRING_LEN {
            bail!(
                "wire string too long: {} bytes ({:#x}), max {} MiB",
                len,
                len,
                MAX_WIRE_STRING_LEN / (1024 * 1024),
            );
        }
        let mut buf = vec![0u8; len as usize];
        self.inner
            .read_exact(&mut buf)
            .await
            .context("failed to read wire bytes data")?;
        let padding = (8 - (len % 8)) % 8;
        if padding > 0 {
            let mut pad = [0u8; 8];
            self.inner
                .read_exact(&mut pad[..padding as usize])
                .await
                .context("failed to read wire bytes padding")?;
        }
        Ok(buf)
    }

    /// Read a length-prefixed string from the wire protocol.
    pub async fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_bytes().await?;
        String::from_utf8(bytes).context("wire string is not valid UTF-8")
    }

    /// Skip a length-prefixed string (no UTF-8 validation).
    pub async fn skip_string(&mut self) -> Result<()> {
        let _bytes = self.read_bytes().await?;
        Ok(())
    }

    /// Read a StringSet: `[u64 count][string1][string2]...`
    pub async fn read_string_set(&mut self) -> Result<Vec<String>> {
        let count = self.read_u64().await?;
        let mut result = Vec::with_capacity(count as usize);
        for _ in 0..count {
            result.push(self.read_string().await?);
        }
        Ok(result)
    }

    /// Skip a StringSet, returning the count.
    pub async fn skip_string_set(&mut self) -> Result<u64> {
        let count = self.read_u64().await?;
        for _ in 0..count {
            self.skip_string().await?;
        }
        Ok(count)
    }

    /// Skip framed data: `[u64 length][bytes]` chunks until a zero-length terminator.
    ///
    /// Returns the total number of payload bytes skipped.
    /// Uses a small stack buffer to avoid allocating for NAR data.
    pub async fn skip_framed(&mut self) -> Result<u64> {
        let mut total = 0u64;
        let mut discard_buf = [0u8; 8192];
        loop {
            let chunk_len = self.read_u64().await?;
            if chunk_len == 0 {
                return Ok(total);
            }
            if chunk_len > MAX_WIRE_STRING_LEN {
                bail!(
                    "framed chunk too long: {} bytes ({:#x}), max {} MiB",
                    chunk_len,
                    chunk_len,
                    MAX_WIRE_STRING_LEN / (1024 * 1024),
                );
            }
            // Discard chunk data using small stack buffer
            let mut remaining = chunk_len as usize;
            while remaining > 0 {
                let to_read = remaining.min(discard_buf.len());
                self.inner
                    .read_exact(&mut discard_buf[..to_read])
                    .await
                    .context("failed to read framed chunk data")?;
                remaining -= to_read;
            }
            total += chunk_len;
        }
    }
}

/// In-memory reader with position tracking.
///
/// Implements both `AsyncRead` and `AsyncBufRead` directly, so it can be
/// used with `AsyncWireReader` without an intermediate `BufReader`.
/// This gives exact position tracking at the protocol level.
pub struct MemReader {
    data: Vec<u8>,
    pos: usize,
}

impl MemReader {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    /// Current byte position in the stream.
    pub fn position(&self) -> usize {
        self.pos
    }
}

impl AsyncRead for MemReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let remaining = &this.data[this.pos..];
        let n = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncBufRead for MemReader {
    fn poll_fill_buf(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        let this = self.get_mut();
        Poll::Ready(Ok(&this.data[this.pos..]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.get_mut().pos += amt;
    }
}

/// Wraps an `AsyncRead` and counts the number of bytes read through it.
pub struct CountingReader<R> {
    inner: R,
    count: u64,
}

impl<R> CountingReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, count: 0 }
    }

    /// Total bytes read so far.
    pub fn count(&self) -> u64 {
        self.count
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let after = buf.filled().len();
        this.count += (after - before) as u64;
        result
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    fn make_reader(data: &[u8]) -> AsyncWireReader<BufReader<&[u8]>> {
        AsyncWireReader::new(BufReader::new(data))
    }

    #[tokio::test]
    async fn read_u64_basic() {
        let data = 0x6e697863u64.to_le_bytes();
        let mut r = make_reader(&data);
        assert_eq!(r.read_u64().await.unwrap(), 0x6e697863);
    }

    #[tokio::test]
    async fn read_u32_basic() {
        let data = 42u32.to_le_bytes();
        let mut r = make_reader(&data);
        assert_eq!(r.read_u32().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn peek_u64_basic() {
        let data = 0xdeadbeefu64.to_le_bytes();
        let mut r = make_reader(&data);
        // Peek should not consume
        assert_eq!(r.peek_u64().await.unwrap(), Some(0xdeadbeef));
        assert_eq!(r.peek_u64().await.unwrap(), Some(0xdeadbeef));
        // Now consume
        assert_eq!(r.read_u64().await.unwrap(), 0xdeadbeef);
        // EOF
        assert_eq!(r.peek_u64().await.unwrap(), None);
    }

    #[tokio::test]
    async fn read_bytes_with_padding() {
        // "hello" (5 bytes) -> len=5, data="hello", padding=3 zeros
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u64.to_le_bytes());
        buf.extend_from_slice(b"hello");
        buf.extend_from_slice(&[0, 0, 0]); // padding to 8-byte boundary
        let mut r = make_reader(&buf);
        assert_eq!(r.read_bytes().await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn read_bytes_aligned() {
        // "helloooo" (8 bytes) -> no padding needed
        let mut buf = Vec::new();
        buf.extend_from_slice(&8u64.to_le_bytes());
        buf.extend_from_slice(b"helloooo");
        let mut r = make_reader(&buf);
        assert_eq!(r.read_bytes().await.unwrap(), b"helloooo");
    }

    #[tokio::test]
    async fn read_bytes_empty() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u64.to_le_bytes());
        let mut r = make_reader(&buf);
        assert_eq!(r.read_bytes().await.unwrap(), b"");
    }

    #[tokio::test]
    async fn read_string_basic() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u64.to_le_bytes());
        buf.extend_from_slice(b"hello");
        buf.extend_from_slice(&[0, 0, 0]);
        let mut r = make_reader(&buf);
        assert_eq!(r.read_string().await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn read_string_set_basic() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u64.to_le_bytes()); // count
        buf.extend_from_slice(&3u64.to_le_bytes()); // "foo"
        buf.extend_from_slice(b"foo");
        buf.extend_from_slice(&[0, 0, 0, 0, 0]); // padding
        buf.extend_from_slice(&3u64.to_le_bytes()); // "bar"
        buf.extend_from_slice(b"bar");
        buf.extend_from_slice(&[0, 0, 0, 0, 0]); // padding
        let mut r = make_reader(&buf);
        assert_eq!(r.read_string_set().await.unwrap(), vec!["foo", "bar"]);
    }

    #[tokio::test]
    async fn skip_string_set_basic() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.extend_from_slice(&3u64.to_le_bytes());
        buf.extend_from_slice(b"foo");
        buf.extend_from_slice(&[0, 0, 0, 0, 0]);
        buf.extend_from_slice(&3u64.to_le_bytes());
        buf.extend_from_slice(b"bar");
        buf.extend_from_slice(&[0, 0, 0, 0, 0]);
        let mut r = make_reader(&buf);
        assert_eq!(r.skip_string_set().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn skip_framed_basic() {
        let mut buf = Vec::new();
        // chunk 1: 4 bytes
        buf.extend_from_slice(&4u64.to_le_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);
        // chunk 2: 8 bytes
        buf.extend_from_slice(&8u64.to_le_bytes());
        buf.extend_from_slice(&[5, 6, 7, 8, 9, 10, 11, 12]);
        // terminator: 0 length
        buf.extend_from_slice(&0u64.to_le_bytes());
        let mut r = make_reader(&buf);
        assert_eq!(r.skip_framed().await.unwrap(), 12);
    }

    #[tokio::test]
    async fn skip_framed_empty() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u64.to_le_bytes());
        let mut r = make_reader(&buf);
        assert_eq!(r.skip_framed().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn read_bytes_rejects_too_long() {
        let mut buf = Vec::new();
        let huge_len = MAX_WIRE_STRING_LEN + 1;
        buf.extend_from_slice(&huge_len.to_le_bytes());
        let mut r = make_reader(&buf);
        assert!(r.read_bytes().await.is_err());
    }

    #[tokio::test]
    async fn mem_reader_position() {
        let data = vec![0u8; 24];
        let mut r = AsyncWireReader::new(MemReader::new(data));
        assert_eq!(r.inner_ref().position(), 0);
        r.read_u64().await.unwrap();
        assert_eq!(r.inner_ref().position(), 8);
        r.read_u64().await.unwrap();
        assert_eq!(r.inner_ref().position(), 16);
        r.read_u64().await.unwrap();
        assert_eq!(r.inner_ref().position(), 24);
    }

    #[tokio::test]
    async fn mem_reader_peek_no_advance() {
        let mut data = Vec::new();
        data.extend_from_slice(&42u64.to_le_bytes());
        data.extend_from_slice(&99u64.to_le_bytes());
        let mut r = AsyncWireReader::new(MemReader::new(data));
        assert_eq!(r.peek_u64().await.unwrap(), Some(42));
        assert_eq!(r.inner_ref().position(), 0); // peek doesn't advance
        r.consume(8);
        assert_eq!(r.inner_ref().position(), 8);
        assert_eq!(r.read_u64().await.unwrap(), 99);
        assert_eq!(r.inner_ref().position(), 16);
    }

    #[tokio::test]
    async fn counting_reader() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut cr = CountingReader::new(&data[..]);
        let mut buf = [0u8; 4];
        AsyncReadExt::read_exact(&mut cr, &mut buf).await.unwrap();
        assert_eq!(cr.count(), 4);
        AsyncReadExt::read_exact(&mut cr, &mut buf).await.unwrap();
        assert_eq!(cr.count(), 8);
    }
}
