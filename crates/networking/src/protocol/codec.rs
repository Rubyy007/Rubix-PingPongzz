//! Length-prefixed frame codec for encrypted messages.
//!
//! # Protocol
//! ```
//! [4 bytes: length (u32 big-endian)] [N bytes: encrypted payload]
//! ```
//!
//! # Security
//! - Max frame size: 64KB + 64 bytes overhead (prevents DoS).
//! - Length is validated before allocating buffer.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, trace, warn};

use crate::error::{NetworkError, NetworkResult};

/// Maximum allowed frame size (64KB plaintext + Noise overhead).
const MAX_FRAME_SIZE: usize = 65536 + 64;

/// Frame codec for length-prefixed encrypted messages.
#[derive(Clone, Debug)]
pub struct EncryptedFrameCodec;

impl EncryptedFrameCodec {
    /// Create a new codec.
    pub fn new() -> Self {
        Self
    }

    /// Encode encrypted data into a length-prefixed frame.
    ///
    /// # Panics
    /// - If `data` exceeds `MAX_FRAME_SIZE` (indicates a bug in upper layers).
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        assert!(
            data.len() <= MAX_FRAME_SIZE,
            "frame size {} exceeds max {}",
            data.len(),
            MAX_FRAME_SIZE
        );

        let mut frame = Vec::with_capacity(4 + data.len());
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    /// Decode a frame from an async stream.
    ///
    /// # Errors
    /// - `NetworkError::FrameTooLarge` if length exceeds max.
    /// - `NetworkError::RecvFailed` on read errors.
    /// - `NetworkError::ConnectionClosed` if stream ends.
    pub async fn decode<S>(&self, stream: &mut S) -> NetworkResult<Vec<u8>>
    where
        S: AsyncReadExt + Unpin,
    {
        // Read 4-byte length prefix
        let mut len_bytes = [0u8; 4];
        stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    NetworkError::ConnectionClosed
                } else {
                    NetworkError::RecvFailed(format!("read length: {}", e))
                }
            })?;

        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > MAX_FRAME_SIZE {
            warn!("frame size {} exceeds max {}, dropping connection", len, MAX_FRAME_SIZE);
            return Err(NetworkError::FrameTooLarge { size: len, max: MAX_FRAME_SIZE });
        }

        trace!("reading frame of {} bytes", len);

        // Read payload
        let mut payload = vec![0u8; len];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    NetworkError::ConnectionClosed
                } else {
                    NetworkError::RecvFailed(format!("read payload: {}", e))
                }
            })?;

        Ok(payload)
    }
}

impl Default for EncryptedFrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn encode_decode_roundtrip() {
        let codec = EncryptedFrameCodec::new();
        let data = b"hello encrypted world";
        let frame = codec.encode(data);

        let mut stream = Cursor::new(frame);
        let decoded = codec.decode(&mut stream).await.unwrap();
        assert_eq!(decoded, data.as_slice());
    }

    #[tokio::test]
    async fn empty_frame() {
        let codec = EncryptedFrameCodec::new();
        let frame = codec.encode(b"");

        let mut stream = Cursor::new(frame);
        let decoded = codec.decode(&mut stream).await.unwrap();
        assert!(decoded.is_empty());
    }

    #[tokio::test]
    async fn large_frame_rejected() {
        let codec = EncryptedFrameCodec::new();
        let oversized = vec![0u8; MAX_FRAME_SIZE + 1];

        // encode should panic in debug, but we test decode
        let mut frame = (oversized.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&oversized);

        let mut stream = Cursor::new(frame);
        let result = codec.decode(&mut stream).await;
        assert!(matches!(result, Err(NetworkError::FrameTooLarge { .. })));
    }

    #[tokio::test]
    async fn truncated_frame() {
        let codec = EncryptedFrameCodec::new();
        let mut frame = (100u32).to_be_bytes().to_vec();
        frame.extend_from_slice(b"short");

        let mut stream = Cursor::new(frame);
        let result = codec.decode(&mut stream).await;
        assert!(matches!(result, Err(NetworkError::ConnectionClosed)));
    }
}