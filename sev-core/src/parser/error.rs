// SPDX-License-Identifier: Apache-2.0

/// Failure while encoding or decoding bytes.
///
/// A short buffer, a wrong length, and a non-zero reserved region are their own
/// variants.
/// Reading a file or an ioctl buffer reports [`std::io::Error`] at that call,
/// before a [`crate::parser::Cursor`] is built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// A read asked for `needed` bytes and the buffer ended first.
    #[error("unexpected end of input while reading {needed} bytes")]
    UnexpectedEof {
        /// Number of bytes this read requested.
        needed: usize,
    },
    /// `from_bytes` or `from_bytes_with` received a buffer of the wrong length.
    #[error("expected {expected} bytes, got {actual}")]
    LengthMismatch {
        /// Length required by [`crate::parser::Decoder::LEN`].
        expected: usize,
        /// Length of the buffer that was passed in.
        actual: usize,
    },
    /// Encoding produced a byte buffer of the wrong length.
    #[error("encoded length {actual} does not match expected {expected}")]
    EncodeLength {
        /// Length required by [`crate::parser::Decoder::LEN`].
        expected: usize,
        /// Length of the encoded buffer.
        actual: usize,
    },
    /// A reserved region contained a non-zero byte.
    ///
    /// `at` is the cursor position of the first byte of the region. The cursor
    /// is left on that byte.
    #[error("non-zero reserved bytes at offset {at}, length {len}")]
    NonZeroReserved {
        /// Cursor position where the reserved region starts.
        at: usize,
        /// Length of the reserved region.
        len: usize,
    },
}
