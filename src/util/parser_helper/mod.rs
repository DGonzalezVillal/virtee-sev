// SPDX-License-Identifier: Apache-2.0

//! Read/write helpers for [`Decoder`](crate::parser::Decoder) and
//! [`Encoder`](crate::parser::Encoder) implementations.
//!
//! Internal building blocks used by wire types under [`crate::types`] and
//! attestation evidence parsers. They extend [`Read`] / [`Write`] with
//! chained decode, encode, padding, and reserved-field checks so `Decoder` /
//! `Encoder` impls stay focused on field order rather than boilerplate.
//!
//! # Submodules
//!
//! | Module | API | Purpose |
//! |--------|-----|---------|
//! | [`read_ext`](self::read_ext) | [`ReadExt`] | Decode next field from a stream |
//! | [`write_ext`](self::write_ext) | [`WriteExt`] | Encode a field or write zero padding |
//! | [`reserved`](self::reserved) | [`validate_reserved`] | Assert reserved bytes are zero |
//!
//! # Typical decode pattern
//!
//! ```ignore
//! impl Decoder<Generation> for MyType {
//!     fn decode(reader: &mut impl Read, gen: Generation) -> Result<Self, io::Error> {
//!         Ok(Self {
//!             field_a: reader.read_bytes()?,
//!             _reserved: reader.skip_bytes::<4>()?,
//!             field_b: reader.read_bytes_with(gen)?,
//!         })
//!     }
//! }
//! ```
//!
//! # Typical encode pattern
//!
//! ```ignore
//! impl Encoder<()> for MyType {
//!     fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), io::Error> {
//!         writer.write_bytes(self.field_a, ())?;
//!         writer.skip_bytes::<4>()?;
//!         writer.write_bytes(self.field_b, ())?;
//!         Ok(())
//!     }
//! }
//! ```

mod read_ext;

mod write_ext;

mod reserved;

pub(crate) use read_ext::ReadExt;

pub(crate) use write_ext::WriteExt;

pub(crate) use reserved::validate_reserved;
