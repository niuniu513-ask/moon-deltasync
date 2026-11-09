///|
/// Byte level helpers shared by every format in this library.
///
/// The formats documented in `docs/design.md` are written with big endian fixed
/// width integers. That decision lives here and nowhere else. Every reader is
/// bounds checked and reports `None` instead of raising, because the bytes being
/// read usually come from a peer and must never be trusted.
let hex_digits : Array[Char] = [
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
]

///|
/// A growable byte sink that the format writers append to.
///
/// `ByteSink` exists instead of `Bytes` because `Bytes` is immutable and the
/// writers do not know the final size in advance. It keeps the
/// "append then freeze" pattern in one place.
pub struct ByteSink {
  bytes : Array[Byte]
}

///|
pub fn ByteSink::new() -> ByteSink {
  { bytes: [], }
}

///|
pub fn ByteSink::length(self : ByteSink) -> Int32 {
  self.bytes.length()
}

///|
/// Append one byte, keeping the low eight bits of `value`.
pub fn ByteSink::write_u8(self : ByteSink, value : Int32) -> Unit {
  self.bytes.push((value & 0xFF).to_byte())
}

///|
/// Append four bytes, most significant first.
pub fn ByteSink::write_u32(self : ByteSink, value : UInt32) -> Unit {
  for shift in [24, 16, 8, 0] {
    self.write_u8((value >> shift).reinterpret_as_int() & 0xFF)
  }
}

///|
/// Append eight bytes, most significant first.
pub fn ByteSink::write_u64(self : ByteSink, value : UInt64) -> Unit {
  for shift in [56, 48, 40, 32, 24, 16, 8, 0] {
    self.write_u8(((value >> shift) & 0xFFUL).to_int())
  }
}

///|
/// Append every byte of `view`.
pub fn ByteSink::write_bytes(self : ByteSink, view : BytesView) -> Unit {
  for i = 0; i < view.length(); i = i + 1 {
    self.bytes.push(view[i])
  }
}

///|
/// An unsigned LEB128 variable length integer. Used by the manifest so that a
/// chunk length below 128 bytes costs one byte rather than four.
pub fn ByteSink::write_varint(self : ByteSink, value : UInt64) -> Unit {
  let mut rest = value
  let mut more = true
  while more {
    let low = (rest & 0x7FUL).to_int() & 0x7F
    rest = rest >> 7
    if rest == 0UL {
      self.write_u8(low)
      more = false
    } else {
      self.write_u8(low | 0x80)
    }
  }
}

///|
/// Freeze the sink into immutable bytes.
pub fn ByteSink::to_bytes(self : ByteSink) -> Bytes {
  Bytes::from_array(self.bytes[:])
}

///|
/// The four big endian bytes of a `u32`.
pub fn be_u32(value : UInt32) -> Bytes {
  let sink = ByteSink::new()
  sink.write_u32(value)
  sink.to_bytes()
}

///|
/// The eight big endian bytes of a `u64`.
pub fn be_u64(value : UInt64) -> Bytes {
  let sink = ByteSink::new()
  sink.write_u64(value)
  sink.to_bytes()
}

///|
/// Read one unsigned byte at `offset`, or `None` when it is outside the view.
pub fn read_u8(view : BytesView, offset : Int32) -> Int32? {
  if offset < 0 || offset >= view.length() {
    return None
  }
  Some(view[offset].to_int())
}

///|
/// Read four big endian bytes at `offset`, or `None` when they do not fit.
pub fn read_u32(view : BytesView, offset : Int32) -> UInt32? {
  if offset < 0 || offset + 4 > view.length() {
    return None
  }
  let mut value : UInt32 = 0U
  for i = 0; i < 4; i = i + 1 {
    value = (value << 8) | view[offset + i].to_uint()
  }
  Some(value)
}

///|
/// Read eight big endian bytes at `offset`, or `None` when they do not fit.
pub fn read_u64(view : BytesView, offset : Int32) -> UInt64? {
  if offset < 0 || offset + 8 > view.length() {
    return None
  }
  let mut value : UInt64 = 0UL
  for i = 0; i < 8; i = i + 1 {
    value = (value << 8) | view[offset + i].to_uint64()
  }
  Some(value)
}

///|
/// Read an unsigned LEB128 integer at `offset`, returning the value and the
/// offset just after it. At most ten bytes are accepted; a longer encoding is a
/// malformed input, not a number.
pub fn read_varint(view : BytesView, offset : Int32) -> (UInt64, Int32)? {
  let mut value : UInt64 = 0UL
  let mut shift = 0
  let mut cursor = offset
  while shift <= 63 {
    match read_u8(view, cursor) {
      None => return None
      Some(byte) => {
        value = value | ((byte & 0x7F).to_uint64() << shift)
        cursor = cursor + 1
        if (byte & 0x80) == 0 {
          return Some((value, cursor))
        }
        shift = shift + 7
      }
    }
  }
  None
}

///|
/// A bounds checked sub view, or `None` when the range is not fully inside.
pub fn sub_view(view : BytesView, offset : Int32, length : Int32) -> BytesView? {
  if offset < 0 || length < 0 || offset + length > view.length() {
    return None
  }
  Some(view.clamped_view(start=offset, end=offset + length))
}

///|
/// Lower case hexadecimal text for `view`, two characters per byte.
pub fn hex_encode(view : BytesView) -> String {
  let builder = StringBuilder(size_hint=view.length() * 2)
  for i = 0; i < view.length(); i = i + 1 {
    let byte = view[i].to_int() & 0xFF
    builder.write_char(hex_digits[byte / 16])
    builder.write_char(hex_digits[byte % 16])
  }
  builder.to_string()
}

///|
/// Parse lower or upper case hexadecimal text. An odd length, or a character
/// that is not a hexadecimal digit, is a malformed input rather than a best
/// effort: silently dropping a nibble would make checksums meaningless.
pub fn hex_decode(text : String) -> Bytes? {
  if text.length() % 2 != 0 {
    return None
  }
  let sink = ByteSink::new()
  let mut high : Int32? = None
  for ch in text {
    match hex_digit(ch) {
      None => return None
      Some(nibble) =>
        match high {
          None => high = Some(nibble)
          Some(top) => {
            sink.write_u8(top * 16 + nibble)
            high = None
          }
        }
    }
  }
  if high is Some(_) {
    return None
  }
  Some(sink.to_bytes())
}

///|
fn hex_digit(ch : Char) -> Int32? {
  if ch >= '0' && ch <= '9' {
    Some(ch.to_int() - '0'.to_int())
  } else if ch >= 'a' && ch <= 'f' {
    Some(ch.to_int() - 'a'.to_int() + 10)
  } else if ch >= 'A' && ch <= 'F' {
    Some(ch.to_int() - 'A'.to_int() + 10)
  } else {
    None
  }
}

///|
/// Byte wise equality that does not stop at the first difference.
///
/// Used when comparing strong checksums: a mismatch should not tell a peer
/// where in the digest the difference starts.
pub fn constant_time_equal(left : BytesView, right : BytesView) -> Bool {
  if left.length() != right.length() {
    return false
  }
  let mut diff = 0
  for i = 0; i < left.length(); i = i + 1 {
    diff = diff | (left[i].to_int() ^ right[i].to_int())
  }
  diff == 0
}

///|
/// The number of blocks of `block_size` bytes needed to hold `total` bytes,
/// rounded up. A total length of zero needs zero blocks.
pub fn block_count(total : Int32, block_size : Int32) -> Int32 {
  if block_size <= 0 || total <= 0 {
    return 0
  }
  (total + block_size - 1) / block_size
}
