///|
/// Where a signature comes from and what it promises.
///
/// A signature describes **the old data**, block by block. The side that sends
/// an update computes it from what the receiver already has; the delta encoder
/// only needs the signature. Every block carries a weak checksum (a candidate
/// filter) and a truncated strong checksum (the decision).
///
/// The limits below are contract, not tuning: they bound every later allocation
/// so that a malformed signature cannot ask the delta encoder for more memory
/// than it is willing to give.
let signature_magic : Bytes = @utf8.encode("DSIG")

///|
let delta_magic : Bytes = @utf8.encode("DDLT")

///|
let manifest_magic : Bytes = @utf8.encode("DCHK")

///|
let format_version : Int32 = 1

///|
let min_block_size : Int32 = 256

///|
let max_block_size : Int32 = 1 << 20

///|
let max_block_count : Int32 = 1_000_000

///|
let max_supported_total : UInt64 = 1UL << 40

///|
/// Everything that can be wrong with a serialized signature or delta.
pub suberror FormatError {
  BadMagic(String)
  UnsupportedVersion(Int32)
  Truncated(Int32)
  BadField(String)
  TooLarge(String)
  BlockMismatch(Int32)
  UnsupportedOp(Int32)
  DigestMismatch
}

///|
pub fn FormatError::message(self : FormatError) -> String {
  match self {
    BadMagic(found) => "bad magic: expected DSIG, found " + found
    UnsupportedVersion(version) =>
      "unsupported format version: " + version.to_string()
    Truncated(offset) => "truncated input at byte " + offset.to_string()
    BadField(field) => "invalid field: " + field
    TooLarge(field) => "value out of range: " + field
    BlockMismatch(index) =>
      "block " + index.to_string() + " does not match the signature"
    UnsupportedOp(tag) => "unsupported delta op tag: " + tag.to_string()
    DigestMismatch =>
      "the rebuilt bytes do not match the digest the delta carries"
  }
}

///|

///|
/// One block of the old data: its position, its weak checksum and the truncated
/// SHA-256 of its bytes.
pub struct BlockSignature {
  index : Int32
  weak : UInt32
  strong : Bytes
}

///|
/// The signature of a whole byte string.
pub struct FileSignature {
  block_size : Int32
  strong_len : Int32
  total_length : Int32
  blocks : Array[BlockSignature]
}

///|
/// The block size used when the caller does not choose one.
///
/// Small inputs get small blocks so a one byte edit on a small file still
/// produces a small delta; large inputs get bigger blocks so that the signature
/// and the delta op list stay proportional to `length / 8192` rather than to
/// `length`. The result is always a power of two inside
/// `[min_block_size, max_block_size]`, which keeps the format predictable.
pub fn default_block_size(length : Int32) -> Int32 {
  let target = if length < 4096 { 512 } else { 8192 }
  let mut size = min_block_size
  while size < target && size * 2 <= max_block_size {
    size = size * 2
  }
  size
}

///|
/// Sign `input` block by block. The last block may be shorter than `block_size`.
pub fn sign_bytes(
  input : BytesView,
  block_size? : Int32,
  strong_len? : Int32,
) -> FileSignature raise FormatError {
  let size = match block_size {
    Some(value) => value
    None => default_block_size(input.length())
  }
  if size < min_block_size || size > max_block_size {
    raise TooLarge(
      "block_size must be between \{min_block_size} and \{max_block_size}, got \{size}",
    )
  }
  let strong = match strong_len {
    Some(value) => value
    None => 16
  }
  if strong != 8 && strong != 16 {
    raise BadField("strong_len must be 8 or 16, got \{strong}")
  }
  let count = block_count(input.length(), size)
  if count > max_block_count {
    raise TooLarge("block count \{count} exceeds \{max_block_count}")
  }
  let blocks : Array[BlockSignature] = []
  for index = 0; index < count; index = index + 1 {
    let start = index * size
    let end = if start + size < input.length() {
      start + size
    } else {
      input.length()
    }
    let block = input.clamped_view(start~, end~)
    blocks.push({
      index,
      weak: weak_checksum(block),
      strong: sha256_prefix(block, strong),
    })
  }
  {
    block_size: size,
    strong_len: strong,
    total_length: input.length(),
    blocks,
  }
}

///|
pub fn FileSignature::block_count(self : FileSignature) -> Int32 {
  self.blocks.length()
}

///|
/// The length of the block at `index`, which is `block_size` for every block but
/// the last one. Returns `None` when the index is outside the signature.
pub fn FileSignature::block_length(
  self : FileSignature,
  index : Int32,
) -> Int32? {
  if index < 0 || index >= self.blocks.length() {
    return None
  }
  let start = index * self.block_size
  let rest = self.total_length - start
  Some(if rest < self.block_size { rest } else { self.block_size })
}

///|
/// The `DSIG` encoding of this signature.
pub fn FileSignature::encode(self : FileSignature) -> Bytes {
  let sink = ByteSink::new()
  sink.write_bytes(signature_magic[:])
  sink.write_u8(format_version)
  sink.write_u32(self.block_size.reinterpret_as_uint())
  sink.write_u8(self.strong_len)
  sink.write_u64(self.total_length.to_uint64())
  sink.write_u32(self.blocks.length().reinterpret_as_uint())
  for block in self.blocks {
    sink.write_u32(block.weak)
    sink.write_bytes(block.strong[:])
  }
  sink.to_bytes()
}

///|
/// Parse a `DSIG` byte string.
///
/// Everything a sender could get wrong is checked here: the magic, the version,
/// the strong length, and the arithmetic that ties `block_count` to
/// `total_length` and `block_size`. A signature that parses is a signature whose
/// block boundaries the delta encoder can trust.
pub fn decode_signature(bytes : BytesView) -> FileSignature raise FormatError {
  if bytes.length() < 4 {
    raise Truncated(0)
  }
  let magic = bytes.clamped_view(start=0, end=4)
  if !constant_time_equal(magic, signature_magic[:]) {
    raise BadMagic(ascii_preview(magic))
  }
  let mut cursor = 4
  let version = match read_u8(bytes, cursor) {
    Some(value) => value
    None => raise Truncated(cursor)
  }
  cursor = cursor + 1
  if version != format_version {
    raise UnsupportedVersion(version)
  }
  let block_size = match read_u32(bytes, cursor) {
    Some(value) => value
    None => raise Truncated(cursor)
  }
  cursor = cursor + 4
  let size = block_size.reinterpret_as_int()
  if size < min_block_size || size > max_block_size {
    raise TooLarge("block_size \{size} outside the supported range")
  }
  let strong_len = match read_u8(bytes, cursor) {
    Some(value) => value
    None => raise Truncated(cursor)
  }
  cursor = cursor + 1
  if strong_len != 8 && strong_len != 16 {
    raise BadField("strong_len must be 8 or 16, got \{strong_len}")
  }
  let total = match read_u64(bytes, cursor) {
    Some(value) => value
    None => raise Truncated(cursor)
  }
  cursor = cursor + 8
  if total > max_supported_total {
    raise TooLarge("total_length \{total} exceeds the supported range")
  }
  let total_length = total.to_int()
  let count = match read_u32(bytes, cursor) {
    Some(value) => value
    None => raise Truncated(cursor)
  }
  cursor = cursor + 4
  let expected = block_count(total_length, size)
  if count.reinterpret_as_int() != expected {
    raise BadField(
      "block_count \{count.reinterpret_as_int()} does not match \{expected} blocks of \{size} bytes",
    )
  }
  if expected > max_block_count {
    raise TooLarge("block count \{expected} exceeds \{max_block_count}")
  }
  let blocks : Array[BlockSignature] = []
  for index = 0; index < expected; index = index + 1 {
    let weak = match read_u32(bytes, cursor) {
      Some(value) => value
      None => raise Truncated(cursor)
    }
    cursor = cursor + 4
    let strong = match sub_view(bytes, cursor, strong_len) {
      Some(view) => view
      None => raise Truncated(cursor)
    }
    cursor = cursor + strong_len
    blocks.push({
      index,
      weak,
      strong: Bytes::from_array(strong.to_array()[:]),
    })
  }
  if cursor != bytes.length() {
    raise BadField(
      "signature has \{bytes.length() - cursor} trailing bytes after \{expected} blocks",
    )
  }
  { block_size: size, strong_len, total_length, blocks, }
}

///|
/// The SHA-256 of the `DSIG` encoding, which is what the reports quote so two
/// signatures can be compared without comparing every block.
pub fn FileSignature::digest_hex(self : FileSignature) -> String {
  sha256_hex(self.encode())
}

///|
/// Four bytes as text when they are printable ASCII, and as hexadecimal
/// otherwise. Only used to make a "bad magic" message readable.
fn ascii_preview(view : BytesView) -> String {
  let mut printable = true
  for i = 0; i < view.length(); i = i + 1 {
    let byte = view[i].to_int()
    if byte < 0x20 || byte > 0x7E {
      printable = false
    }
  }
  if printable {
    let builder = StringBuilder(size_hint=view.length())
    for i = 0; i < view.length(); i = i + 1 {
      builder.write_char(view[i].to_int().unsafe_to_char())
    }
    builder.to_string()
  } else {
    "0x" + hex_encode(view)
  }
}
