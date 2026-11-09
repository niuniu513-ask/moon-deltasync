///|
/// Turning "the peer's new data" into "the operations needed on what I have".
///
/// The encoder slides a window of `block_size` bytes over the new data and asks
/// the signature whether that window is a block it already holds. The weak
/// checksum answers "maybe" in constant time per byte; the truncated SHA-256
/// answers "yes" once per candidate. Everything that is not a match becomes a
/// literal.
///
/// The decoder never trusts the old data blindly: every copy operation carries
/// the strong checksum of the bytes it claims to copy, and `apply_delta`
/// recomputes it. A delta built against a different version of the old data
/// therefore fails loudly instead of producing a plausible looking wrong file.

///|
/// One operation of a delta.
pub enum DeltaOp {
  /// Copy the block at this index from the old data, which must match `strong`.
  Copy(Int32, Bytes)
  /// Copy `count` consecutive blocks starting at `start`, whose concatenation
  /// must match `strong` (the last block may be shorter than `block_size`).
  CopyRun(Int32, Int32, Bytes)
  /// Carry these bytes verbatim.
  Literal(Bytes)
}

///|
/// A sequence of operations that turns the old data into the new data.
pub struct Delta {
  block_size : Int32
  strong_len : Int32
  new_length : Int32
  /// SHA-256 of the bytes the delta must reproduce. It is what turns a damaged
  /// or truncated delta into an error instead of plausible looking output.
  content_digest : Bytes
  ops : Array[DeltaOp]
}

///|
/// The outcome of applying a delta: what was written and what was verified.
pub struct ApplyResult {
  bytes_written : Int32
  blocks_verified : Int32
  ops_applied : Int32
  digest_hex : String
  output : Bytes
}

///|
/// How many bytes the delta carries as copy operations rather than literals.
pub fn Delta::copied_bytes(self : Delta) -> Int32 {
  let mut total = 0
  for op in self.ops {
    match op {
      Copy(_, _) => total = total + self.block_size
      CopyRun(_, count, _) => total = total + count * self.block_size
      Literal(_) => ()
    }
  }
  total
}

///|
/// The number of copy operations (single or run) in this delta.
pub fn Delta::copy_ops(self : Delta) -> Int32 {
  let mut total = 0
  for op in self.ops {
    match op {
      Copy(_, _) => total = total + 1
      CopyRun(_, _, _) => total = total + 1
      Literal(_) => ()
    }
  }
  total
}

///|
/// The number of bytes carried as literals.
pub fn Delta::literal_bytes(self : Delta) -> Int32 {
  let mut total = 0
  for op in self.ops {
    match op {
      Literal(bytes) => total = total + bytes.length()
      _ => ()
    }
  }
  total
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

///|
/// Build the delta that turns the signed old data into `new_bytes`.
///
/// The result is normalised: consecutive copies are folded into one `CopyRun`,
/// consecutive literals into one `Literal`, and the bytes covered by the
/// operations equal `new_bytes.length()`.
pub fn compute_delta(
  new_bytes : BytesView,
  signature : FileSignature,
) -> Delta raise FormatError {
  if signature.strong_len != 8 && signature.strong_len != 16 {
    raise BadField("signature strong_len must be 8 or 16")
  }
  let block_size = signature.block_size
  let total = new_bytes.length()
  let strong_len = signature.strong_len
  // Only full length blocks can ever match a sliding window. The final short
  // block of the old data is handled separately at the tail.
  let buckets : Map[UInt32, Array[Int32]] = Map([])
  for block in signature.blocks {
    let remaining = signature.total_length - block.index * block_size
    if remaining >= block_size {
      let bucket = match buckets.get(block.weak) {
        Some(existing) => existing
        None => {
          let fresh : Array[Int32] = []
          buckets[block.weak] = fresh
          fresh
        }
      }
      if bucket.length() < 64 {
        bucket.push(block.index)
      }
    }
  }
  let raw_ops : Array[DeltaOp] = []
  let mut cursor = 0
  let mut literal_start = 0
  if block_size <= total {
    let roll = WeakRoll::new(new_bytes.clamped_view(start=0, end=block_size))
    while cursor + block_size <= total {
      if cursor > 0 && cursor > literal_start {
        roll.roll(new_bytes[cursor - 1], new_bytes[cursor + block_size - 1])
      }
      let mut matched = -1
      match buckets.get(roll.value()) {
        None => ()
        Some(candidates) => {
          let window = new_bytes.clamped_view(
            start=cursor,
            end=cursor + block_size,
          )
          let strong = sha256_prefix(window, strong_len)
          for index in candidates {
            if constant_time_equal(strong[:], signature.blocks[index].strong[:]) {
              matched = index
              break
            }
          }
        }
      }
      if matched >= 0 {
        if cursor > literal_start {
          raw_ops.push(
            Literal(
              Bytes::from_array(
                new_bytes
                .clamped_view(start=literal_start, end=cursor)
                .to_array()[:],
              ),
            ),
          )
        }
        raw_ops.push(Copy(matched, Bytes::new(0)))
        cursor = cursor + block_size
        literal_start = cursor
        if cursor + block_size <= total {
          roll.reset(
            new_bytes.clamped_view(start=cursor, end=cursor + block_size),
          )
        }
      } else {
        cursor = cursor + 1
      }
    }
  }
  // Tail: the final, shorter block of the old data can still be reused when the
  // remaining new bytes have exactly its length.
  let last_index = signature.blocks.length() - 1
  if last_index >= 0 {
    let last_length = signature.total_length - last_index * block_size
    if last_length > 0 && last_length < block_size {
      let remaining = total - literal_start
      if remaining == last_length {
        let tail = new_bytes.clamped_view(start=literal_start, end=total)
        let strong = sha256_prefix(tail, strong_len)
        if constant_time_equal(
            strong[:],
            signature.blocks[last_index].strong[:],
          ) {
          raw_ops.push(Copy(last_index, Bytes::new(0)))
          literal_start = total
        }
      }
    }
  }
  if literal_start < total {
    raw_ops.push(
      Literal(
        Bytes::from_array(
          new_bytes.clamped_view(start=literal_start, end=total).to_array()[:],
        ),
      ),
    )
  }
  let ops = normalise(new_bytes, raw_ops, block_size, strong_len)
  {
    block_size,
    strong_len,
    new_length: total,
    content_digest: sha256(new_bytes),
    ops,
  }
}

///|
/// Fold runs of consecutive copies and runs of adjacent literals, and give every
/// copy operation the strong checksum of the bytes it reproduces.
fn normalise(
  new_bytes : BytesView,
  raw_ops : Array[DeltaOp],
  block_size : Int32,
  strong_len : Int32,
) -> Array[DeltaOp] {
  let ops : Array[DeltaOp] = []
  let mut cursor = 0
  let mut index = 0
  while index < raw_ops.length() {
    match raw_ops[index] {
      Literal(bytes) => {
        let builder = ByteSink::new()
        builder.write_bytes(bytes[:])
        let mut next = index + 1
        let mut done = false
        while next < raw_ops.length() && !done {
          match raw_ops[next] {
            Literal(more) => {
              builder.write_bytes(more[:])
              next = next + 1
            }
            _ => done = true
          }
        }
        let merged = builder.to_bytes()
        cursor = cursor + merged.length()
        ops.push(Literal(merged))
        index = next
      }
      Copy(first, _) => {
        let mut count = 1
        let mut next = index + 1
        let mut done = false
        while next < raw_ops.length() && !done {
          match raw_ops[next] {
            Copy(candidate, _) =>
              if candidate == first + count {
                count = count + 1
                next = next + 1
              } else {
                done = true
              }
            _ => done = true
          }
        }
        let run_length = count * block_size
        let run_end = if cursor + run_length < new_bytes.length() {
          cursor + run_length
        } else {
          new_bytes.length()
        }
        let strong = sha256_prefix(
          new_bytes.clamped_view(start=cursor, end=run_end),
          strong_len,
        )
        cursor = run_end
        ops.push(CopyRun(first, count, strong))
        index = next
      }
      CopyRun(start, count, _) => {
        let run_length = count * block_size
        let run_end = if cursor + run_length < new_bytes.length() {
          cursor + run_length
        } else {
          new_bytes.length()
        }
        let strong = sha256_prefix(
          new_bytes.clamped_view(start=cursor, end=run_end),
          strong_len,
        )
        ops.push(CopyRun(start, count, strong))
        cursor = run_end
        index = index + 1
      }
    }
  }
  ops
}

///|
/// The `DDLT` encoding of this delta.
pub fn Delta::encode(self : Delta) -> Bytes {
  let sink = ByteSink::new()
  sink.write_bytes(delta_magic[:])
  sink.write_u8(format_version)
  sink.write_u32(self.block_size.reinterpret_as_uint())
  sink.write_u8(self.strong_len)
  sink.write_u64(self.new_length.to_uint64())
  sink.write_bytes(self.content_digest[:])
  sink.write_u32(self.ops.length().reinterpret_as_uint())
  for op in self.ops {
    match op {
      Copy(index, strong) => {
        sink.write_u8(0)
        sink.write_u32(index.reinterpret_as_uint())
        sink.write_bytes(strong[:])
      }
      Literal(bytes) => {
        sink.write_u8(1)
        sink.write_u32(bytes.length().reinterpret_as_uint())
        sink.write_bytes(bytes[:])
      }
      CopyRun(start, count, strong) => {
        sink.write_u8(2)
        sink.write_u32(start.reinterpret_as_uint())
        sink.write_u32(count.reinterpret_as_uint())
        sink.write_bytes(strong[:])
      }
    }
  }
  sink.to_bytes()
}

///|
/// The SHA-256 of the `DDLT` encoding.
pub fn Delta::digest_hex(self : Delta) -> String {
  sha256_hex(self.encode())
}

// ---------------------------------------------------------------------------
// Decoding and application
// ---------------------------------------------------------------------------

///|
/// Parse a `DDLT` byte string.
pub fn decode_delta(bytes : BytesView) -> Delta raise FormatError {
  if bytes.length() < 4 {
    raise Truncated(0)
  }
  let magic = bytes.clamped_view(start=0, end=4)
  if !constant_time_equal(magic, delta_magic[:]) {
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
    raise TooLarge("new_length \{total} exceeds the supported range")
  }
  let new_length = total.to_int()
  let content_digest = match sub_view(bytes, cursor, 32) {
    Some(view) => Bytes::from_array(view.to_array()[:])
    None => raise Truncated(cursor)
  }
  cursor = cursor + 32
  let count = match read_u32(bytes, cursor) {
    Some(value) => value
    None => raise Truncated(cursor)
  }
  cursor = cursor + 4
  let op_count = count.reinterpret_as_int()
  if op_count > max_block_count * 2 {
    raise TooLarge("op_count \{op_count} exceeds the supported range")
  }
  let ops : Array[DeltaOp] = []
  for index = 0; index < op_count; index = index + 1 {
    let tag = match read_u8(bytes, cursor) {
      Some(value) => value
      None => raise Truncated(cursor)
    }
    cursor = cursor + 1
    match tag {
      0 => {
        let block_index = match read_u32(bytes, cursor) {
          Some(value) => value
          None => raise Truncated(cursor)
        }
        cursor = cursor + 4
        let strong = match sub_view(bytes, cursor, strong_len) {
          Some(view) => view
          None => raise Truncated(cursor)
        }
        cursor = cursor + strong_len
        ops.push(
          Copy(
            block_index.reinterpret_as_int(),
            Bytes::from_array(strong.to_array()[:]),
          ),
        )
      }
      2 => {
        let start = match read_u32(bytes, cursor) {
          Some(value) => value
          None => raise Truncated(cursor)
        }
        cursor = cursor + 4
        let run = match read_u32(bytes, cursor) {
          Some(value) => value
          None => raise Truncated(cursor)
        }
        cursor = cursor + 4
        let strong = match sub_view(bytes, cursor, strong_len) {
          Some(view) => view
          None => raise Truncated(cursor)
        }
        cursor = cursor + strong_len
        ops.push(
          CopyRun(
            start.reinterpret_as_int(),
            run.reinterpret_as_int(),
            Bytes::from_array(strong.to_array()[:]),
          ),
        )
      }
      1 => {
        let length = match read_u32(bytes, cursor) {
          Some(value) => value
          None => raise Truncated(cursor)
        }
        cursor = cursor + 4
        let payload = match
          sub_view(bytes, cursor, length.reinterpret_as_int()) {
          Some(view) => view
          None => raise Truncated(cursor)
        }
        cursor = cursor + length.reinterpret_as_int()
        ops.push(Literal(Bytes::from_array(payload.to_array()[:])))
      }
      other => raise UnsupportedOp(other)
    }
  }
  if cursor != bytes.length() {
    raise BadField("delta has \{bytes.length() - cursor} trailing bytes")
  }
  { block_size: size, strong_len, new_length, content_digest, ops, }
}

///|
/// Apply `delta` to `old`, verifying the strong checksum of every copy.
///
/// The result is byte identical to the data the encoder started from when the
/// old data is the same version the signature described. Any other combination
/// raises `BlockMismatch` or `BadField` rather than returning plausible bytes.
pub fn apply_delta(
  old : BytesView,
  delta : Delta,
) -> ApplyResult raise FormatError {
  let sink = ByteSink::new()
  let old_blocks = block_count(old.length(), delta.block_size)
  let mut blocks_verified = 0
  let mut written = 0
  for op in delta.ops {
    match op {
      Literal(bytes) => {
        sink.write_bytes(bytes[:])
        written = written + bytes.length()
      }
      Copy(index, strong) => {
        if index < 0 || index >= old_blocks {
          raise BadField(
            "copy refers to block \{index} but the old data has \{old_blocks} blocks",
          )
        }
        let start = index * delta.block_size
        let end = if start + delta.block_size < old.length() {
          start + delta.block_size
        } else {
          old.length()
        }
        let block = old.clamped_view(start~, end~)
        let actual = sha256_prefix(block, delta.strong_len)
        if !constant_time_equal(actual[:], strong[:]) {
          raise BlockMismatch(index)
        }
        sink.write_bytes(block)
        written = written + end - start
        blocks_verified = blocks_verified + 1
      }
      CopyRun(start, count, strong) => {
        if count <= 0 {
          raise BadField("copy run at block \{start} has no blocks")
        }
        if start < 0 || start + count > old_blocks {
          raise BadField(
            "copy run [\{start}, \{start + count}) exceeds \{old_blocks} blocks",
          )
        }
        let begin = start * delta.block_size
        let mut end = (start + count) * delta.block_size
        if end > old.length() {
          end = old.length()
        }
        let run = old.clamped_view(start=begin, end~)
        let actual = sha256_prefix(run, delta.strong_len)
        if !constant_time_equal(actual[:], strong[:]) {
          raise BlockMismatch(start)
        }
        sink.write_bytes(run)
        written = written + end - begin
        blocks_verified = blocks_verified + count
      }
    }
  }
  if written != delta.new_length {
    raise BadField(
      "delta covers \{written} bytes but claims \{delta.new_length}",
    )
  }
  let output = sink.to_bytes()
  if !constant_time_equal(sha256(output[:])[:], delta.content_digest[:]) {
    raise DigestMismatch
  }
  {
    bytes_written: written,
    blocks_verified,
    ops_applied: delta.ops.length(),
    digest_hex: sha256_hex(output[:]),
    output,
  }
}
