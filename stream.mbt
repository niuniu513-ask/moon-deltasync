///|
/// Signing and chunking without holding the whole input in memory.
///
/// `sign_bytes` and `chunk_manifest` take a `BytesView`, which is fine for the
/// sizes a test or a small file has, and impossible for a 40 GiB disk image. The
/// functions here read the same formats from a pull based `ByteSource` instead:
/// the caller decides how the bytes arrive, this library only ever holds one
/// block or one chunk at a time.
///
/// The formats are unchanged. A stream produced signature is byte identical to
/// the one `sign_bytes` would build from the same data, which is what the tests
/// assert.

///|
/// A sequential source of bytes: `next` returns the following slice, or `None`
/// once the stream is over. The slices may have any length, including zero.
///
/// Implementing this for a file, a socket or a decompressor is a few lines in the
/// caller's code, and keeps this library free of I/O.
pub(open) trait ByteSource {
  fn next(Self) -> Bytes?
}

///|
/// The in-memory source, mostly useful for tests and for adapting a `Bytes` that
/// is already loaded.
pub struct MemorySource {
  data : Bytes
  mut offset : Int32
  window : Int32
}

///|
/// Wrap `data` as a source that hands out at most `window` bytes per call.
pub fn MemorySource::new(data : BytesView, window? : Int32) -> MemorySource {
  let size = match window {
    Some(value) => value
    None => 64 * 1024
  }
  {
    data: Bytes::from_array(data.to_array()[:]),
    offset: 0,
    window: if size <= 0 {
      64 * 1024
    } else {
      size
    },
  }
}

///|
impl ByteSource for MemorySource with fn next(self : MemorySource) -> Bytes? {
  if self.offset >= self.data.length() {
    return None
  }
  let end = if self.offset + self.window < self.data.length() {
    self.offset + self.window
  } else {
    self.data.length()
  }
  let slice = self.data.clamped_view(start=self.offset, end~)
  self.offset = end
  Some(Bytes::from_array(slice.to_array()[:]))
}

///|
/// Sign a stream block by block.
///
/// The block boundaries are `block_size` bytes apart exactly as in
/// `sign_bytes`, so the two functions produce the same `DSIG` bytes for the same
/// input. Only one block is buffered at a time; the signature itself grows with
/// `total_length / block_size`, which is the format's own cost.
pub fn sign_source(
  source : &ByteSource,
  block_size? : Int32,
  strong_len? : Int32,
  total_length? : Int32,
) -> FileSignature raise FormatError {
  // A stream cannot measure itself before it is read, so the adaptive default of
  // `sign_bytes` is only available when the caller states the total length. With
  // neither a block size nor a hint the block size is 8192, which is what
  // `sign_bytes` uses for inputs of 4096 bytes or more.
  let size = match block_size {
    Some(value) => value
    None =>
      match total_length {
        Some(length) => default_block_size(length)
        None => 8192
      }
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
  let pending = ByteSink::new()
  let blocks : Array[BlockSignature] = []
  let mut total = 0
  let mut more = true
  while more {
    match source.next() {
      None => more = false
      Some(slice) => {
        total = total + slice.length()
        for index = 0; index < slice.length(); index = index + 1 {
          pending.write_u8(slice[index].to_int())
          if pending.length() == size {
            let block = pending.to_bytes()
            blocks.push({
              index: blocks.length(),
              weak: weak_checksum(block[:]),
              strong: sha256_prefix(block[:], strong),
            })
            pending.reset()
          }
        }
        if blocks.length() > max_block_count {
          raise TooLarge("block count exceeds \{max_block_count}")
        }
      }
    }
  }
  if pending.length() > 0 {
    let block = pending.to_bytes()
    blocks.push({
      index: blocks.length(),
      weak: weak_checksum(block[:]),
      strong: sha256_prefix(block[:], strong),
    })
  }
  { block_size: size, strong_len: strong, total_length: total, blocks, }
}

///|
/// Cut a stream into chunks and describe the result, without ever holding more
/// than one chunk.
///
/// The boundaries are decided by the same gear hash and mask as
/// `chunk_boundaries`, so the manifest is identical to the one built from the
/// whole input in memory.
pub fn chunk_source(
  source : &ByteSource,
  params? : ChunkParams,
) -> ChunkManifest {
  let settings = match params {
    Some(value) => value
    None => ChunkParams::default()
  }
  let mask = chunk_mask(settings)
  let chunks : Array[ChunkRef] = []
  let pending = ByteSink::new()
  let mut hash : UInt64 = 0UL
  let mut more = true
  while more {
    match source.next() {
      None => more = false
      Some(slice) =>
        for index = 0; index < slice.length(); index = index + 1 {
          let byte = slice[index]
          hash = (hash << 1) + gear_table[byte.to_int() & 0xFF]
          pending.write_u8(byte.to_int())
          let size = pending.length()
          let hit = (hash & mask) == 0UL
          if (size >= settings.min_size && hit) || size >= settings.max_size {
            let chunk = pending.to_bytes()
            chunks.push({ digest: sha256(chunk[:]), length: chunk.length(), })
            pending.reset()
            hash = 0UL
          }
        }
    }
  }
  if pending.length() > 0 {
    let chunk = pending.to_bytes()
    chunks.push({ digest: sha256(chunk[:]), length: chunk.length(), })
  }
  { params: settings, chunks, root: manifest_root(chunks), }
}

///|
/// Sign bytes that are already in memory through the streaming path.
///
/// This exists so that the streaming and the buffer APIs share one code path for
/// the block loop, and so that a caller does not have to build a trait object for
/// the common case.
pub fn sign_memory(
  data : BytesView,
  block_size? : Int32,
  strong_len? : Int32,
) -> FileSignature raise FormatError {
  sign_source(
    MemorySource::new(data) as &ByteSource,
    block_size?,
    strong_len?,
    total_length=data.length(),
  )
}

///|
/// Cut bytes that are already in memory through the streaming path.
pub fn chunk_memory(data : BytesView, params? : ChunkParams) -> ChunkManifest {
  chunk_source(MemorySource::new(data) as &ByteSource, params?)
}
