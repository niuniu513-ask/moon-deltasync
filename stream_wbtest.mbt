///|
/// Streaming tests: the point of `sign_source` and `chunk_source` is that they
/// must produce exactly the same bytes as the in-memory entry points, no matter
/// how the source hands the data over. Every test here compares against the
/// whole-buffer function rather than against a hand written expectation.

///|
/// A source that yields pre-cut slices, to prove a caller can feed the library
/// from anywhere (a file, a socket) without depending on `MemorySource`.
struct SliceSource {
  slices : Array[Bytes]
  mut index : Int32
}

///|
impl ByteSource for SliceSource with fn next(self : SliceSource) -> Bytes? {
  if self.index >= self.slices.length() {
    return None
  }
  let slice = self.slices[self.index]
  self.index = self.index + 1
  Some(slice)
}

///|
fn slice_source(data : Bytes, width : Int32) -> SliceSource {
  let slices : Array[Bytes] = []
  let mut offset = 0
  while offset < data.length() {
    let end = if offset + width < data.length() {
      offset + width
    } else {
      data.length()
    }
    slices.push(
      Bytes::from_array(data.clamped_view(start=offset, end~).to_array()[:]),
    )
    offset = end
  }
  { slices, index: 0, }
}

///|
test "signing a stream matches signing a buffer" {
  let data = pattern(50000, 61)
  let expected = sign_bytes(data[:], block_size=1024, strong_len=8)
  for width in [1, 7, 1024, 4096, 65536] {
    let source = MemorySource::new(data[:], window=width)
    let actual = sign_source(
      source as &ByteSource,
      block_size=1024,
      strong_len=8,
    )
    assert_eq(hex_encode(actual.encode()[:]), hex_encode(expected.encode()[:]))
  }
}

///|
test "signing a caller supplied source matches the buffer" {
  let data = pattern(20000, 62)
  let expected = sign_bytes(data[:], block_size=512)
  let source = slice_source(data, 333)
  let actual = sign_source(source as &ByteSource, block_size=512)
  assert_eq(hex_encode(actual.encode()[:]), hex_encode(expected.encode()[:]))
}

///|
test "an empty stream signs to an empty signature" {
  let source = MemorySource::new(Bytes::make(0, b'\x00')[:])
  let signature = sign_source(source as &ByteSource, block_size=256)
  assert_eq(signature.total_length, 0)
  assert_eq(signature.blocks.length(), 0)
  assert_eq(signature.encode().length(), 22)
}

///|
test "chunking a stream matches chunking a buffer" {
  let data = pattern(200000, 63)
  let expected = chunk_manifest(data[:])
  for width in [64, 1000, 65536] {
    let source = MemorySource::new(data[:], window=width)
    let actual = chunk_source(source as &ByteSource)
    assert_eq(actual.chunk_count(), expected.chunk_count())
    assert_eq(actual.root_hex(), expected.root_hex())
    assert_eq(hex_encode(actual.encode()[:]), hex_encode(expected.encode()[:]))
  }
}

///|
test "chunking a caller supplied source matches the buffer" {
  let data = pattern(120000, 64)
  let expected = chunk_manifest(
    data[:],
    params=ChunkParams::new(min_size=1024, max_size=8192, mask_bits=11),
  )
  let source = slice_source(data, 777)
  let actual = chunk_source(
    source as &ByteSource,
    params=ChunkParams::new(min_size=1024, max_size=8192, mask_bits=11),
  )
  assert_eq(actual.root_hex(), expected.root_hex())
}

///|
test "an empty stream chunks to an empty manifest" {
  let source = MemorySource::new(Bytes::make(0, b'\x00')[:])
  let manifest = chunk_source(source as &ByteSource)
  assert_eq(manifest.chunk_count(), 0)
  assert_eq(manifest.total_length(), 0)
}
