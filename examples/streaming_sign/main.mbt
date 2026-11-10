///|
/// Workflow with a caller supplied byte source: the data never has to be in
/// memory as one buffer.
///
/// Runs offline: `moon run examples/streaming_sign`.

///|
/// A source that generates a synthetic document in pieces. A real caller would
/// read a file or a socket here; the point is that the library only asks for the
/// next slice.
struct DocumentSource {
  mut sent : Int32
  total : Int32
  width : Int32
}

///|
impl @ds.ByteSource for DocumentSource with fn next(self : DocumentSource) -> Bytes? {
  if self.sent >= self.total {
    return None
  }
  let take = if self.sent + self.width < self.total {
    self.width
  } else {
    self.total - self.sent
  }
  let builder = @ds.ByteSink::new()
  for index = 0; index < take; index = index + 1 {
    let position = self.sent + index
    builder.write_u8((position * 31 + position / 97) % 251)
  }
  self.sent = self.sent + take
  Some(builder.to_bytes())
}

///|
fn main raise {
  let total = 300_000
  // 1. Sign the stream in 1000 byte pieces.
  let source : DocumentSource = { sent: 0, total, width: 1000, }
  let streamed = @ds.sign_source(source as &@ds.ByteSource, block_size=8192)
  println(
    "streamed signature: \{streamed.total_length} bytes, \{streamed.blocks.length()} blocks",
  )
  // 2. The same data through the in-memory path must produce the same bytes.
  let whole = {
    let builder = @ds.ByteSink::new()
    for index = 0; index < total; index = index + 1 {
      builder.write_u8((index * 31 + index / 97) % 251)
    }
    builder.to_bytes()
  }
  let buffered = @ds.sign_bytes(whole[:], block_size=8192)
  println(
    "identical to the buffered signature: \{@ds.hex_encode(streamed.encode()[:]) == @ds.hex_encode(buffered.encode()[:])}",
  )
  // 3. Chunking can stream too, which is what a backup tool needs for a disk image.
  let chunk_source : DocumentSource = { sent: 0, total, width: 4096, }
  let manifest = @ds.chunk_source(chunk_source as &@ds.ByteSource)
  println(
    "streamed manifest: \{manifest.chunk_count()} chunks, root \{manifest.root_hex()}",
  )
  let memory_manifest = @ds.chunk_manifest(whole[:])
  println(
    "same root as the buffered manifest: \{manifest.root_hex() == memory_manifest.root_hex()}",
  )
}
