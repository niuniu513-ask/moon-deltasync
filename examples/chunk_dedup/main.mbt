///|
/// Workflow 3: store two versions of the same object and pay only for the parts
/// that differ. Runs offline: `moon run examples/chunk_dedup`.

///|
fn ascii(text : String) -> Bytes {
  @utf8.encode(text)
}

///|
fn snapshot(generation : Int32) -> Bytes {
  let builder = @ds.ByteSink::new()
  for index = 0; index < 4000; index = index + 1 {
    builder.write_bytes(
      ascii(
        "record \{index}: value=\{index * 7 % 1000} generation=\{index / 1000}\n",
      )[:],
    )
  }
  builder.write_bytes(ascii("generation marker: \{generation}\n")[:])
  builder.to_bytes()
}

///|
fn main raise {
  let store = @ds.ChunkStore::new()
  let first = snapshot(1)
  let second = snapshot(2)
  let report_first = @ds.ingest_snapshot(store, first[:])
  println(@ds.render_chunk_json(report_first, "snapshot-1"))
  let report_second = @ds.ingest_snapshot(store, second[:])
  println(@ds.render_chunk_json(report_second, "snapshot-2"))
  println("distinct chunks in the store: \{store.unique_chunks()}")
  println("bytes actually kept: \{store.stored_bytes()}")
  println("bytes deduplication avoided: \{store.saved_bytes()}")
  // Rebuilding from the store is what proves the deduplication did not lose
  // anything: the manifest names the chunks, the store supplies them.
  let manifest = @ds.chunk_manifest(second[:])
  let rebuilt = store.assemble(manifest)
  println("rebuilt second snapshot: \{@ds.sha256_hex(rebuilt[:])}")
  println(
    "matches the source: \{@ds.sha256_hex(rebuilt[:]) == @ds.sha256_hex(second[:])}",
  )
}
