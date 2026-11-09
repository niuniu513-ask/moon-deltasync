///|
/// Chunking tests: the boundaries are in range, they cover the input exactly,
/// they survive an insertion, and a manifest can be rebuilt from a store.
///
/// The shared helpers `ascii_bytes` and `pattern` live in `delta_wbtest.mbt`,
/// because whitebox test files are compiled as one package.

///|
test "boundaries cover the input without gaps" {
  let data = pattern(100000, 3)
  let boundaries = chunk_boundaries(data[:])
  assert_eq(boundaries.length() > 0, true)
  assert_eq(boundaries[0].0, 0)
  assert_eq(boundaries[boundaries.length() - 1].1, data.length())
  let mut previous_end = 0
  for boundary in boundaries {
    let (start, end) = boundary
    assert_eq(start, previous_end)
    assert_eq(end > start, true)
    previous_end = end
  }
}

///|
test "chunk sizes respect the configured bounds" {
  let params = ChunkParams::new(min_size=512, max_size=4096, mask_bits=10)
  let data = pattern(200000, 5)
  for boundary in chunk_boundaries(data[:], params~) {
    let (start, end) = boundary
    let size = end - start
    assert_eq(size <= 4096, true)
    assert_eq(size >= 1, true)
  }
}

///|
test "an inserted byte keeps most chunks identical" {
  let data = pattern(262144, 7)
  let before = chunk_manifest(data[:])
  let builder = ByteSink::new()
  builder.write_bytes(data.clamped_view(start=0, end=100000))
  builder.write_bytes(ascii_bytes("X")[:])
  builder.write_bytes(data.clamped_view(start=100000, end=data.length()))
  let edited = builder.to_bytes()
  let after = chunk_manifest(edited[:])
  let kept = count_shared_chunks(before, after)
  let ratio = kept.to_int64() * 100L / before.chunk_count().to_int64()
  assert_eq(ratio >= 90L, true)
}

///|
fn count_shared_chunks(left : ChunkManifest, right : ChunkManifest) -> Int32 {
  let digests : Map[String, Int32] = Map([])
  for chunk in right.chunks {
    digests[hex_encode(chunk.digest[:])] = 1
  }
  let mut shared = 0
  for chunk in left.chunks {
    match digests.get(hex_encode(chunk.digest[:])) {
      Some(_) => shared = shared + 1
      None => ()
    }
  }
  shared
}

///|
test "manifest encodes, decodes and verifies" {
  let data = pattern(65536, 9)
  let manifest = chunk_manifest(data[:])
  let encoded = manifest.encode()
  let decoded = decode_manifest(encoded[:])
  assert_eq(decoded.chunk_count(), manifest.chunk_count())
  assert_eq(decoded.total_length(), data.length())
  assert_eq(decoded.root_hex(), manifest.root_hex())
  assert_eq(decoded.verify(data[:]), true)
  assert_eq(decoded.verify(pattern(65536, 10)[:]), false)
}

///|
test "a corrupted manifest root is rejected" {
  let data = pattern(8192, 11)
  let manifest = chunk_manifest(data[:])
  let encoded = manifest.encode()
  let corrupted = ByteSink::new()
  corrupted.write_bytes(encoded.clamped_view(start=0, end=encoded.length() - 1))
  corrupted.write_u8(encoded[encoded.length() - 1].to_int() ^ 0xFF)
  let failed = try {
    decode_manifest(corrupted.to_bytes()[:]) |> ignore
    false
  } catch {
    _ => true
  }
  assert_eq(failed, true)
}

///|
test "the store deduplicates similar versions" {
  let store = ChunkStore::new()
  let old = pattern(262144, 13)
  let first = ingest_snapshot(store, old[:])
  assert_eq(first.new_chunks, first.chunk_count)
  assert_eq(first.reused_chunks, 0)
  let edit_point = old.length() / 2
  let builder = ByteSink::new()
  builder.write_bytes(old.clamped_view(start=0, end=edit_point))
  builder.write_bytes(ascii_bytes("EDITED")[:])
  builder.write_bytes(old.clamped_view(start=edit_point + 6, end=old.length()))
  let edited = builder.to_bytes()
  let second = ingest_snapshot(store, edited[:])
  assert_eq(second.reused_chunks > 0, true)
  assert_eq(second.new_chunks < second.chunk_count, true)
  assert_eq(store.saved_bytes() > 0, true)
}

///|
test "assembling a manifest from the store reproduces the bytes" {
  let store = ChunkStore::new()
  let data = pattern(131072, 17)
  let report = ingest_snapshot(store, data[:])
  let manifest = chunk_manifest(data[:])
  assert_eq(report.root_hex, manifest.root_hex())
  let rebuilt = store.assemble(manifest)
  assert_eq(hex_encode(rebuilt[:]), hex_encode(data[:]))
}

///|
test "assembling with a missing chunk fails" {
  let store = ChunkStore::new()
  let data = pattern(65536, 19)
  let manifest = chunk_manifest(data[:])
  let failed = try {
    store.assemble(manifest) |> ignore
    false
  } catch {
    _ => true
  }
  assert_eq(failed, true)
}
