///|
/// Workflow tests: the pieces `plan_transfer` and `verified_update` glue
/// together, and the report numbers that depend on them.

///|
test "a small edit on a large document is a small delta" {
  let old = pattern(65536, 31)
  let builder = ByteSink::new()
  builder.write_bytes(old.clamped_view(start=0, end=30000))
  builder.write_bytes(ascii_bytes("one changed sentence")[:])
  builder.write_bytes(old.clamped_view(start=30020, end=old.length()))
  let fresh = builder.to_bytes()
  let plan = plan_transfer(old[:], fresh[:], block_size=1024)
  assert_eq(plan.new_length(), fresh.length())
  assert_eq(plan.savings_ppm() > 900_000, true)
  // A 32 bit multiplication here would overflow and report a saving of zero.
  assert_eq(plan.savings_ppm() <= 1_000_000, true)
}

///|
test "the plan and its application agree byte for byte" {
  let old = pattern(20000, 37)
  let fresh = pattern(20000, 38)
  let plan = plan_transfer(old[:], fresh[:], block_size=1024)
  let result = verified_update(old[:], plan.delta_bytes()[:])
  assert_eq(result.bytes_written, fresh.length())
  assert_eq(result.digest_hex, sha256_hex(fresh[:]))
}

///|
test "a cached signature can plan several later versions" {
  let old = pattern(30000, 41)
  let signature = sign_bytes(old[:], block_size=2048)
  assert_eq(signature_matches(signature, old[:]), true)
  for seed in [42, 43, 44] {
    let fresh = pattern(30000, seed)
    let plan = plan_from_signature(signature, fresh[:])
    let result = apply_delta(old[:], plan.delta())
    assert_eq(result.digest_hex, sha256_hex(fresh[:]))
  }
}

///|
test "signature_matches rejects a longer input" {
  let data = pattern(4096, 45)
  let signature = sign_bytes(data[:], block_size=1024)
  let longer = pattern(4097, 45)
  assert_eq(signature_matches(signature, longer[:]), false)
}

///|
test "ingest_snapshot reports what the store kept" {
  let store = ChunkStore::new()
  let data = pattern(65536, 47)
  let report = ingest_snapshot(store, data[:])
  assert_eq(report.total_bytes, data.length())
  assert_eq(report.chunk_count, report.new_chunks)
  assert_eq(report.stored_bytes, data.length())
  assert_eq(report.saved_bytes, 0)
  assert_eq(report.root_hex.length(), 64)
}
