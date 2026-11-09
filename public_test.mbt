///|
/// Blackbox tests: the same three workflows through the public API only, the way
/// a user of the published package sees it.
///
/// These tests do not reach into package internals on purpose: if a symbol is
/// missing here, it is missing from the documented surface.

///|
fn hex(text : String) -> Bytes {
  match @ds.hex_decode(text) {
    Some(bytes) => bytes
    None => abort("test fixture is not hexadecimal")
  }
}

///|
test "update a file with a verified delta" {
  let old = hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  )
  let fresh = hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fff",
  )
  let plan = @ds.plan_transfer(old[:], fresh[:], block_size=256)
  let result = @ds.verified_update(old[:], plan.delta_bytes()[:])
  assert_eq(result.bytes_written, fresh.length())
  assert_eq(result.digest_hex, @ds.sha256_hex(fresh[:]))
}

///|
test "sign a file and check that it still matches" {
  let data = hex("deadbeefcafebabe00112233445566778899aabbccddeeff")
  let signature = @ds.sign_bytes(data[:], strong_len=8)
  assert_eq(@ds.signature_matches(signature, data[:]), true)
  let encoded = signature.encode()
  let decoded = @ds.decode_signature(encoded[:])
  assert_eq(decoded.strong_len, 8)
  assert_eq(decoded.total_length, data.length())
}

///|
test "store two snapshots and rebuild the second" {
  let first = hex("00ff00ff00ff00ff00ff00ff00ff00ff")
  let second = hex("00ff00ff00ff00ff00ff00ff00ff00fe")
  let store = @ds.ChunkStore::new()
  let report_a = @ds.ingest_snapshot(store, first[:])
  let report_b = @ds.ingest_snapshot(store, second[:])
  assert_eq(report_a.total_bytes, first.length())
  assert_eq(report_b.total_bytes, second.length())
  assert_eq(store.unique_chunks() >= 2, true)
  let manifest = @ds.chunk_manifest(second[:])
  let rebuilt = store.assemble(manifest)
  assert_eq(@ds.sha256_hex(rebuilt[:]), @ds.sha256_hex(second[:]))
}

///|
test "a bad signature is rejected with a diagnostic" {
  let failed = try {
    @ds.decode_signature(hex("00010203")[:]) |> ignore
    false
  } catch {
    error => error.message().contains("bad magic")
  }
  assert_eq(failed, true)
}
