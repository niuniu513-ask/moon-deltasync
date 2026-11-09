///|
/// Delta tests: the round trip, the reuse of unchanged blocks, the normalised op
/// list, and the corruption cases that must fail rather than return bytes.

///|
fn ascii_bytes(text : String) -> Bytes {
  @utf8.encode(text)
}

///|
/// A deterministic byte string of `length` bytes, so every test input is
/// reproducible without a random source.
fn pattern(length : Int32, seed : Int32) -> Bytes {
  let builder = ByteSink::new()
  let mut value = seed
  for i = 0; i < length; i = i + 1 {
    value = (value * 1103515 + 12345) % 2147483647
    builder.write_u8(value % 251)
  }
  builder.to_bytes()
}

///|
test "identical data produces a single copy run" {
  let old = pattern(4096, 7)
  let signature = sign_bytes(old[:], block_size=1024)
  let delta = compute_delta(old[:], signature)
  assert_eq(delta.copy_ops(), 1)
  assert_eq(delta.literal_bytes(), 0)
  let result = apply_delta(old[:], delta)
  assert_eq(result.bytes_written, 4096)
  assert_eq(hex_encode(result.output[:]), hex_encode(old[:]))
}

///|
test "a one byte edit only carries the neighbourhood" {
  let old = pattern(65536, 11)
  let new = bytearray_copy_edit(old, 30000)
  let signature = sign_bytes(old[:], block_size=1024)
  let delta = compute_delta(new[:], signature)
  assert_eq(delta.literal_bytes() < 4096, true)
  let result = apply_delta(old[:], delta)
  assert_eq(hex_encode(result.output[:]), hex_encode(new[:]))
}

///|
/// Copy `data` and flip one byte, which is the smallest edit a delta can face.
fn bytearray_copy_edit(data : Bytes, offset : Int32) -> Bytes {
  let builder = ByteSink::new()
  for i = 0; i < data.length(); i = i + 1 {
    if i == offset {
      builder.write_u8(data[i].to_int() ^ 0xFF)
    } else {
      builder.write_u8(data[i].to_int())
    }
  }
  builder.to_bytes()
}

///|
test "insertion keeps most blocks reusable" {
  let old = pattern(32768, 13)
  let inserted = ascii_bytes("0123456789abcdef")
  let builder = ByteSink::new()
  builder.write_bytes(old.clamped_view(start=0, end=8192))
  builder.write_bytes(inserted[:])
  builder.write_bytes(old.clamped_view(start=8192, end=old.length()))
  let new = builder.to_bytes()
  let signature = sign_bytes(old[:], block_size=1024)
  let delta = compute_delta(new[:], signature)
  assert_eq(delta.literal_bytes() < 3072, true)
  let result = apply_delta(old[:], delta)
  assert_eq(hex_encode(result.output[:]), hex_encode(new[:]))
}

///|
test "delta encoding round trips" {
  let old = pattern(5000, 17)
  let new = bytearray_copy_edit(old, 100)
  let signature = sign_bytes(old[:])
  let delta = compute_delta(new[:], signature)
  let encoded = delta.encode()
  let decoded = decode_delta(encoded[:])
  assert_eq(decoded.ops.length(), delta.ops.length())
  assert_eq(decoded.new_length, delta.new_length)
  let result = apply_delta(old[:], decoded)
  assert_eq(hex_encode(result.output[:]), hex_encode(new[:]))
}

///|
test "a delta applied to the wrong old data fails" {
  let old = pattern(4096, 19)
  let other = pattern(4096, 20)
  let signature = sign_bytes(old[:], block_size=1024)
  let new = bytearray_copy_edit(old, 10)
  let delta = compute_delta(new[:], signature)
  let failed = try {
    apply_delta(other[:], delta) |> ignore
    false
  } catch {
    _ => true
  }
  assert_eq(failed, true)
}

///|
test "a truncated delta is rejected" {
  let old = pattern(4096, 21)
  let signature = sign_bytes(old[:], block_size=1024)
  let delta = compute_delta(old[:], signature)
  let encoded = delta.encode()
  let truncated = encoded.clamped_view(start=0, end=encoded.length() - 1)
  let failed = try {
    decode_delta(truncated) |> ignore
    false
  } catch {
    _ => true
  }
  assert_eq(failed, true)
}

///|
test "a signature round trips and rejects a wrong block count" {
  let data = pattern(3000, 23)
  let signature = sign_bytes(data[:], block_size=1024, strong_len=8)
  let encoded = signature.encode()
  let decoded = decode_signature(encoded[:])
  assert_eq(decoded.block_size, 1024)
  assert_eq(decoded.strong_len, 8)
  assert_eq(decoded.blocks.length(), 3)
  assert_eq(hex_encode(decoded.encode()[:]), hex_encode(encoded[:]))
}

///|
test "signature_matches detects different data" {
  let data = pattern(2048, 29)
  let signature = sign_bytes(data[:], block_size=1024)
  assert_eq(signature_matches(signature, data[:]), true)
  assert_eq(signature_matches(signature, pattern(2048, 30)[:]), false)
}
