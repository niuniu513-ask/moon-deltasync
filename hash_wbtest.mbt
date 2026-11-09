///|
/// Checksum tests. The vectors are the published ones: if these fail, every
/// signature and every chunk digest in the library is wrong, so they come first.

///|
fn ascii(text : String) -> Bytes {
  @utf8.encode(text)
}

///|
test "sha256 matches the empty string vector" {
  assert_eq(
    sha256_hex(Bytes::make(0, b'\x00')[:]),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
}

///|
test "sha256 matches the abc vector" {
  assert_eq(
    sha256_hex(ascii("abc")[:]),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

///|
test "sha256 matches the 448 bit vector" {
  assert_eq(
    sha256_hex(
      ascii("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")[:],
    ),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
}

///|
test "weak checksum of the empty window is one" {
  assert_eq(weak_checksum(Bytes::make(0, b'\x00')[:]), 1U)
}

///|
test "weak checksum is the adler layout of a known window" {
  // a = 1 + 97 + 98 + 99 = 295, b = 98 + 196 + 295 = 589
  let value = weak_checksum(ascii("abc")[:])
  assert_eq(value & 0xFFFFU, 295U)
  assert_eq(value >> 16, 589U)
}

///|
test "rolling update equals recomputation" {
  let data = ascii("0123456789abcdefghijklmnopqrstuvwxyz")
  let window = data.clamped_view(start=0, end=8)
  let roll = WeakRoll::new(window)
  assert_eq(roll.value(), weak_checksum(window))
  let mut offset = 0
  while offset + 8 < data.length() {
    roll.roll(data[offset], data[offset + 8])
    offset = offset + 1
    assert_eq(
      roll.value(),
      weak_checksum(data.clamped_view(start=offset, end=offset + 8)),
    )
  }
}

///|
test "xxh64 matches the empty vector" {
  assert_eq(xxh64_hex(Bytes::make(0, b'\x00')[:]), "ef46db3751d8e999")
}

///|
test "xxh64 matches the abc vector" {
  assert_eq(xxh64_hex(ascii("abc")[:]), "44bc2cf5ad770999")
}
