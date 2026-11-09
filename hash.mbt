///|
/// The three checksums this library relies on, each with a different job.
///
/// `weak_checksum` is an Adler-32 variant modulo 65521: cheap, incremental in
/// O(1) per byte, and used only as a first filter when matching blocks.
///
/// `sha256` is the strong checksum. It is what makes a `COPY` operation
/// trustworthy, and it is what the delta format stores (truncated) per block.
///
/// `xxh64` is a fast non cryptographic fingerprint used by the reports and by
/// the chunk index. It is never used to decide whether bytes are equal.
///
/// None of these functions panics: inputs of any length are accepted, including
/// the empty slice.

// ---------------------------------------------------------------------------
// Adler-32 variant
// ---------------------------------------------------------------------------

let adler_modulus : UInt32 = 65521U

///|
/// The weak checksum of an entire slice, taken as one window.
pub fn weak_checksum(view : BytesView) -> UInt32 {
  let mut a : UInt32 = 1U
  let mut b : UInt32 = 0U
  for i = 0; i < view.length(); i = i + 1 {
    a = (a + view[i].to_uint()) % adler_modulus
    b = (b + a) % adler_modulus
  }
  (b << 16) | a
}

///|
/// A sliding window over a byte stream whose weak checksum can be updated in
/// constant time when one byte leaves and one enters.
///
/// The window length never changes, so `value` stays comparable between
/// positions of the same stream and with the checksums stored in a signature.
pub struct WeakRoll {
  mut a : UInt32
  mut b : UInt32
  window : UInt32
}

///|
/// Build a rolling window whose initial position is the whole of `view`.
pub fn WeakRoll::new(view : BytesView) -> WeakRoll {
  let mut a : UInt32 = 1U
  let mut b : UInt32 = 0U
  for i = 0; i < view.length(); i = i + 1 {
    a = (a + view[i].to_uint()) % adler_modulus
    b = (b + a) % adler_modulus
  }
  { a, b, window: view.length().reinterpret_as_uint(), }
}

///|
/// The checksum of the current window, laid out as `(b << 16) | a`.
pub fn WeakRoll::value(self : WeakRoll) -> UInt32 {
  (self.b << 16) | self.a
}

///|
/// Re-point the window at a completely new position, recomputing from scratch.
/// Used after a copy, where the next window is not one byte away from the last.
pub fn WeakRoll::reset(self : WeakRoll, view : BytesView) -> Unit {
  let mut a : UInt32 = 1U
  let mut b : UInt32 = 0U
  for i = 0; i < view.length(); i = i + 1 {
    a = (a + view[i].to_uint()) % adler_modulus
    b = (b + a) % adler_modulus
  }
  self.a = a
  self.b = b
}

///|
/// Slide the window one byte to the right: `leaving` drops out of the front,
/// `entering` arrives at the back. Both arguments must be the actual bytes at
/// the two edges, otherwise the checksum stops matching `weak_checksum`.
pub fn WeakRoll::roll(self : WeakRoll, leaving : Byte, entering : Byte) -> Unit {
  let out = leaving.to_uint() % adler_modulus
  let product = self.window % adler_modulus * out % adler_modulus
  self.a = (self.a + adler_modulus - out + entering.to_uint()) % adler_modulus
  // b is the sum of the running a values, so the constant one that `a` starts
  // from contributes one extra to b at every position: hence the `- 1`.
  self.b = (self.b + adler_modulus - product) % adler_modulus
  self.b = (self.b + self.a + adler_modulus - 1U) % adler_modulus
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

///|
let sha256_k : Array[UInt32] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
fn rotr32(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
/// Compress one 64 byte message block into `state`, which holds the eight
/// chaining words `h0..h7`.
fn sha256_compress(state : Array[UInt32], block : BytesView) -> Unit {
  let w : Array[UInt32] = Array::make(64, 0U)
  for i = 0; i < 16; i = i + 1 {
    let mut word : UInt32 = 0U
    for j = 0; j < 4; j = j + 1 {
      word = (word << 8) | block[i * 4 + j].to_uint()
    }
    w[i] = word
  }
  for i = 16; i < 64; i = i + 1 {
    let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
    let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1
  }
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]
  for i = 0; i < 64; i = i + 1 {
    let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
    let ch = (e & f) ^ (e.lnot() & g)
    let temp1 = h + s1 + ch + sha256_k[i] + w[i]
    let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let temp2 = s0 + maj
    h = g
    g = f
    f = e
    e = d + temp1
    d = c
    c = b
    b = a
    a = temp1 + temp2
  }
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}

///|
/// The SHA-256 digest of `view`, as 32 bytes.
pub fn sha256(view : BytesView) -> Bytes {
  let state : Array[UInt32] = [
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU,
    0x1f83d9abU, 0x5be0cd19U,
  ]
  let length = view.length()
  let mut offset = 0
  while offset + 64 <= length {
    sha256_compress(state, view.clamped_view(start=offset, end=offset + 64))
    offset = offset + 64
  }
  // Padding: the remaining bytes, one 0x80 byte, zeros, then the bit length as a
  // big endian u64, which always fits in one or two trailing blocks.
  let rest = length - offset
  let padded_length = if rest < 56 { 64 } else { 128 }
  let padded : Array[Byte] = Array::make(padded_length, b'\x00')
  for i = 0; i < rest; i = i + 1 {
    padded[i] = view[offset + i]
  }
  padded[rest] = b'\x80'
  let bit_length = length.to_uint64() * 8UL
  for i = 0; i < 8; i = i + 1 {
    padded[padded_length - 8 + i] = ((bit_length >> ((7 - i) * 8)) & 0xFFUL).to_byte()
  }
  let padded_bytes = Bytes::from_array(padded[:])
  let mut tail_offset = 0
  while tail_offset < padded_length {
    sha256_compress(
      state,
      padded_bytes.clamped_view(start=tail_offset, end=tail_offset + 64),
    )
    tail_offset = tail_offset + 64
  }
  let sink = ByteSink::new()
  for i = 0; i < 8; i = i + 1 {
    sink.write_u32(state[i])
  }
  sink.to_bytes()
}

///|
/// The SHA-256 digest of `view` as lower case hexadecimal text.
pub fn sha256_hex(view : BytesView) -> String {
  hex_encode(sha256(view))
}

///|
/// The first `length` bytes of the SHA-256 digest of `view`.
///
/// A signature stores a truncated digest: 8 or 16 bytes is enough to make an
/// accidental match impossible while keeping signatures small, and the weak
/// checksum already filtered the candidates. Truncation is a format decision,
/// so it lives here rather than in the caller.
pub fn sha256_prefix(view : BytesView, length : Int32) -> Bytes {
  if length <= 0 {
    return Bytes::new(0)
  }
  let digest = sha256(view)
  let take = if length < 32 { length } else { 32 }
  Bytes::from_array(digest.clamped_view(start=0, end=take).to_array()[:])
}

// ---------------------------------------------------------------------------
// XXH64
// ---------------------------------------------------------------------------

///|
let xxh_prime1 : UInt64 = 11400714785074694791UL

///|
let xxh_prime2 : UInt64 = 14029467366897019727UL

///|
let xxh_prime3 : UInt64 = 1609587929392839161UL

///|
let xxh_prime4 : UInt64 = 9650029242287828579UL

///|
let xxh_prime5 : UInt64 = 2870177450012600261UL

///|
fn rotl64(x : UInt64, n : Int32) -> UInt64 {
  (x << n) | (x >> (64 - n))
}

///|
fn xxh_round(acc : UInt64, input : UInt64) -> UInt64 {
  rotl64(acc + input * xxh_prime2, 31) * xxh_prime1
}

///|
fn xxh_merge_round(acc : UInt64, value : UInt64) -> UInt64 {
  (acc ^ xxh_round(0UL, value)) * xxh_prime1 + xxh_prime4
}

///|
fn xxh_read_u64(view : BytesView, offset : Int32) -> UInt64 {
  let mut value : UInt64 = 0UL
  for i = 0; i < 8; i = i + 1 {
    value = value | (view[offset + i].to_uint64() << (i * 8))
  }
  value
}

///|
fn xxh_read_u32(view : BytesView, offset : Int32) -> UInt64 {
  let mut value : UInt64 = 0UL
  for i = 0; i < 4; i = i + 1 {
    value = value | (view[offset + i].to_uint64() << (i * 8))
  }
  value
}

///|
/// The XXH64 fingerprint of `view` with seed zero.
///
/// This is a fast non cryptographic hash: it detects accidental change and it
/// makes reports readable. It must never be the reason two byte strings are
/// considered equal, which is what `sha256` and `constant_time_equal` are for.
pub fn xxh64(view : BytesView) -> UInt64 {
  let length = view.length()
  let mut offset = 0
  let mut hash : UInt64 = 0UL
  if length >= 32 {
    let mut v1 = xxh_prime1 + xxh_prime2
    let mut v2 = xxh_prime2
    let mut v3 : UInt64 = 0UL
    let mut v4 = 0UL - xxh_prime1
    let limit = length - 32
    while offset <= limit {
      v1 = xxh_round(v1, xxh_read_u64(view, offset))
      v2 = xxh_round(v2, xxh_read_u64(view, offset + 8))
      v3 = xxh_round(v3, xxh_read_u64(view, offset + 16))
      v4 = xxh_round(v4, xxh_read_u64(view, offset + 24))
      offset = offset + 32
    }
    hash = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18)
    hash = xxh_merge_round(hash, v1)
    hash = xxh_merge_round(hash, v2)
    hash = xxh_merge_round(hash, v3)
    hash = xxh_merge_round(hash, v4)
  } else {
    hash = hash + xxh_prime5
  }
  hash = hash + length.to_uint64()
  while offset + 8 <= length {
    let k1 = xxh_round(0UL, xxh_read_u64(view, offset))
    hash = hash ^ k1
    hash = rotl64(hash, 27) * xxh_prime1 + xxh_prime4
    offset = offset + 8
  }
  if offset + 4 <= length {
    hash = hash ^ (xxh_read_u32(view, offset) * xxh_prime1)
    hash = rotl64(hash, 23) * xxh_prime2 + xxh_prime3
    offset = offset + 4
  }
  while offset < length {
    hash = hash ^ (view[offset].to_uint64() * xxh_prime5)
    hash = rotl64(hash, 11) * xxh_prime1
    offset = offset + 1
  }
  hash = hash ^ (hash >> 33)
  hash = hash * xxh_prime2
  hash = hash ^ (hash >> 29)
  hash = hash * xxh_prime3
  hash = hash ^ (hash >> 32)
  hash
}

///|
/// The XXH64 fingerprint as sixteen lower case hexadecimal characters, which is
/// how the reports spell it.
pub fn xxh64_hex(view : BytesView) -> String {
  let value = xxh64(view)
  let builder = StringBuilder(size_hint=16)
  for shift in [60, 56, 52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0] {
    builder.write_char(hex_digits[((value >> shift) & 0xFUL).to_int()])
  }
  builder.to_string()
}
