///|
/// Content defined chunking, the half of the library that decides **where** the
/// data is cut.
///
/// A fixed size split (every 8192 bytes) looks simpler, but a one byte insertion
/// near the front shifts every later boundary and every later block fingerprint,
/// so a backup of a slightly edited file stores everything again. Cutting on a
/// property of the trailing bytes instead makes boundaries survive insertions
/// and deletions: that property is what `chunk_boundaries` computes, using a
/// gear rolling hash and a mask that decides the average chunk length.
///
/// The manifest is the description of one version: the digest and length of each
/// chunk plus a root digest over the digests. A store keyed by digest can then
/// answer "do I already have this chunk" without ever looking at file names.

///|
/// The parameters that decide how a stream is cut.
///
/// `mask_bits` controls the average chunk length: a boundary is taken when the
/// low `mask_bits` bits of the rolling hash are zero, so the expected length is
/// `2^mask_bits` before the minimum and maximum corrections apply.
pub struct ChunkParams {
  min_size : Int32
  max_size : Int32
  mask_bits : Int32
}

///|
/// Min 2 KiB, average 8 KiB, max 32 KiB: small enough that an edit only re-cuts
/// a couple of neighbours, large enough that the manifest stays small.
pub fn ChunkParams::default() -> ChunkParams {
  { min_size: 2048, max_size: 32768, mask_bits: 13, }
}

///|
/// Build parameters, rejecting combinations that cannot produce sane chunks.
pub fn ChunkParams::new(
  min_size? : Int32,
  max_size? : Int32,
  mask_bits? : Int32,
) -> ChunkParams raise FormatError {
  let min_value = match min_size {
    Some(value) => value
    None => 2048
  }
  let max_value = match max_size {
    Some(value) => value
    None => 32768
  }
  let bits = match mask_bits {
    Some(value) => value
    None => 13
  }
  if min_value < 64 {
    raise BadField("min_size must be at least 64 bytes, got \{min_value}")
  }
  if max_value < min_value {
    raise BadField("max_size \{max_value} is below min_size \{min_value}")
  }
  if bits < 1 || bits > 24 {
    raise BadField("mask_bits must be in [1, 24], got \{bits}")
  }
  { min_size: min_value, max_size: max_value, mask_bits: bits, }
}

///|
/// The gear table: one 64 bit constant per byte value.
///
/// The values are derived from XXH64 of the single byte, so they are fixed by
/// the code rather than by a copied table, and a reader can reproduce them.
fn build_gear_table() -> Array[UInt64] {
  let table : Array[UInt64] = []
  for value = 0; value < 256; value = value + 1 {
    let single = Bytes::make(1, value.to_byte())
    table.push(xxh64(single[:]))
  }
  table
}

///|
let gear_table : Array[UInt64] = build_gear_table()

///|
/// The mask that turns "low bits are zero" into a boundary decision.
fn chunk_mask(params : ChunkParams) -> UInt64 {
  (1UL << params.mask_bits) - 1UL
}

///|
/// The cut points of `input` as half open `(start, end)` pairs.
///
/// The boundaries depend only on the bytes since the previous boundary, capped
/// by `min_size` and `max_size`, so an edit only affects the chunks around it.
pub fn chunk_boundaries(
  input : BytesView,
  params? : ChunkParams,
) -> Array[(Int32, Int32)] {
  let settings = match params {
    Some(value) => value
    None => ChunkParams::default()
  }
  let mask = chunk_mask(settings)
  let length = input.length()
  let boundaries : Array[(Int32, Int32)] = []
  let mut start = 0
  let mut hash : UInt64 = 0UL
  for index = 0; index < length; index = index + 1 {
    hash = (hash << 1) + gear_table[input[index].to_int() & 0xFF]
    let size = index + 1 - start
    let hit = (hash & mask) == 0UL
    if (size >= settings.min_size && hit) || size >= settings.max_size {
      if start < index + 1 {
        boundaries.push((start, index + 1))
      }
      start = index + 1
      hash = 0UL
    }
  }
  if start < length {
    boundaries.push((start, length))
  }
  boundaries
}

///|
/// One chunk of a manifest: its SHA-256 digest and its length.
pub struct ChunkRef {
  digest : Bytes
  length : Int32
}

///|
/// The description of one version of a stream as a sequence of chunks.
pub struct ChunkManifest {
  params : ChunkParams
  chunks : Array[ChunkRef]
  root : Bytes
}

///|
/// Split `input` and describe the result.
pub fn chunk_manifest(
  input : BytesView,
  params? : ChunkParams,
) -> ChunkManifest {
  let settings = match params {
    Some(value) => value
    None => ChunkParams::default()
  }
  let chunks : Array[ChunkRef] = []
  for boundary in chunk_boundaries(input, params=settings) {
    let (start, end) = boundary
    chunks.push({
      digest: sha256(input.clamped_view(start~, end~)),
      length: end - start,
    })
  }
  { params: settings, chunks, root: manifest_root(chunks), }
}

///|
/// The root digest: SHA-256 over the concatenation of every chunk digest, in
/// order. It identifies the whole stream and changes when any chunk does.
fn manifest_root(chunks : Array[ChunkRef]) -> Bytes {
  let sink = ByteSink::new()
  for chunk in chunks {
    sink.write_bytes(chunk.digest[:])
  }
  sha256(sink.to_bytes()[:])
}

///|
pub fn ChunkManifest::chunk_count(self : ChunkManifest) -> Int32 {
  self.chunks.length()
}

///|
/// The total length of the described stream.
pub fn ChunkManifest::total_length(self : ChunkManifest) -> Int32 {
  let mut total = 0
  for chunk in self.chunks {
    total = total + chunk.length
  }
  total
}

///|
/// How many distinct chunk digests the manifest references. A version with
/// many repeated chunks reports a number far below `chunk_count`.
pub fn ChunkManifest::unique_chunks(self : ChunkManifest) -> Int32 {
  let seen : Map[String, Int32] = Map([])
  for chunk in self.chunks {
    let key = hex_encode(chunk.digest[:])
    match seen.get(key) {
      Some(_) => ()
      None => seen[key] = 1
    }
  }
  seen.length()
}

///|
/// The root digest as hexadecimal text.
pub fn ChunkManifest::root_hex(self : ChunkManifest) -> String {
  hex_encode(self.root[:])
}

///|
/// Recompute the manifest of `input` with the same parameters and compare roots.
/// A mismatch means the bytes are not the version this manifest describes.
pub fn ChunkManifest::verify(self : ChunkManifest, input : BytesView) -> Bool {
  let recomputed = chunk_manifest(input, params=self.params)
  constant_time_equal(recomputed.root[:], self.root[:])
}

///|
/// The `DCHK` encoding of this manifest.
pub fn ChunkManifest::encode(self : ChunkManifest) -> Bytes {
  let sink = ByteSink::new()
  sink.write_bytes(manifest_magic[:])
  sink.write_u8(format_version)
  sink.write_u32(self.params.min_size.reinterpret_as_uint())
  sink.write_u32(self.params.max_size.reinterpret_as_uint())
  sink.write_u8(self.params.mask_bits)
  sink.write_u32(self.chunks.length().reinterpret_as_uint())
  for chunk in self.chunks {
    sink.write_bytes(chunk.digest[:])
    sink.write_varint(chunk.length.to_uint64())
  }
  sink.write_bytes(self.root[:])
  sink.to_bytes()
}

///|
/// Parse a `DCHK` byte string.
pub fn decode_manifest(bytes : BytesView) -> ChunkManifest raise FormatError {
  if bytes.length() < 4 {
    raise Truncated(0)
  }
  let magic = bytes.clamped_view(start=0, end=4)
  if !constant_time_equal(magic, manifest_magic[:]) {
    raise BadMagic(ascii_preview(magic))
  }
  let mut cursor = 4
  let version = match read_u8(bytes, cursor) {
    Some(value) => value
    None => raise Truncated(cursor)
  }
  cursor = cursor + 1
  if version != format_version {
    raise UnsupportedVersion(version)
  }
  let min_size = match read_u32(bytes, cursor) {
    Some(value) => value
    None => raise Truncated(cursor)
  }
  cursor = cursor + 4
  let max_size = match read_u32(bytes, cursor) {
    Some(value) => value
    None => raise Truncated(cursor)
  }
  cursor = cursor + 4
  let mask_bits = match read_u8(bytes, cursor) {
    Some(value) => value
    None => raise Truncated(cursor)
  }
  cursor = cursor + 1
  let params = ChunkParams::new(
    min_size=min_size.reinterpret_as_int(),
    max_size=max_size.reinterpret_as_int(),
    mask_bits~,
  )
  let count = match read_u32(bytes, cursor) {
    Some(value) => value
    None => raise Truncated(cursor)
  }
  cursor = cursor + 4
  let chunk_count = count.reinterpret_as_int()
  if chunk_count > max_block_count {
    raise TooLarge("chunk_count \{chunk_count} exceeds \{max_block_count}")
  }
  let chunks : Array[ChunkRef] = []
  for index = 0; index < chunk_count; index = index + 1 {
    let digest = match sub_view(bytes, cursor, 32) {
      Some(view) => view
      None => raise Truncated(cursor)
    }
    cursor = cursor + 32
    let (length, next) = match read_varint(bytes, cursor) {
      Some(pair) => pair
      None => raise Truncated(cursor)
    }
    cursor = next
    if length > max_supported_total {
      raise TooLarge("chunk length \{length} exceeds the supported range")
    }
    chunks.push({
      digest: Bytes::from_array(digest.to_array()[:]),
      length: length.to_int(),
    })
  }
  let root = match sub_view(bytes, cursor, 32) {
    Some(view) => view
    None => raise Truncated(cursor)
  }
  cursor = cursor + 32
  if cursor != bytes.length() {
    raise BadField("manifest has \{bytes.length() - cursor} trailing bytes")
  }
  let manifest = {
    params,
    chunks,
    root: Bytes::from_array(root.to_array()[:]),
  }
  if !constant_time_equal(manifest.root[:], manifest_root(manifest.chunks)[:]) {
    raise BadField("manifest root does not match its chunk digests")
  }
  manifest
}

///|
/// What one `ingest` call changed in the store.
pub struct IngestReport {
  total_bytes : Int32
  chunk_count : Int32
  new_chunks : Int32
  reused_chunks : Int32
  unique_bytes : Int32
  manifest : ChunkManifest
}

///|
/// A content addressed store: chunks keyed by digest, which is what makes a
/// second, similar version cost only the chunks that actually changed.
pub struct ChunkStore {
  chunks : Map[String, Bytes]
  references : Map[String, Int32]
  mut total_bytes : Int32
  mut unique_bytes : Int32
}

///|
pub fn ChunkStore::new() -> ChunkStore {
  { chunks: Map([]), references: Map([]), total_bytes: 0, unique_bytes: 0, }
}

///|
/// How many distinct chunks the store holds.
pub fn ChunkStore::unique_chunks(self : ChunkStore) -> Int32 {
  self.chunks.length()
}

///|
/// The sum of the lengths of every version ingested so far.
pub fn ChunkStore::total_bytes_ingested(self : ChunkStore) -> Int32 {
  self.total_bytes
}

///|
/// The sum of the lengths of the distinct chunks.'
pub fn ChunkStore::stored_bytes(self : ChunkStore) -> Int32 {
  self.unique_bytes
}

///|
/// The bytes that deduplication avoided: what the versions contained minus what
/// the store actually keeps.
pub fn ChunkStore::saved_bytes(self : ChunkStore) -> Int32 {
  self.total_bytes - self.unique_bytes
}

///|
/// Split `input`, add every chunk that is not already stored, and return the
/// manifest plus what changed.
pub fn ChunkStore::ingest(
  self : ChunkStore,
  input : BytesView,
  params? : ChunkParams,
) -> IngestReport {
  let settings = match params {
    Some(value) => value
    None => ChunkParams::default()
  }
  let chunks : Array[ChunkRef] = []
  let mut new_chunks = 0
  let mut reused_chunks = 0
  for boundary in chunk_boundaries(input, params=settings) {
    let (start, end) = boundary
    let payload = input.clamped_view(start~, end~)
    let digest = sha256(payload)
    let key = hex_encode(digest[:])
    match self.chunks.get(key) {
      Some(_) => {
        reused_chunks = reused_chunks + 1
        self.references[key] = self.references.get_or_default(key, 0) + 1
      }
      None => {
        let stored = Bytes::from_array(payload.to_array()[:])
        self.chunks[key] = stored
        self.references[key] = 1
        self.unique_bytes = self.unique_bytes + stored.length()
        new_chunks = new_chunks + 1
      }
    }
    chunks.push({ digest, length: end - start, })
  }
  let manifest = { params: settings, chunks, root: manifest_root(chunks), }
  self.total_bytes = self.total_bytes + input.length()
  {
    total_bytes: input.length(),
    chunk_count: chunks.length(),
    new_chunks,
    reused_chunks,
    unique_bytes: self.unique_bytes,
    manifest,
  }
}

///|
/// Rebuild the bytes described by `manifest` from the chunks in the store.
pub fn ChunkStore::assemble(
  self : ChunkStore,
  manifest : ChunkManifest,
) -> Bytes raise FormatError {
  let sink = ByteSink::new()
  for chunk in manifest.chunks {
    let key = hex_encode(chunk.digest[:])
    match self.chunks.get(key) {
      None => raise BadField("chunk \{key} is missing from the store")
      Some(payload) => {
        if payload.length() != chunk.length {
          raise BadField(
            "chunk \{key} has \{payload.length()} bytes but the manifest says \{chunk.length}",
          )
        }
        sink.write_bytes(payload[:])
      }
    }
  }
  let output = sink.to_bytes()
  output
}

///|
/// What collecting unreferenced chunks reclaimed.
pub struct GcReport {
  removed_chunks : Int32
  reclaimed_bytes : Int32
  remaining_chunks : Int32
  remaining_bytes : Int32
}

///|
/// How many versions reference a chunk. A chunk nobody references can be
/// collected; this is what makes the store usable for retention, not just for
/// deduplication.
pub fn ChunkStore::references(self : ChunkStore, digest_hex : String) -> Int32 {
  self.references.get_or_default(digest_hex, 0)
}

///|
/// Add one reference for every chunk in `manifest`.
pub fn ChunkStore::retain(self : ChunkStore, manifest : ChunkManifest) -> Unit {
  for chunk in manifest.chunks {
    let key = hex_encode(chunk.digest[:])
    if self.chunks.get(key) is Some(_) {
      self.references[key] = self.references.get_or_default(key, 0) + 1
    }
  }
}

///|
/// Remove one reference for every chunk in `manifest`.
///
/// Returns the number of chunks whose reference count reached zero. Those chunks
/// stay in the store until `collect` runs, so a release can still be rolled back.
pub fn ChunkStore::release(
  self : ChunkStore,
  manifest : ChunkManifest,
) -> Int32 {
  let mut emptied = 0
  for chunk in manifest.chunks {
    let key = hex_encode(chunk.digest[:])
    if self.chunks.get(key) is Some(_) {
      let current = self.references.get_or_default(key, 0)
      let next = if current > 0 { current - 1 } else { 0 }
      self.references[key] = next
      if next == 0 {
        emptied = emptied + 1
      }
    }
  }
  emptied
}

///|
/// Drop every chunk whose reference count is zero, and report what that freed.
pub fn ChunkStore::collect(self : ChunkStore) -> GcReport {
  let dead : Array[String] = []
  let mut emptied = 0
  for key in self.references.keys() {
    if self.references.get_or_default(key, 0) <= 0 &&
      self.chunks.get(key) is Some(_) {
      dead.push(key)
      emptied = emptied + 1
    }
  }
  let mut reclaimed = 0
  for key in dead {
    match self.chunks.get(key) {
      Some(payload) => reclaimed = reclaimed + payload.length()
      None => ()
    }
    self.chunks.remove(key)
    self.references.remove(key)
  }
  self.unique_bytes = self.unique_bytes - reclaimed
  {
    removed_chunks: emptied,
    reclaimed_bytes: reclaimed,
    remaining_chunks: self.chunks.length(),
    remaining_bytes: self.unique_bytes,
  }
}
