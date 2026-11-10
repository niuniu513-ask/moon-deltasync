///|
/// The three workflows the library is meant to be used through.
///
/// Each of them is a thin composition of the layers below, kept here so that a
/// caller does not have to remember which order to call `sign`, `compute_delta`
/// and `apply` in, and so that the numbers a report quotes come from one place.
///
/// 1. **Update a file**: `plan_transfer(old, new)` then send `delta`; the receiver
///    runs `verified_update(old, delta)` and gets the new bytes or an error.
/// 2. **Answer an update request**: the sender signs what the peer has, once, and
///    reuses that signature for every later version.
/// 3. **Deduplicate snapshots**: `ChunkStore::ingest` for every version, then
///    `assemble` to check that nothing was lost.

///|
/// The result of planning one transfer: the delta plus the numbers that make the
/// saving visible.
pub struct TransferPlan {
  signature : FileSignature
  delta : Delta
  new_length : Int32
  delta_bytes : Int32
}

///|
/// Sign `old` and compute the delta from it to `new_bytes`.
pub fn plan_transfer(
  old : BytesView,
  new_bytes : BytesView,
  block_size? : Int32,
  strong_len? : Int32,
) -> TransferPlan raise FormatError {
  let signature = sign_bytes(old, block_size?, strong_len?)
  let delta = compute_delta(new_bytes, signature)
  {
    signature,
    delta,
    new_length: new_bytes.length(),
    delta_bytes: delta.encode().length(),
  }
}

///|
/// Compute a delta against a signature that was produced earlier, which is what a
/// server does when it keeps the client's signature between requests.
pub fn plan_from_signature(
  signature : FileSignature,
  new_bytes : BytesView,
) -> TransferPlan raise FormatError {
  let delta = compute_delta(new_bytes, signature)
  {
    signature,
    delta,
    new_length: new_bytes.length(),
    delta_bytes: delta.encode().length(),
  }
}

///|
pub fn TransferPlan::delta(self : TransferPlan) -> Delta {
  self.delta
}

///|
pub fn TransferPlan::signature(self : TransferPlan) -> FileSignature {
  self.signature
}

///|
/// The encoded delta, ready to be stored or sent.
pub fn TransferPlan::delta_bytes(self : TransferPlan) -> Bytes {
  self.delta.encode()
}

///|
pub fn TransferPlan::new_length(self : TransferPlan) -> Int32 {
  self.new_length
}

///|
pub fn TransferPlan::literal_bytes(self : TransferPlan) -> Int32 {
  self.delta.literal_bytes()
}

///|
pub fn TransferPlan::copied_bytes(self : TransferPlan) -> Int32 {
  self.delta.copied_bytes()
}

///|
pub fn TransferPlan::copy_ops(self : TransferPlan) -> Int32 {
  self.delta.copy_ops()
}

///|
/// The saving as parts per million: `(new_length - delta_bytes) / new_length`.
///
/// Returned as an integer on purpose. A floating point ratio would print
/// differently on different backends in the last digit, and a report that cannot
/// be reproduced byte for byte is not much use as evidence.
pub fn TransferPlan::savings_ppm(self : TransferPlan) -> Int32 {
  if self.new_length <= 0 {
    return 0
  }
  let saved = self.new_length - self.delta_bytes
  if saved <= 0 {
    return 0
  }
  // 64 bit intermediate: `saved * 1_000_000` overflows a 32 bit Int for inputs
  // above a couple of kilobytes, which would silently turn the ratio into zero.
  (saved.to_int64() * 1_000_000L / self.new_length.to_int64()).to_int()
}

///|
/// Decode a delta, apply it and verify every copy. This is the only way a
/// receiver is expected to use a delta.
pub fn verified_update(
  old : BytesView,
  delta_bytes : BytesView,
) -> ApplyResult raise FormatError {
  let delta = decode_delta(delta_bytes)
  apply_delta(old, delta)
}

///|
/// Check that `old` really is the data the signature describes, block by block.
/// Useful when a signature is cached between requests.
pub fn signature_matches(signature : FileSignature, old : BytesView) -> Bool {
  if signature.total_length != old.length() {
    return false
  }
  for block in signature.blocks {
    let start = block.index * signature.block_size
    let end = if start + signature.block_size < old.length() {
      start + signature.block_size
    } else {
      old.length()
    }
    let actual = sha256_prefix(
      old.clamped_view(start~, end~),
      signature.strong_len,
    )
    if !constant_time_equal(actual[:], block.strong[:]) {
      return false
    }
  }
  true
}

///|
/// What one snapshot added to a store, in the shape a report wants it.
pub struct SnapshotReport {
  total_bytes : Int32
  chunk_count : Int32
  unique_chunks : Int32
  new_chunks : Int32
  reused_chunks : Int32
  stored_bytes : Int32
  saved_bytes : Int32
  manifest_bytes : Int32
  /// Saved bytes per million input bytes, so the ratio stays an integer.
  dedup_ppm : Int32
  root_hex : String
}

///|
/// Ingest one version into `store` and summarise what it cost.
pub fn ingest_snapshot(
  store : ChunkStore,
  input : BytesView,
  params? : ChunkParams,
) -> SnapshotReport {
  let ingest = store.ingest(input, params?)
  let saved = store.saved_bytes()
  let ingested = store.total_bytes_ingested()
  let dedup_ppm = if ingested <= 0 {
    0
  } else {
    (saved.to_int64() * 1_000_000L / ingested.to_int64()).to_int()
  }
  {
    total_bytes: ingest.total_bytes,
    chunk_count: ingest.chunk_count,
    unique_chunks: store.unique_chunks(),
    new_chunks: ingest.new_chunks,
    reused_chunks: ingest.reused_chunks,
    stored_bytes: store.stored_bytes(),
    saved_bytes: saved,
    manifest_bytes: ingest.manifest.encode().length(),
    dedup_ppm,
    root_hex: ingest.manifest.root_hex(),
  }
}

///|
/// What a chain of deltas produced.
pub struct ChainResult {
  steps : Int32
  bytes_written : Int32
  blocks_verified : Int32
  digest_hex : String
  output : Bytes
}

///|
/// Apply a chain of deltas one after another, verifying every step.
///
/// A chain is how an update that spans several releases is handled without
/// shipping a full copy: each delta is built against the previous version, and
/// the result of one step is the input of the next. Verification is per step, so
/// a broken link is reported with the index of the delta that failed.
pub fn apply_chain(
  old : BytesView,
  deltas : Array[BytesView],
) -> ChainResult raise FormatError {
  let mut current = Bytes::from_array(old.to_array()[:])
  let mut blocks = 0
  let mut steps = 0
  for delta_bytes in deltas {
    let result = verified_update(current[:], delta_bytes)
    current = result.output
    blocks = blocks + result.blocks_verified
    steps = steps + 1
  }
  {
    steps,
    bytes_written: current.length(),
    blocks_verified: blocks,
    digest_hex: sha256_hex(current[:]),
    output: current,
  }
}
