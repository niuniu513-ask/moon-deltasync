///|
/// Workflow 1: keep an old copy of a document and only receive what changed.
///
/// The example builds both versions in memory so it runs the same on every
/// backend and needs no files: `moon run examples/version_upgrade`.

///|
fn ascii(text : String) -> Bytes {
  @utf8.encode(text)
}

///|
/// A deterministic body of text, the kind of thing that gets edited in place.
fn document(paragraphs : Int32, edited : Bool) -> Bytes {
  let builder = @ds.ByteSink::new()
  for index = 0; index < paragraphs; index = index + 1 {
    builder.write_bytes(
      ascii(
        "paragraph \{index}: the quick brown fox jumps over the lazy dog.\n",
      )[:],
    )
    if edited && index == paragraphs / 2 {
      builder.write_bytes(
        ascii("inserted line: this is the only real change.\n")[:],
      )
    }
  }
  builder.to_bytes()
}

///|
fn main raise {
  let old = document(2000, false)
  let fresh = document(2000, true)
  let plan = @ds.plan_transfer(old[:], fresh[:])
  println("old bytes: \{old.length()}")
  println("new bytes: \{fresh.length()}")
  println(@ds.render_plan_markdown(plan))
  // The sender transmits plan.delta_bytes(); the receiver only needs the old
  // bytes and the delta, because every copy carries its own strong checksum.
  let delta_bytes = plan.delta_bytes()
  println("delta bytes on the wire: \{delta_bytes.length()}")
  let result = @ds.verified_update(old[:], delta_bytes[:])
  println(
    "rebuilt bytes: \{result.bytes_written} (verified \{result.blocks_verified} blocks)",
  )
  println("rebuilt digest: \{result.digest_hex}")
  println(
    "identical to the new version: \{result.digest_hex == @ds.sha256_hex(fresh[:])}",
  )
}
