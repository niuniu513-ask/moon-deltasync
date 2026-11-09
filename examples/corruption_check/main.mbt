///|
/// Workflow 2, failure side: a delta that arrives damaged, or that is replayed
/// against the wrong old version, must be rejected instead of producing bytes.
///
/// Runs offline: `moon run examples/corruption_check`.

///|
fn ascii(text : String) -> Bytes {
  @utf8.encode(text)
}

///|
fn body(revision : Int32) -> Bytes {
  let builder = @ds.ByteSink::new()
  for index = 0; index < 600; index = index + 1 {
    builder.write_bytes(
      ascii("line \{index}: revision \{revision} of the same document\n")[:],
    )
  }
  builder.to_bytes()
}

///|
/// Flip one bit in the middle of `bytes`, the cheapest kind of corruption.
fn damage(bytes : Bytes) -> Bytes {
  let builder = @ds.ByteSink::new()
  for index = 0; index < bytes.length(); index = index + 1 {
    if index == bytes.length() / 2 {
      builder.write_u8(bytes[index].to_int() ^ 0x01)
    } else {
      builder.write_u8(bytes[index].to_int())
    }
  }
  builder.to_bytes()
}

///|
fn main raise {
  // Only a few lines differ, so the delta is mostly copies of the old data:
  // this is the case where the checksums matter.
  let old = body(1)
  let fresh_builder = @ds.ByteSink::new()
  fresh_builder.write_bytes(old.clamped_view(start=0, end=1000)[:])
  fresh_builder.write_bytes(ascii("line rewritten by the editor\n")[:])
  fresh_builder.write_bytes(old.clamped_view(start=1030, end=old.length())[:])
  let fresh = fresh_builder.to_bytes()
  let plan = @ds.plan_transfer(old[:], fresh[:])
  let encoded = plan.delta_bytes()
  println("old bytes: \{old.length()}")
  println("new bytes: \{fresh.length()}")
  println("delta bytes: \{encoded.length()} (copy ops: \{plan.copy_ops()})")
  let clean = @ds.verified_update(old[:], encoded[:])
  println(
    "intact delta rebuilds \{clean.bytes_written} bytes, all checksums agree",
  )
  let damaged = damage(encoded)
  let damaged_outcome = try {
    let result = @ds.verified_update(old[:], damaged[:])
    "accepted (\{result.bytes_written} bytes) -- this would be a bug"
  } catch {
    error => "rejected: \{error.message()}"
  }
  println("damaged delta: \{damaged_outcome}")
  let other_old = body(9)
  let replay_outcome = try {
    @ds.verified_update(other_old[:], encoded[:]) |> ignore
    "accepted -- this would be a bug"
  } catch {
    error => "rejected: \{error.message()}"
  }
  println("same delta against a different old version: \{replay_outcome}")
}
