///|
/// Renderers: the same facts as text, JSON and Markdown.
///
/// The JSON lines are the machine readable contract used by the command line and
/// by the external verification script, so they are written by hand here rather
/// than through a generic serializer: the field order is fixed, the numbers are
/// integers or fixed precision text, and nothing depends on a hash order. A
/// document always ends with exactly one newline.

///|
/// Quote a JSON string, escaping the characters that must be escaped.
pub fn json_string(text : String) -> String {
  let builder = StringBuilder(size_hint=text.length() + 2)
  builder.write_char('"')
  for ch in text {
    if ch == '"' {
      builder.write_string("\\\"")
    } else if ch == '\\' {
      builder.write_string("\\\\")
    } else if ch == '\n' {
      builder.write_string("\\n")
    } else if ch == '\r' {
      builder.write_string("\\r")
    } else if ch == '\t' {
      builder.write_string("\\t")
    } else if ch.to_int() < 32 {
      builder.write_string("\\u00")
      builder.write_string(two_hex(ch.to_int()))
    } else {
      builder.write_char(ch)
    }
  }
  builder.write_char('"')
  builder.to_string()
}

///|
fn two_hex(value : Int32) -> String {
  let digits : Array[Char] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  ]
  let safe = if value < 0 { 0 } else { value }
  digits[safe / 16 % 16].to_string() + digits[safe % 16].to_string()
}

///|
/// A ratio expressed in parts per million as fixed four decimal text, e.g.
/// `0.9992`. Integer arithmetic only, so the same input prints the same text on
/// every backend.
pub fn ppm_text(ppm : Int32) -> String {
  let clamped = if ppm < 0 {
    0
  } else if ppm > 1_000_000 {
    1_000_000
  } else {
    ppm
  }
  let whole = clamped / 1_000_000
  let fraction = clamped % 1_000_000
  let four = (fraction + 50) / 100
  if four >= 10_000 {
    whole.to_string() + ".0000"
  } else {
    let text = four.to_string()
    let padding = if text.length() >= 4 {
      ""
    } else if text.length() == 3 {
      "0"
    } else if text.length() == 2 {
      "00"
    } else if text.length() == 1 {
      "000"
    } else {
      "0000"
    }
    whole.to_string() + "." + padding + text
  }
}

///|
/// One JSON line describing a signature.
pub fn render_signature_json(
  signature : FileSignature,
  path : String,
) -> String {
  "{\"kind\":\"sign\",\"path\":" +
  json_string(path) +
  ",\"total_length\":" +
  signature.total_length.to_string() +
  ",\"block_size\":" +
  signature.block_size.to_string() +
  ",\"strong_len\":" +
  signature.strong_len.to_string() +
  ",\"block_count\":" +
  signature.blocks.length().to_string() +
  ",\"signature_bytes\":" +
  signature.encode().length().to_string() +
  ",\"signature_sha256_hex\":" +
  json_string(signature.digest_hex()) +
  "}"
}

///|
/// One JSON line describing the plan for one transfer.
pub fn render_delta_json(
  plan : TransferPlan,
  old_path : String,
  new_path : String,
) -> String {
  "{\"kind\":\"delta\",\"old\":" +
  json_string(old_path) +
  ",\"new\":" +
  json_string(new_path) +
  ",\"new_length\":" +
  plan.new_length().to_string() +
  ",\"copy_ops\":" +
  plan.copy_ops().to_string() +
  ",\"copied_bytes\":" +
  plan.copied_bytes().to_string() +
  ",\"literal_bytes\":" +
  plan.literal_bytes().to_string() +
  ",\"delta_bytes\":" +
  plan.delta_bytes().length().to_string() +
  ",\"delta_sha256_hex\":" +
  json_string(plan.delta().digest_hex()) +
  ",\"savings_ratio\":" +
  ppm_text(plan.savings_ppm()) +
  "}"
}

///|
/// One JSON line describing an applied delta.
pub fn render_apply_json(result : ApplyResult) -> String {
  "{\"kind\":\"apply\",\"ok\":true,\"bytes_written\":" +
  result.bytes_written.to_string() +
  ",\"blocks_verified\":" +
  result.blocks_verified.to_string() +
  ",\"ops_applied\":" +
  result.ops_applied.to_string() +
  ",\"sha256_hex\":" +
  json_string(result.digest_hex) +
  "}"
}

///|
/// One JSON line describing one snapshot ingested into a chunk store.
pub fn render_chunk_json(report : SnapshotReport, path : String) -> String {
  "{\"kind\":\"chunk\",\"path\":" +
  json_string(path) +
  ",\"length\":" +
  report.total_bytes.to_string() +
  ",\"chunk_count\":" +
  report.chunk_count.to_string() +
  ",\"new_chunks\":" +
  report.new_chunks.to_string() +
  ",\"reused_chunks\":" +
  report.reused_chunks.to_string() +
  ",\"stored_bytes\":" +
  report.stored_bytes.to_string() +
  ",\"saved_bytes\":" +
  report.saved_bytes.to_string() +
  ",\"root_hex\":" +
  json_string(report.root_hex) +
  "}"
}

///|
/// One JSON line describing a failure. The command line prints this instead of a
/// stack trace, and exits non zero.
pub fn render_error_json(code : String, message : String) -> String {
  "{\"kind\":\"error\",\"code\":" +
  json_string(code) +
  ",\"message\":" +
  json_string(message) +
  "}"
}

///|
/// A human readable summary of one transfer, for a terminal or a log line.
pub fn render_plan_text(plan : TransferPlan) -> String {
  "new_length: " +
  plan.new_length().to_string() +
  "\ncopy_ops: " +
  plan.copy_ops().to_string() +
  "\ncopied_bytes: " +
  plan.copied_bytes().to_string() +
  "\nliteral_bytes: " +
  plan.literal_bytes().to_string() +
  "\ndelta_bytes: " +
  plan.delta_bytes().length().to_string() +
  "\nsavings_ratio: " +
  ppm_text(plan.savings_ppm()) +
  "\n"
}

///|
/// The same summary as a Markdown table, for a pull request comment or a report.
pub fn render_plan_markdown(plan : TransferPlan) -> String {
  let builder = StringBuilder()
  builder.write_string("| 指标 | 值 |\n| --- | --- |\n")
  builder.write_string(
    "| 新数据长度 | " + plan.new_length().to_string() + " |\n",
  )
  builder.write_string(
    "| 复制操作数 | " + plan.copy_ops().to_string() + " |\n",
  )
  builder.write_string(
    "| 复制字节 | " + plan.copied_bytes().to_string() + " |\n",
  )
  builder.write_string(
    "| 字面量字节 | " + plan.literal_bytes().to_string() + " |\n",
  )
  builder.write_string(
    "| delta 字节 | " + plan.delta_bytes().length().to_string() + " |\n",
  )
  builder.write_string(
    "| 节省比例 | " + ppm_text(plan.savings_ppm()) + " |\n",
  )
  builder.to_string()
}
