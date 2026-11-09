///|
/// Report tests: the JSON contract is what the external verification script reads,
/// so the field order and the fixed precision are pinned here.

///|
test "ppm_text renders four decimals without floating point" {
  assert_eq(ppm_text(0), "0.0000")
  assert_eq(ppm_text(1_000_000), "1.0000")
  assert_eq(ppm_text(917_464), "0.9175")
  assert_eq(ppm_text(500_000), "0.5000")
  assert_eq(ppm_text(15), "0.0000")
  assert_eq(ppm_text(-5), "0.0000")
  assert_eq(ppm_text(2_000_000), "1.0000")
}

///|
test "json_string escapes the mandatory characters" {
  assert_eq(json_string("plain"), "\"plain\"")
  assert_eq(json_string("a\"b"), "\"a\\\"b\"")
  assert_eq(json_string("a\\b"), "\"a\\\\b\"")
  assert_eq(json_string("a\nb"), "\"a\\nb\"")
}

///|
test "signature json carries the documented fields" {
  let data = ascii_bytes("hello world")
  let signature = sign_bytes(data[:], block_size=256, strong_len=8)
  let line = render_signature_json(
    signature,
    "hello.txt",
    sha256_hex(data[:]),
    xxh64_hex(data[:]),
  )
  assert_eq(line.contains("\"kind\":\"sign\""), true)
  assert_eq(line.contains("\"block_size\":256"), true)
  assert_eq(line.contains("\"strong_len\":8"), true)
  assert_eq(line.contains("\"block_count\":1"), true)
  assert_eq(line.contains("\"signature_bytes\":34"), true)
  assert_eq(
    line.contains("\"sha256_hex\":\"" + sha256_hex(data[:]) + "\""),
    true,
  )
  assert_eq(line.contains("\"xxh64_hex\":\"" + xxh64_hex(data[:]) + "\""), true)
}

///|
test "delta json carries the documented fields" {
  let old = pattern(4096, 51)
  let fresh = pattern(4096, 52)
  let plan = plan_transfer(old[:], fresh[:], block_size=1024)
  let line = render_delta_json(plan, "old.bin", "new.bin")
  assert_eq(line.contains("\"kind\":\"delta\""), true)
  assert_eq(line.contains("\"copy_ops\":"), true)
  assert_eq(line.contains("\"savings_ratio\":0."), true)
}

///|
test "error json is a single machine readable line" {
  let line = render_error_json("format_error", "bad \"magic\"")
  assert_eq(
    line, "{\"kind\":\"error\",\"code\":\"format_error\",\"message\":\"bad \\\"magic\\\"\"}",
  )
}
