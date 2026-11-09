///|
/// The command line entry point.
///
/// Every command prints exactly one JSON line to stdout, as documented in
/// `docs/design.md` §8.1, and never panics on bad input: a malformed file becomes
/// an `{"kind":"error",...}` line and a non zero exit code.
///
/// This file is the only place in the project that touches the file system. The
/// library itself takes and returns bytes, so it stays usable from wasm, from a
/// service worker, or from a test that never opens a file.

///|
suberror CliError {
  /// A machine readable code plus the sentence a human needs.
  Failure(String, String)
}

///|
fn command_args() -> Array[String] {
  let args = @env.args()
  let offset = argument_offset()
  let rest : Array[String] = []
  for index = offset; index < args.length(); index = index + 1 {
    rest.push(args[index])
  }
  rest
}

///|
#cfg(target="js")
fn argument_offset() -> Int32 {
  2
}

///|
#cfg(not(target="js"))
fn argument_offset() -> Int32 {
  1
}

///|
#cfg(target="js")
extern "js" fn exit_process(code : Int32) = "(code) => { process.exit(code) }"

///|
#cfg(not(target="js"))
fn exit_process(code : Int32) -> Unit {
  ignore(code)
}

///|
fn read_bytes(path : String) -> Bytes raise CliError {
  @fs.read_file_to_bytes(path) catch {
    _ => raise Failure("read_failed", "cannot read " + path)
  }
}

///|
fn write_bytes(path : String, bytes : Bytes) -> Unit raise CliError {
  @fs.write_bytes_to_file(path, bytes) catch {
    _ => raise Failure("write_failed", "cannot write " + path)
  }
}

///|
fn main {
  let argv = command_args()
  let outcome : Result[String, (String, String)] = Ok(dispatch(argv)) catch {
    Failure(code, message) => Err((code, message))
  }
  match outcome {
    Ok(line) => println(line)
    Err(failure) => {
      let (code, message) = failure
      println(@ds.render_error_json(code, message))
      exit_process(1)
    }
  }
}

///|
/// Run a library call that may reject its input, and turn the rejection into a
/// command line failure that keeps the library message.
fn[T] recover(body : () -> T raise @ds.FormatError) -> T raise CliError {
  body() catch {
    error => raise Failure("format_error", error.message())
  }
}

///|
fn dispatch(argv : Array[String]) -> String raise CliError {
  if argv.length() == 0 {
    raise Failure("usage", usage_text())
  }
  let command = argv[0]
  if command == "sign" {
    command_sign(argv)
  } else if command == "delta" {
    command_delta(argv)
  } else if command == "apply" {
    command_apply(argv)
  } else if command == "chunk" {
    command_chunk(argv)
  } else if command == "verify" {
    command_verify(argv)
  } else if command == "help" || command == "--help" {
    usage_text()
  } else {
    raise Failure("usage", "unknown command: " + command)
  }
}

///|
fn usage_text() -> String {
  "usage: moon-deltasync <sign|delta|apply|chunk|verify> ...\n" +
  "  sign   <path>\n" +
  "  delta  <old> <new> [--out <delta-file>]\n" +
  "  apply  <old> <delta> [--out <file>]\n" +
  "  chunk  <path>\n" +
  "  verify <path> <sha256-hex>"
}

///|
fn command_sign(argv : Array[String]) -> String raise CliError {
  if argv.length() < 2 {
    raise Failure("usage", "sign needs one path")
  }
  let path = argv[1]
  let bytes = read_bytes(path)
  let signature = recover(() => @ds.sign_bytes(bytes[:]))
  @ds.render_signature_json(signature, path)
}

///|
fn option_value(argv : Array[String], name : String) -> String? {
  for index = 0; index < argv.length(); index = index + 1 {
    if argv[index] == name && index + 1 < argv.length() {
      return Some(argv[index + 1])
    }
  }
  None
}

///|
fn command_delta(argv : Array[String]) -> String raise CliError {
  if argv.length() < 3 {
    raise Failure("usage", "delta needs <old> <new>")
  }
  let old_path = argv[1]
  let new_path = argv[2]
  let old = read_bytes(old_path)
  let fresh = read_bytes(new_path)
  let plan = recover(() => @ds.plan_transfer(old[:], fresh[:]))
  match option_value(argv, "--out") {
    Some(target) => write_bytes(target, plan.delta_bytes())
    None => ()
  }
  @ds.render_delta_json(plan, old_path, new_path)
}

///|
fn command_apply(argv : Array[String]) -> String raise CliError {
  if argv.length() < 3 {
    raise Failure("usage", "apply needs <old> <delta>")
  }
  let old_path = argv[1]
  let delta_path = argv[2]
  let old = read_bytes(old_path)
  let delta_bytes = read_bytes(delta_path)
  let result = recover(() => @ds.verified_update(old[:], delta_bytes[:]))
  match option_value(argv, "--out") {
    Some(target) => write_bytes(target, result.output)
    None => ()
  }
  @ds.render_apply_json(result)
}

///|
fn command_chunk(argv : Array[String]) -> String raise CliError {
  if argv.length() < 2 {
    raise Failure("usage", "chunk needs one path")
  }
  let path = argv[1]
  let bytes = read_bytes(path)
  let store = @ds.ChunkStore::new()
  let report = @ds.ingest_snapshot(store, bytes[:])
  @ds.render_chunk_json(report, path)
}

///|
fn command_verify(argv : Array[String]) -> String raise CliError {
  if argv.length() < 3 {
    raise Failure("usage", "verify needs <path> <sha256-hex>")
  }
  let path = argv[1]
  let expected = argv[2]
  let bytes = read_bytes(path)
  let actual = @ds.sha256_hex(bytes[:])
  let ok = actual == expected
  "{\"kind\":\"verify\",\"ok\":" +
  (if ok { "true" } else { "false" }) +
  ",\"sha256_hex\":\"" +
  actual +
  "\"}"
}
