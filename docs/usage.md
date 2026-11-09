# 使用指南

本文说明 `moon-deltasync` 的公开用法。语义契约见 [design.md](design.md)，接口清单以 [pkg.generated.mbti](../pkg.generated.mbti) 为准。本文的每个 API 调用形式都取自仓库中可编译的 `examples/` 与 `public_test.mbt`，数字是 `--target js` 的实跑输出。

## 1. 三种入口，选一个

| 你的角色 | 你需要先有 | 你要的产出 |
| --- | --- | --- |
| 接收方，手里只有旧数据 | 旧数据 + 对方给的 `DDLT` 字节流 | 新数据 + 「每个 op 都通过强校验且整体摘要一致」的结论 |
| 发布方，手里有旧签名和新版本 | 客户端签名（或已解析的 `FileSignature`）+ 新版本 | 可发送的 `DDLT` 字节流 + 字节数统计 |
| 备份/缓存，手里有两个版本 | 版本 A、版本 B 的字节 | `DCHK` manifest + 去重率 + 可重建校验 |

三者都不做 I/O：入口和出口都是内存字节。`BytesView` 用 `bytes[:]` 切片取得，不复制数据。

## 2. 最短可用片段

```moonbit
// 发布方：一次调用完成签名 + delta
let plan = @ds.plan_transfer(old[:], fresh[:])
let wire = plan.delta_bytes()      // 要发送的 DDLT 字节

// 接收方：解码 + 逐 op 校验 + 整体摘要校验
let result = @ds.verified_update(old[:], wire[:])
println(result.bytes_written)      // 重建字节数
println(result.digest_hex)         // 重建结果的 SHA-256
```

`plan_transfer(old, new, block_size?, strong_len?)` 在需要固定块大小时传可选参数，例如 `block_size=256`——小文件用小块的写法见 `public_test.mbt`。

## 3. 类型速查

字段名与类型来自 `pkg.generated.mbti`（`moon info` 生成）：

```moonbit
pub struct FileSignature { block_size : Int32, strong_len : Int32, total_length : Int32, blocks : Array[BlockSignature] }
pub struct BlockSignature { index : Int32, weak : UInt32, strong : Bytes }

pub struct Delta { block_size : Int32, strong_len : Int32, new_length : Int32, content_digest : Bytes, ops : Array[DeltaOp] }
pub enum DeltaOp { Copy(Int32, Bytes), CopyRun(Int32, Int32, Bytes), Literal(Bytes) }

pub struct ApplyResult { bytes_written : Int32, blocks_verified : Int32, ops_applied : Int32, digest_hex : String, output : Bytes }

pub struct ChunkParams { min_size : Int32, max_size : Int32, mask_bits : Int32 }
pub struct ChunkRef { digest : Bytes, length : Int32 }
pub struct ChunkManifest { params : ChunkParams, chunks : Array[ChunkRef], root : Bytes }

pub struct IngestReport { total_bytes : Int32, chunk_count : Int32, new_chunks : Int32, reused_chunks : Int32, unique_bytes : Int32, manifest : ChunkManifest }
pub struct SnapshotReport { total_bytes : Int32, chunk_count : Int32, new_chunks : Int32, reused_chunks : Int32, stored_bytes : Int32, saved_bytes : Int32, root_hex : String }
pub struct TransferPlan { signature : FileSignature, delta : Delta, new_length : Int32, delta_bytes : Int32 }
```

两个容易踩的类型细节：

- **`DeltaOp` 的复制 op 自带强校验**：`Copy(块号, 该块强校验)`、`CopyRun(起始块, 块数, 连续块拼接后的强校验)`。接收端因此**不需要签名文件**就能逐 op 验证。
- **`TransferPlan` 里 `delta_bytes` 有两种形态**：字段 `delta_bytes : Int32` 是字节数，方法 `plan.delta_bytes()` 返回序列化后的 `Bytes`。取值时看清是属性还是调用。

## 4. 接收方：应用一个 delta

这是唯一会拒绝数据的路径，也是整个库的验收点。

```moonbit
let result = @ds.verified_update(old[:], delta_bytes[:])          // 解码 + 应用 + 校验
// 或者分两步，自己看中间结构：
let delta = @ds.decode_delta(delta_bytes[:])
let result = @ds.apply_delta(old[:], delta)
```

`apply_delta` 的校验是**三层**，任一层失败都抛 `FormatError`，不返回「尽力而为」的字节：

1. 逐 op：重算被复制内容的强校验，与 op 里记录的不一致 → `BlockMismatch(index)`。
2. 整体：重算输出的 SHA-256，与 `DDLT` 头部的 `content_digest` 不一致 → `DigestMismatch`。
3. 结构：越界块号、未知 op tag、截断、尾部多余字节 → `UnsupportedOp` / `Truncated` / `BadField`。

第 2 层挡住的是第 1 层看不见的损坏：`LITERAL` 载荷被改、`new_length`/`length` 字段被改。实测输出把三种结局分得很清楚：

```text
intact delta rebuilds 25089 bytes, all checksums agree
damaged delta: rejected: the rebuilt bytes do not match the digest the delta carries
same delta against a different old version: rejected: block 1 does not match the signature
```

如果签名是缓存的、跨请求复用的，先用 `signature_matches(signature, old[:]) -> Bool` 确认旧数据没变，再算 delta。

## 5. 发布方：算一个 delta

```moonbit
let plan = @ds.plan_transfer(old[:], fresh[:])            // 签名 + delta，一次完成
// 服务端缓存了客户端签名时，省掉重新签名：
let plan = @ds.plan_from_signature(signature, fresh[:])

plan.new_length()      // 新数据字节数
plan.copy_ops()        // 复制 op 个数
plan.copied_bytes()    // 从旧数据复制的字节
plan.literal_bytes()   // 需要随 delta 传输的字面量字节
plan.delta_bytes()     // DDLT 序列化字节
plan.savings_ppm()     // 节省比例，整数 ppm
@ds.ppm_text(plan.savings_ppm())   // 渲染成 "0.9310" 这样的四位小数文本
```

三点值得先知道：

- **输出是规范化的**：相邻同类 op 必须合并，且 op 覆盖长度之和 == `new_length`（不变量 2）。同一 `(old, new)` 只产生**唯一** delta 字节串，可以当缓存键。
- **比例用整数 ppm 而不是浮点**：`savings_ppm()` 返回 `Int32`，`ppm_text` 渲染成固定 4 位小数。这样同一输入在四个后端打印出完全相同的文本——浮点比例会在最后一位上分化，报告就失去可复现性。
- **滑窗在新数据上**：实现把窗口滑过**新版本**，逐个窗口去旧的块签名表里查。命中就发 `COPY`（连续命中合并为 `COPY_RUN` 并核对内容确实连续），未命中累积成 `LITERAL`。复杂度 O(新数据长度)。

## 6. 备份/缓存：分块与去重

```moonbit
let store = @ds.ChunkStore::new()
let report_a = @ds.ingest_snapshot(store, first[:])    // 第一个版本：全部是新增
let report_b = @ds.ingest_snapshot(store, second[:])   // 第二个版本：大部分复用

report_b.reused_chunks   // 复用的块数
report_b.new_chunks      // 真正新增的块数
report_b.saved_bytes     // 去重省下的字节
store.stored_bytes()     // 实际占用
store.unique_chunks()    // 去重后的块数

// 重建才证明去重没丢东西
let manifest = @ds.chunk_manifest(second[:])
let rebuilt  = store.assemble(manifest)                // Array 缺块会抛 FormatError
```

- 默认参数 `ChunkParams::default()` = `min_size 2048`、`max_size 32768`、`mask_bits 13`（期望块长 `2^13 = 8192`）。可用 `ChunkParams::new(min_size=..., max_size=..., mask_bits=...)` 覆盖，约束是 `min_size ≥ 64`、`max_size ≥ min_size`、`mask_bits ∈ [1, 24]`，越界抛 `BadField`。
- `chunk_boundaries(input[:], params?)` 只返回 `Array[(start, end)]`，想看切点而不建 manifest 时用它。
- manifest 自带 `params`，`ChunkManifest::verify(input[:])` 用同一组参数重算 `root` 并比对；参数不同的两份 manifest 不能混用。
- `unique_chunks()` 是 manifest 视角的去重块数，`ChunkStore::unique_chunks()` 是存储视角；比较两者能看出本次快照复用了多少。

实测（`examples/chunk_dedup`，两个约 139 KiB 版本，只有一处 generation 标记不同）：第一个版本 13 块全部新增，第二个版本 13 块中复用 12、新增 1，`saved_bytes 136156`，重建哈希与源一致。

## 7. 错误处理

所有可出错的地方收敛到一个 `suberror FormatError`，8 个构造子：

```moonbit
pub suberror FormatError {
  BadMagic(String)          // magic 不对，消息里带 4 字节预览
  UnsupportedVersion(Int32) // 版本号不认识
  Truncated(Int32)          // 在指定偏移处截断
  BadField(String)          // 字段非法，如 strong_len 不是 8/16、尾部多余字节
  TooLarge(String)          // 越界，如 block_size、block_count、total_length
  BlockMismatch(Int32)      // 第 index 块与 op 记录的强校验不符
  UnsupportedOp(Int32)      // delta 的 op tag 不认识
  DigestMismatch            // 整体摘要不符（LITERAL 或长度字段被改坏）
}
```

`error.message()` 给出人读文本。按构造子区分恢复策略：`BlockMismatch` 说明旧数据或 delta 内容坏了，`DigestMismatch` 说明重建结果整体不对，`BadMagic`/`Truncated` 说明对端发的东西根本不是这个格式。

```moonbit
let outcome = try {
  let result = @ds.verified_update(old[:], wire[:])
  "ok \{result.bytes_written}"
} catch {
  error => "rejected: \{error.message()}"
}
```

## 8. 报告与命令行

报告渲染器把同样的数字输出成三种形态：`render_signature_json` / `render_delta_json` / `render_apply_json` / `render_chunk_json` / `render_error_json`（单行 JSON）、`render_plan_text`（终端）、`render_plan_markdown`（PR 评论里的表格）。

```sh
moon-deltasync sign    <path>
moon-deltasync delta   <old> <new>   --out <d>
moon-deltasync apply   <old> <delta> --out <f>
moon-deltasync chunk   <path>
moon-deltasync verify  <path> <sha256-hex>
```

本仓库中：

```sh
moon run cmd/main --target js -- sign   old.txt
moon run cmd/main --target js -- delta  old.txt new.txt --out patch.ddlt
moon run cmd/main --target js -- apply  old.txt patch.ddlt --out rebuilt.txt
moon run cmd/main --target js -- chunk  new.txt
moon run cmd/main --target js -- verify new.txt <64-hex>
```

`--target` 可取 `wasm`、`wasm-gc`、`js`、`native`（native 需 MSVC）。

### 8.1 五种 JSON 行的实际字段

以下是实跑输出（120890 → 120935 字节的文本对，省略长哈希）：

```json
{"kind":"sign","path":"old.txt","total_length":120890,"block_size":8192,"strong_len":16,"block_count":15,"signature_bytes":322,"signature_sha256_hex":"add8904b…"}
{"kind":"delta","old":"old.txt","new":"new.txt","new_length":120935,"copy_ops":2,"copied_bytes":114688,"literal_bytes":8237,"delta_bytes":8346,"delta_sha256_hex":"7830b34f…","savings_ratio":0.9310}
{"kind":"apply","ok":true,"bytes_written":120935,"blocks_verified":14,"ops_applied":3,"sha256_hex":"970caa0e…"}
{"kind":"chunk","path":"new.txt","length":120935,"chunk_count":4,"new_chunks":4,"reused_chunks":0,"stored_bytes":120935,"saved_bytes":0,"root_hex":"ba92558c…"}
{"kind":"verify","ok":true,"sha256_hex":"970caa0e…"}
{"kind":"error","code":"format_error","message":"bad magic: expected DSIG, found 0x01020304"}
```

- `signature_bytes` 是 `DSIG` 序列化长度：`322 = 22 + 15 × 20`（22 字节定长头，每块 `weak 4 + strong 16`）。
- `savings_ratio` 是**字节数比例** `1 - delta_bytes/new_length`，由整数 ppm 渲染，不含协议开销，也不是与 rsync 的对比。
- **`sign` 行只有 `signature_sha256_hex`，没有文件内容的 `sha256_hex`/`xxh64_hex`**。要文件哈希用 `verify` 或库里的 `sha256_hex`。

### 8.2 三条容易踩的 CLI 行为

1. **`--out` 只对 `delta` 和 `apply` 生效**。`sign --out` 与 `chunk --out` 被**静默忽略**：返回 0、不写文件、不报错。需要 `DSIG` 或 `DCHK` 字节时调用库的 `FileSignature::encode()` / `ChunkManifest::encode()`，目前没有 CLI 出口。
2. **`verify` 的失败不改变退出码**：哈希不符、或传了非十六进制/长度不对的字符串，都输出 `{"kind":"verify","ok":false,…}` 且**退出码 0**。判断成败只看 `ok`。退出码 1 只用于 `usage` / `read_failed` / `write_failed` / `format_error`。
3. **未知命令**返回 `{"kind":"error","code":"usage","message":"unknown command: …"}`，退出码 1。

## 9. 实测样例

同一个库在不同数据上的表现差别很大，这两个都值得看：

| 语料 | 规模 | delta | 节省比例 | 说明 |
| --- | --- | --- | --- | --- |
| 结构化文本，中间插入一行 | 120890 → 120935 | 8346 | 0.9310 | 典型文档编辑，复制 114688 字节、字面量 8237 字节 |
| 高熵随机字节，插入 20 字节 + 改 5 字节 | 200000 → 200020 | 114822 | 0.4259 | 200 KB 随机数据的签名只有 522 字节，但内容不可复用，delta 仍接近全量 |

第二行不是缺陷：rsync 类方法节省的是**重复内容**，随机数据没有重复内容可省。`savings_ratio` 接近 0 时应该考虑换块大小，或者干脆直接传整份文件。

## 10. 边界与常见误用

- **`weak` 不是校验**：它只用于把候选块缩小到常数个，真正的判断在 `strong`。不要只比 `weak` 就接受数据。
- **强校验不是签名**：SHA-256 前缀和整体摘要能发现损坏，不能证明来源。需要身份认证就外加固签名，本库不提供。
- **`sha256_hex` 一致 ≠ 某个块也对**：它只说明整体输出与预期一致；逐块结论看 `blocks_verified` 与是否抛错。
- **不要用 XXH64 做安全判断**：它是快速指纹，用于分块索引与报告，design.md §6.2 明确写了「不用于安全用途」。
- **输入全是内存字节**：不做文件系统、不做内存映射、不做流式增量解析；超大对象要调用方自己切分，切分方式会影响去重率。
- **畸形输入必须报错而不是崩溃**（不变量 8）：如果你在封装里遇到某个输入导致 panic，那是实现的 bug，不是用法问题。
- **四个后端结果必须逐字节相同**（不变量 7）：`js` 与 `native` 的 delta 字节不同就是缺陷，不能当成「实现差异」放过。
- **`verify` 的退出码不代表业务成功**：见 8.2 第 2 条，脚本里请解析 `ok`。

## 11. 契约与实现的差异（供回填 design.md）

以下是逐条核对代码后确认的差异。本文档按**实现**记录；`design.md` 的对应位置需要修，列表留在此处便于复查：

| design.md 位置 | 现文 | 实际 |
| --- | --- | --- |
| §8.1 sign 示例 | 含 `sha256_hex`、`xxh64_hex` | 不输出这两个字段 |
| §8.1 delta 示例 | `op_count`、`copy_blocks` | `copy_ops`、`copied_bytes` |
| §8.1 chunk 示例 | `unique_chunks`、`dedup_ratio`、`manifest_bytes` | `new_chunks`、`reused_chunks`、`stored_bytes`、`saved_bytes` |
| §8.1 注 | `verify` 失败 → `error` + 非零退出 | `ok:false` + 退出码 0 |
| §8 注 | `--out` 可导出 `DSIG`/`DDLT` | 只有 `delta`/`apply` 支持；`sign`/`chunk` 静默忽略；`DCHK` 无 CLI 出口 |
| §5.3 `DCHK` 布局 | 头部无参数，块长 `u32` | 头部含 `min_size:u32 max_size:u32 mask_bits:u8`，块长为 `varint` |
| §4 错误 | `FormatError` 7 个构造子 | 8 个（多 `DigestMismatch`） |
| §3 模块表 | 列了 `rolling.mbt` | 不存在；`WeakRoll` 在 `hash.mbt` |
| §6.3 delta 生成 | 「在旧数据长度上滑动窗口」 | 窗口滑过**新数据**，反查旧块签名表 |
| §7 不变量 1 | `apply`/`compute_delta`/`sign` | `apply_delta`/`compute_delta`/`sign_bytes` |

除了上表，`scripts/verify-report.txt` 记录了第三方校验器按 §8.1 断言时发现的同类不一致（硬断言失败项全部来自这几条）。
