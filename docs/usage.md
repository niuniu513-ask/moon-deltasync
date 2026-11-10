# 使用指南

本文说明 `moon-deltasync` 的公开用法。语义契约见 [design.md](design.md)，接口清单以 [pkg.generated.mbti](../pkg.generated.mbti) 为准。本文的 API 调用形式取自仓库中可编译的 `examples/` 与 `public_test.mbt`，数字是 `--target js` 的实跑输出。

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

pub struct SnapshotReport {
  total_bytes : Int32, chunk_count : Int32, unique_chunks : Int32,
  new_chunks : Int32, reused_chunks : Int32, stored_bytes : Int32,
  saved_bytes : Int32, manifest_bytes : Int32, dedup_ppm : Int32, root_hex : String,
}

pub struct TransferPlan { signature : FileSignature, delta : Delta, new_length : Int32, delta_bytes : Int32 }

// 流式（stream.mbt）
pub(open) trait ByteSource { fn next(Self) -> Bytes? }
pub struct MemorySource { data : Bytes, mut offset : Int32, window : Int32 }

// 跨版本更新与回收
pub struct ChainResult { steps : Int32, bytes_written : Int32, blocks_verified : Int32, digest_hex : String, output : Bytes }
pub struct GcReport { removed_chunks : Int32, reclaimed_bytes : Int32, remaining_chunks : Int32, remaining_bytes : Int32 }

// 只由 apply_chain 抛出的错误：段号 + 底层原因
pub suberror ChainError { StepFailed(Int32, FormatError) }
```

三个容易踩的类型细节：

- **`DeltaOp` 的复制 op 自带强校验**：`Copy(块号, 该块强校验)`、`CopyRun(起始块, 块数, 连续块拼接后的强校验)`。接收端因此**不需要签名文件**就能逐 op 验证。
- **`Delta` 里有 `content_digest`**：整个 `DDLT` 携带目标数据的 SHA-256，应用完再比对一次。
- **`TransferPlan` 里 `delta_bytes` 有两种形态**：字段 `delta_bytes : Int32` 是字节数，方法 `plan.delta_bytes()` 返回序列化后的 `Bytes`。取值时看清是属性还是调用。

## 4. 接收方：应用一个 delta

这是唯一会拒绝数据的路径，也是整个库的验收点。

```moonbit
let result = @ds.verified_update(old[:], delta_bytes[:])          // 解码 + 应用 + 校验
// 或者分两步，自己看中间结构：
let delta = @ds.decode_delta(delta_bytes[:])
let result = @ds.apply_delta(old[:], delta)
```

校验是**三层**，任一层失败都抛 `FormatError`，不返回「尽力而为」的字节：

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

plan.new_length()            // 新数据字节数
plan.copy_ops()              // 复制 op 个数
plan.copied_bytes()          // 从旧数据复制的字节
plan.literal_bytes()         // 需要随 delta 传输的字面量字节
plan.delta_bytes()           // DDLT 序列化字节
plan.savings_ppm()           // 节省比例，整数 ppm
@ds.ppm_text(plan.savings_ppm())   // 渲染成 "0.9310" 这样的四位小数文本

// 需要更细的 op 结构时，从计划里取 delta：
plan.delta().op_count()      // op 总数（复制 + 字面量）
plan.delta().copy_ops()      // 复制 op 数
plan.delta().copied_blocks() // 复制的块数
```

**`op_count` 与 `copied_blocks` 不是一回事**：一个 `COPY_RUN` 只算 1 个 op，但可能覆盖几百个块。实测同一对文件：`op_count 3`（2 个复制 + 1 个字面量）、`copy_ops 2`、`copy_blocks 14`。

三点值得先知道：

- **输出是规范化的**：相邻同类 op 必须合并，且 op 覆盖长度之和 == `new_length`（不变量 2）。同一 `(old, new)` 只产生**唯一** delta 字节串，可以当缓存键。
- **比例用整数 ppm 而不是浮点**：`savings_ppm()` 返回 `Int32`，`ppm_text` 渲染成固定 4 位小数。这样同一输入在四个后端打印出完全相同的文本——浮点比例会在最后一位上分化，报告就失去可复现性。
- **滑窗在新数据上**：实现把窗口滑过**新版本**，逐个窗口去旧的块签名表里查。命中就发 `COPY`（连续命中合并为 `COPY_RUN` 并核对内容确实连续），未命中累积成 `LITERAL`。复杂度 O(新数据长度)。

这也解释了块边界对齐的影响：只翻转 1 个字节时，只有受影响的块变成字面量（实测 200000 字节、翻 1 字节 → delta 8301、节省 0.9585）；而在中间**插入** 20 字节会让其后所有固定块边界错位，可复用的块骤减（同一份数据插入 20 字节 + 改 5 字节 → delta 114822、节省 0.4259）。固定块大小是这条路线的固有取舍，不是实现缺陷。

## 6. 备份/缓存：分块与去重

```moonbit
let store = @ds.ChunkStore::new()
let report_a = @ds.ingest_snapshot(store, first[:])    // 第一个版本：全部是新增
let report_b = @ds.ingest_snapshot(store, second[:])   // 第二个版本：大部分复用

report_b.chunk_count      // 本次快照的块数
report_b.new_chunks       // 本次真正新增的块
report_b.reused_chunks    // 本次复用的块
report_b.unique_chunks    // 存储里的去重块数（累计视角）
report_b.stored_bytes     // 实际占用（累计视角）
report_b.saved_bytes      // 去重省下的字节（累计视角）
report_b.manifest_bytes   // 本次 manifest 的 DCHK 序列化长度
report_b.dedup_ppm        // 去重比例，整数 ppm，用 ppm_text 渲染

// 重建才证明去重没丢东西
let manifest = @ds.chunk_manifest(second[:])
let rebuilt  = store.assemble(manifest)                // 缺块会抛 FormatError
```

- **累计视角 vs 本次视角**：`new_chunks` / `reused_chunks` / `chunk_count` 是**本次快照**的统计；`unique_chunks` / `stored_bytes` / `saved_bytes` / `dedup_ppm` 是**整个 store** 的累计值（`dedup_ppm = saved_bytes × 10^6 / 累计已摄入字节`）。CLI 每次新建 store，所以命令行输出里两者数值重合；在长期运行的备份进程里必须分清。
- 默认参数 `ChunkParams::default()` = `min_size 2048`、`max_size 32768`、`mask_bits 13`（期望块长 `2^13 = 8192`）。可用 `ChunkParams::new(min_size=..., max_size=..., mask_bits=...)` 覆盖，约束是 `min_size ≥ 64`、`max_size ≥ min_size`、`mask_bits ∈ [1, 24]`，越界抛 `BadField`。
- `chunk_boundaries(input[:], params?)` 只返回 `Array[(start, end)]`，想看切点而不建 manifest 时用它。
- manifest 自带 `params`，`ChunkManifest::verify(input[:])` 用同一组参数重算 `root` 并比对；参数不同的两份 manifest 不能混用。

实测（`examples/chunk_dedup`，两个约 139 KiB 版本，只有一处 generation 标记不同）：第一个版本 13 块全部新增，第二个版本 13 块中复用 12、新增 1，`saved_bytes 136156`，重建哈希与源一致。

## 7. 流式签名与分块

`sign_bytes` / `chunk_manifest` 要 `BytesView`，对测试和小文件没问题，对数十 GiB 的磁盘镜像不可能。流式入口换成拉取式字节源：**库只持有一个块或一个 chunk**，数据怎么来由调用方决定。

```moonbit
// 1) 内存数据，按 777 字节一批交付
let sig_source = @ds.MemorySource::new(data[:], window=777)
let signature = @ds.sign_source(sig_source as &ByteSource, block_size=1024)

// 2) 同一份数据做分块：ByteSource 是消耗品，读完就到底，所以另开一个
let chunk_src = @ds.MemorySource::new(data[:], window=777)
let manifest = @ds.chunk_source(chunk_src as &ByteSource)

// 3) 自己实现 ByteSource，接文件 / socket / 解压流（示意，读盘细节略）
struct FileSource { mut pending : Bytes? }
impl ByteSource for FileSource with fn next(self : FileSource) -> Bytes? {
  // 读到一块返回 Some(block)，读完返回 None
}
let signature = @ds.sign_source(file_source as &ByteSource, block_size=8192)
```

要点：

- **必须显式转 trait 对象**：MoonBit 不会自动把 `MemorySource` 隐式当成 `&ByteSource`，写法是 `source as &ByteSource`。这一步漏了会直接编译失败，不会静默。
- **`window` 是每次 `next` 最多交付多少字节**，默认 64 KiB；`window ≤ 0` 会被当作 64 KiB。窗口大小**不影响产物**——这是不变量 9：1 / 7 / 1024 / 64 KiB 得到同一份 `DSIG` / `DCHK`。
- **`sign_memory` / `chunk_memory`** 是给「数据已在内存、但想走同一条流式代码路径」的便捷包装，省掉建 trait 对象。

> **块大小要一致，但默认值这件事已经解决了。** `sign_bytes` 对 `< 4096` 字节的输入默认用 512（长度自适应），而流式读到最后才知道总长，所以 `sign_source` 自己猜不了。三种写法都能对齐：
> - `sign_source(src, block_size=8192)`：显式指定，两边都按同样块长切。
> - `sign_source(src, total_length=n)`：给出总长提示，`sign_source` 就用 `default_block_size(n)`，与 `sign_bytes` 的自适应默认**完全一致**。
> - `sign_source(src)` 且既无 `block_size` 也无 `total_length`：默认 **8192**。这时只有当数据 ≥ 4096 字节才与 `sign_bytes` 默认值相同；小于 4096 字节（含空输入）会得到不同的 `block_size` 字段（`DSIG` 头部就写着它，所以产物不同）。
>
> **`sign_memory` 总是把 `data.length()` 当提示传进去**，因此它**无条件等于 `sign_bytes`**——空输入、100 字节、10 MiB 都一样，不需要任何额外参数。`chunk_source` / `chunk_memory` 与 `chunk_manifest` 也无条件相等（默认 `ChunkParams` 相同）。

## 8. delta 链：跨版本更新

客户端从 v1 升到 v4，而服务端只有 v1→v2、v2→v3、v3→v4 三段 delta 时，用 `apply_chain` 一次走完，不用自己管中间缓冲：

```moonbit
let result = @ds.apply_chain(v1[:], [d12[:], d23[:], d34[:]])
result.steps            // 应用成功的段数（成功返回时 == deltas.length()）
result.bytes_written    // 最终字节数
result.blocks_verified  // 累计校验通过的块数
result.digest_hex       // 最终结果的 SHA-256
result.output           // 最终字节
```

语义是**逐步应用、逐步验证**（不变量 10）：每一环都调用一次 `verified_update`（解码 + 逐 op 强校验 + 整体摘要校验），通过之后才作为下一环的 `old`。任何一环的基准版本对不上，就在那一环停下，**不会**把错误的中间结果喂给下一环，也不会返回部分成功——所以只要拿到 `ChainResult`，就意味着**全部**段都成功了。

失败时抛的是 `ChainError`，**段号和底层原因都在**：

```moonbit
pub suberror ChainError { StepFailed(Int32, FormatError) }

// 用错基准版本时：
// error.message() == "delta #0 failed: block 1 does not match the signature"
```

两个使用上的注意点：

- **`StepFailed(step, 原因)` 的 `step` 是从 0 开始的 delta 下标**：上例里 `delta #0` 就是 `deltas[0]` 失败，`原因` 是原封不动的 `FormatError`（`BlockMismatch` / `DigestMismatch` / `BadMagic`…），可以继续按构造子分支处理。需要人读文本时用 `ChainError::message()`，它把两段拼成一句话。
- **中间结果全在内存**：`apply_chain` 每段都产生完整的新字节，一次调用的峰值是「当前版本 + 下一版本」。跨很多大版本时，宁可逐段调用并自己落盘。

## 9. 块回收

`ChunkStore` 一直存块会越用越大。显式引用计数让生命周期可控：

```moonbit
let store = @ds.ChunkStore::new()
let m1 = @ds.chunk_manifest(v1[:])
let m2 = @ds.chunk_manifest(v2[:])

let report = store.ingest(v1[:])   // 存入 v1 的块；每块出现一次 → 引用 +1
let key = @ds.hex_encode(m1.chunks[0].digest[:])
store.references(key)              // 这个块现在被引用几次（未知块返回 0）

store.retain(m2)                   // 为 m2 用到的块各 +1
let freed = store.release(m1)      // 为 m1 用到的块各 -1；返回「计数归零的块数」
let gc : @ds.GcReport = store.collect()
gc.removed_chunks; gc.reclaimed_bytes; gc.remaining_chunks; gc.remaining_bytes
```

- **只有引用计数为 0 的块会被 `collect` 删除**（不变量 11）。仍被某个 manifest 引用的块不会被误删，`assemble` 之后仍能重建出原字节。
- **计数是按「块出现次数」算的**，不是按「有几个 manifest 用到它」：同一份数据里同一个块出现两次，`ingest` 之后计数就是 2；因此 `release` 一次只减掉该 manifest 里的出现次数。
- `ingest` 本身就会 retain（新块置 1、已存在则 +1），所以「先 ingest 再 release」是配对的；只想为一份没 ingest 过的 manifest 加引用时才需要显式 `retain`。
- `release` 返回的是**归零块数**，不是立即删除的字节数——真正回收发生在 `collect()`，可以把多次 release 合成一次回收。
- `references` 的参数是**块的 SHA-256 十六进制串**（用 `hex_encode` 从 `ChunkRef.digest` 得到），不是 `Bytes`。

## 10. 错误处理

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

`apply_chain` 抛的是另一个错误类型 `ChainError`，它只有 `StepFailed(step, 原因)` 一个构造子：`step` 是失败的 delta 下标（从 0 起），`原因` 是上面那个 `FormatError` 原样保留。`ChainError::message()` 拼成 `delta #0 failed: block 1 does not match the signature` 这种形式。想按错误种类分支时，先 match `StepFailed(step, cause)` 再 match `cause`。

命令行把这些错误映射成 `code`：

| 情况 | `code` | 退出码 |
| --- | --- | --- |
| 未知命令、未知参数、参数个数不符、摘要不是合法十六进制 / 不是 32 字节 | `usage` | 1 |
| 输入文件读不到、输出文件写不了 | `read_failed` / `write_failed` | 1 |
| 库抛出的任何 `FormatError` | `format_error` | 1 |

`chain` 目前只有库接口、没有子命令，所以 `ChainError` 不会出现在 CLI 输出里。

## 11. 命令行

```sh
moon-deltasync sign    <path>                 [--out dsig]   # 摘要，可导出 DSIG
moon-deltasync delta   <old> <new>            [--out d]      # 计算 delta，可导出 DDLT
moon-deltasync apply   <old> <delta>          [--out f]      # 应用并校验，可写出重建结果
moon-deltasync chunk   <path>                 [--out dchk]   # 分块报告，可导出 DCHK
moon-deltasync verify  <path> <sha256-hex>                   # 全流校验
```

本仓库中：

```sh
moon run cmd/main --target js -- sign  old.txt --out old.dsig
moon run cmd/main --target js -- delta old.txt new.txt --out patch.ddlt
moon run cmd/main --target js -- apply old.txt patch.ddlt --out rebuilt.txt
moon run cmd/main --target js -- chunk new.txt --out new.dchk
moon run cmd/main --target js -- verify new.txt <64-hex>
```

`--target` 可取 `wasm`、`wasm-gc`、`js`、`native`（native 需 MSVC）。

### 11.1 六种 JSON 行的实际字段

以下是同一对文件（120890 → 120935 字节文本）的实跑输出，省略长哈希：

```json
{"kind":"sign","path":"old.txt","total_length":120890,"block_size":8192,"strong_len":16,"block_count":15,"signature_bytes":322,"signature_sha256_hex":"add8904b…","sha256_hex":"d242f2a7…","xxh64_hex":"8d32c2ca93e03df3"}
{"kind":"delta","old":"old.txt","new":"new.txt","new_length":120935,"op_count":3,"copy_ops":2,"copy_blocks":14,"copied_bytes":114688,"literal_bytes":8237,"delta_bytes":8346,"delta_sha256_hex":"7830b34f…","savings_ratio":0.9310}
{"kind":"apply","ok":true,"bytes_written":120935,"blocks_verified":14,"ops_applied":3,"sha256_hex":"970caa0e…"}
{"kind":"chunk","path":"new.txt","length":120935,"chunk_count":4,"unique_chunks":4,"new_chunks":4,"reused_chunks":0,"stored_bytes":120935,"saved_bytes":0,"dedup_ratio":0.0000,"manifest_bytes":190,"root_hex":"ba92558c…"}
{"kind":"verify","ok":true,"sha256_hex":"970caa0e…"}
{"kind":"error","code":"usage","message":"the expected digest is not hexadecimal"}
```

- `signature_bytes` = `DSIG` 序列化长度（`322 = 22 + 15 × 20`）；`sign --out` 写出的文件实测就是 322 字节。
- `sha256_hex` 是**被签名内容**的全流 SHA-256，`xxh64_hex` 是同内容的 XXH64，外部脚本可据此独立复核；`signature_sha256_hex` 是 `DSIG` 字节本身的哈希，用于比较两份签名是否相同。三者不可互换。
- `savings_ratio` = `1 - delta_bytes/new_length`，由整数 ppm 渲染成 4 位小数；`dedup_ratio` 同理，来自 `saved_bytes / 累计已摄入字节`。
- `manifest_bytes` = `DCHK` 序列化长度，`chunk --out` 写出的文件实测与它等长（190 字节）。

### 11.2 四条容易踩的 CLI 行为

1. **四个子命令的 `--out` 都生效**：`sign` 写 `DSIG`、`chunk` 写 `DCHK`、`delta` 写 `DDLT`、`apply` 写重建结果，写的都是**原始字节**而非 JSON。省略 `--out` 时只打印 JSON。
2. **`verify` 有两档失败**：① 参数个数不是 2、摘要不是合法十六进制或不是 32 字节 → `{"kind":"error","code":"usage",…}` + **退出码 1**（实测 `verify f zzzz` → `the expected digest is not hexadecimal`）；② 摘要合法但与文件不符 → `{"kind":"verify","ok":false,…}` + **退出码 0**，这是正常结论（「这份文件不是这个摘要」），脚本里请解析 `ok`。
3. **未知命令与未知参数都是 `usage` 错误 + 退出码 1**（实测 `sign f --bogus` → `unexpected argument: --bogus`），不会静默丢弃参数。
4. **坏输入不 panic**：格式损坏的 delta 返回 `{"kind":"error","code":"format_error","message":"bad magic: expected DSIG, found 0x01020304"}` + 退出码 1，而不是崩溃或部分重建。

## 12. 实测样例

同一份库在不同数据上的表现差别很大，这三行都值得看：

| 语料 | 规模 | delta | 节省比例 | 说明 |
| --- | --- | --- | --- | --- |
| 结构化文本，中间插入一行 | 120890 → 120935 | 8346 | 0.9310 | 典型文档编辑：复制 114688 字节、字面量 8237 字节 |
| 高熵随机字节，翻 1 个字节 | 200000 → 200000 | 8301 | 0.9585 | 只有受影响的块变成字面量（8192 字节），其余全部复用 |
| 高熵随机字节，插入 20 + 改 5 | 200000 → 200020 | 114822 | 0.4259 | 插入让其后块边界整体错位，固定块方案无法再匹配 |

第一、三行的差别不是缺陷：rsync 类方法节省的是**对齐的重复内容**。随机数据本身没有重复可省，而插入会破坏对齐；`savings_ratio` 接近 0 时应该考虑换块大小，或者干脆直接传整份文件。

## 13. 边界与常见误用

- **`weak` 不是校验**：它只用于把候选块缩小到常数个，真正的判断在 `strong`。不要只比 `weak` 就接受数据。
- **强校验不是签名**：SHA-256 前缀和整体摘要能发现损坏，不能证明来源。需要身份认证就外加固签名，本库不提供。
- **`sha256_hex` 一致 ≠ 某个块也对**：它只说明整体输出与预期一致；逐块结论看 `blocks_verified` 与是否抛错。
- **不要用 XXH64 做安全判断**：它是快速指纹，用于分块索引与报告，design.md §6.2 明确写了「不用于安全用途」。
- **输入全是内存字节**：不做文件系统、不做内存映射、不做流式增量解析；超大对象要调用方自己切分，切分方式会影响去重率。
- **畸形输入必须报错而不是崩溃**（不变量 8）：如果你在封装里遇到某个输入导致 panic，那是实现的 bug，不是用法问题。
- **四个后端结果必须逐字节相同**（不变量 7）：`js` 与 `native` 的 delta 字节不同就是缺陷，不能当成「实现差异」放过。
- **`verify` 的退出码不等于「文件正确」**：`ok:false` 时退出码是 0（见 11.2 第 2 条）；只有 `code:"usage"` 之类才是非零。

## 14. 契约对齐状态（逐条复核于 2026-11-10，对应 commit `4b0f12d` + 本轮 stream/chain/gc）

| design.md 位置 | 检查项 | 状态 |
| --- | --- | --- |
| §4 类型声明块 | `Int32`/`UInt32`、`Copy(Int32, Bytes)`、`CopyRun(Int32, Int32, Bytes)`、`Delta.content_digest`、`ChunkManifest.params : ChunkParams` | **已对齐**（照 §4 抄代码现在能编译） |
| §4 错误类型 | `FormatError` 8 个构造子 | **已对齐** |
| §3 模块表 | `WeakRoll` 归在 `hash.mbt`，不再列 `rolling.mbt` | **已对齐** |
| §5.2 `DDLT` 布局 | `content_digest:u8[32]` + 每个复制 op 带 `strong` | **已对齐** |
| §5.3 `DCHK` 布局 | 头部 `min_size`/`max_size`/`mask_bits`，块长 `varint` | **已对齐** |
| §6.3 delta 生成 | 窗口滑过**新数据**、反查旧块签名表 | **已对齐** |
| §8 synopsis | `sign`/`chunk` 也列了 `--out` | **已对齐** |
| §8.1 退出码 | 非法摘要 → `error` + 非零；摘要不匹配 → `ok:false` + 0 | **已对齐**，实测 `zzzz` → `usage` rc=1，错哈希 → `ok:false` rc=0 |
| §8.1 `--out` 说明 | 本节开头与末尾两处说明一致，列出四个子命令各自导出什么 | **已对齐**（原先末尾那句只说 `DSIG`/`DDLT`，已改写） |
| §8.1 sign 示例 | `sha256_hex`、`xxh64_hex`、`signature_bytes 2582` | **已对齐** |
| §8.1 delta 示例 | `op_count`、`copy_ops`、`copy_blocks`、`copied_bytes` | **已对齐**（实测 `3 / 2 / 14 / 114688`） |
| §8.1 chunk 示例 | `unique_chunks`、`dedup_ratio`、`manifest_bytes` | **已对齐**，且 `manifest_bytes` 的算法（`18 + Σ(32 + varint)` + 32）与实测一致 |
| §8.1 apply 示例 | `ops_applied` | **已对齐** |
| §3 模块表（本轮） | 新增 `stream.mbt` 一行，职责写「流式入口 `ByteSource`」 | **已对齐**，文件与 trait 都存在 |
| §4 类型（本轮） | 新类型是否有对应实现 | `ByteSource` / `MemorySource` / `ChainResult` / `GcReport` 均在 `pkg.generated.mbti` 中 |
| §7 不变量 9（流式等价） | 窗口 1 / 7 / 1024 / 64 KiB 产物一致 | **已对齐**（`stream_wbtest.mbt` 10 项测试，全部对比整缓冲结果） |
| §7 不变量 10（链式校验） | 错基准在中间停下并给出段号 | **已对齐**：`ChainError::StepFailed(step, 原因)` 已落地；`sync_wbtest.mbt` 有「a chain of deltas applies step by step」「a broken link in the chain is reported」 |
| §7 不变量 11（回收安全） | 只删零引用块、保留块仍可重建 | **已对齐**（`chunk_wbtest.mbt`「reference counting keeps shared chunks and drops the rest」「a retained snapshot survives a collect」） |
| §7.9 等价性的前提 | 原文只写「窗口多大都与 `sign_bytes` 相同」，缺块大小的前提 | **已对齐**：design.md §7.9 现在写明了前提；代码侧补了 `sign_source(..., total_length?)`（按 `default_block_size` 走同一套自适应默认），`sign_memory` 总是传 `data.length()` 提示，因此无条件等于 `sign_bytes`。另有 4 项新测试固定这一行为 |
| §4 错误类型（本轮） | `ChainError` 是否进了契约 | **已对齐**：design.md §7.10 与代码都有 `StepFailed(Int32, FormatError)` + `message()` |

**未对齐：0 条。** 上表 20 行全部「已对齐」。上一轮的两处（§4 类型声明块、§8.1 末尾 `--out` 注）早在 `4b0f12d` 修掉；本轮唯一待补的 §7.9 前提，design.md 已写入、代码已补 `total_length?` 并用 4 项新测试固定，因此也关掉了。

一点非阻塞的排版瑕疵：design.md §7.9 那两行首尾各有一个多余的直引号 `'`（像编辑残留），不影响语义，可以顺手清掉。

外部校验器在 0.2.0 代码上重跑（`scripts/verify-report.txt`，2026-11-10 12:29:39，硬断言 775/775、阻塞 0、退出码 0）——注意它只覆盖 CLI 与三种格式，本轮新增的流式/链/回收属于 API 层，由 `moon test` 的 52 项覆盖。
