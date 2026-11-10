# moon-deltasync

MoonBit 增量传输内核。在两个版本的数据之间只传差异，并在接收端**可验证地**重建出与源逐字节相同的结果。

三个能力在同一套字节格式上闭合：rsync 风格**块签名**、**可逐块校验的 delta**、**内容定义分块与去重**。库的根包只 import `moonbitlang/core`；模块另有一个依赖 `moonbitlang/x@0.5.6`，仅 `cmd/main` 读文件时用到（库本身不碰文件系统）。算法全部来自公开定义，本项目是独立实现，不宣称发明 rsync、Rabin/gear CDC 或 SHA-256。与 MoonBit 相邻包的关系和有限查重结论见 [SOURCES.md](SOURCES.md)。

## 定位与边界

它解决的是和 rsync、增量 OTA、备份去重、CI 构建缓存同一类的问题：数据有历史版本，下一次只需要传「变了的部分」，而正确性必须能被验证，不是被相信。

本库**不做**的事，逐条写清楚，避免过度承诺：

- **不做网络**：没有 socket、没有协议握手、没有断点续传，不做 rsync 的 ssh 通道与并发调度。传输层由调用者决定。
- **不做文件系统**：库的输入输出统一是内存字节（`BytesView` / `Bytes`）；只有 `cmd/main` 碰文件。不读目录树、不做多文件同步、不做内存映射。
- **不做压缩**：可与任意压缩层叠加，本库不感知也不内嵌 deflate/zstd/brotli。
- **不做加密，也不做签名认证**：强校验是**完整性校验**，不是数字签名。它能发现传输或存储造成的损坏，**不能**阻止有能力的篡改者伪造数据并同步伪造指纹。
- 不追求比成熟 C 实现更快。追求的是**确定性、可验证、不做隐藏的第三方依赖、四后端一致**。

## 三个完整工作流

| 使用者与问题 | 输入 → 库内计算 → 输出 | 可运行入口 |
| --- | --- | --- |
| 收到增量包的客户端：这个 delta 能不能安全落到本地？ | 旧数据 + 服务端给的 delta → 反序列化、重放 `COPY`/`COPY_RUN`/`LITERAL`、逐 op 校验、末尾再验整体摘要 → 新数据 + 结论（成功，或第几块失败） | `verified_update`；`examples/corruption_check` |
| 发布方 / 服务端：这次更新实际要传多少字节？ | 客户端签名 + 新版本 → 弱校验分桶、滑窗匹配、规划、规范化 → `DDLT` 字节流 + 字节数与节省比例 | `plan_transfer` / `plan_from_signature`；`examples/version_upgrade` |
| 备份 / 构建缓存：两个版本重复了多少？ | 两个版本的对象 → 内容定义分块、指纹索引、引用计数 → `DCHK` manifest + 去重率 + 可重建校验 | `ChunkStore::ingest` / `assemble`；`examples/chunk_dedup` |

第一条是唯一会**拒绝**数据的路径，也是一层的叠加：delta 里每个 `COPY`/`COPY_RUN` 自带所复制内容的强校验（接收端**不需要签名文件**就能逐 op 验证），最后一层是 `DDLT` 头部携带的目标数据 SHA-256。

## 能力概览

- **块签名 `DSIG`**：Adler-32 变体弱校验（模 65521，O(1) 滑动更新）+ SHA-256 前缀强校验，22 字节定长头，解析时校验字段自洽并拒绝尾部多余字节。
- **delta `DDLT` 与逐层校验**：弱校验分桶 + 等块长滑窗，`COPY`/`COPY_RUN` 自带强校验，`LITERAL` 携带新数据；应用时逐 op 校验 + 整体 `content_digest` 校验 + 结构校验，任一层失败即报错。
- **内容定义分块 `DCHK`**：gear hash 单遍切分（默认 2048 / 8192 / 32768），manifest 记录分块参数与块指纹，`root` 由指纹确定性导出。
- **去重块存储**：`ChunkStore` 按指纹存块、按引用计数管理生命周期，`ingest` 报告新增/复用/字节节省。
- **流式签名与分块**：`ByteSource` 拉取式字节源 + `sign_source` / `chunk_source`，一次只持有一个块或一个 chunk，**不需要整份数据在内存里**。这是为数十 GiB 级磁盘镜像、超大备份对象准备的：`sign_bytes` 要求 `BytesView`，那类对象根本装不进内存。
- **delta 链**：`apply_chain(old, deltas)` 跨多个版本逐步应用、逐步校验，某一环的基准版本不对就在该环停下，抛 `ChainError::StepFailed(step, 原因)` 并给出从 0 开始的段号，不会把错误数据喂给下一环。
- **块回收**：`ChunkStore::retain` / `release` / `collect` 用引用计数回收，只删计数归零的块，仍被 manifest 引用的块不会被误删。
- **报告与 CLI**：文本 / JSON / Markdown 三态报告；`sign` / `delta` / `apply` / `chunk` / `verify` 五个子命令，四个支持 `--out` 导出原始字节。

## 环境与快速开始

要求 MoonBit CLI，`moonc >= 0.10.16`。本机使用的工具链在 `D:\moonbit\_tools\moon-0.10.17\bin`，`moon version --all` 实测输出：

```text
moon  0.1.20261023 (3778465 2026-10-23)
moonc v0.10.17+d971670cd (2026-10-23)
moonrun 0.1.20261023 (3778465 2026-10-23)
```

在该目录外使用时，把工具链 bin 放进 `PATH`：

```powershell
$env:PATH = 'D:\moonbit\_tools\moon-0.10.17\bin;' + $env:PATH
```

在项目根目录执行：

```sh
moon check --deny-warn --target all
moon build --target js
moon test  --deny-warn --target js
moon run   examples/version_upgrade  --target js
moon run   examples/chunk_dedup      --target js
moon run   examples/corruption_check --target js
moon run   examples/streaming_sign   --target js
```

JS 后端需要 Node.js；`wasm`、`wasm-gc` 由 `moonrun` 直接执行；native 后端需要 MSVC（`cl.exe`/`clang-cl`），本机未安装，见下文「验证状态」。四个后端必须产生**逐字节相同**的签名、delta 与 manifest（不变量 7）；本机已在 js / wasm / wasm-gc 上跑通，native 由 CI 覆盖。

已发布到 Mooncakes：`niuniu513-ask/moon-deltasync@0.2.1`（MIT）。在另一个包里引用：

```sh
moon add niuniu513-ask/moon-deltasync@0.2.1
```

```moonbit
import {
  "niuniu513-ask/moon-deltasync" @ds,
}
```

也可以把本目录作为工作区模块直接引用，跳过下载。完整公开接口见 [pkg.generated.mbti](pkg.generated.mbti)。

## 四个示例的实际输出

以下是本机实测（`--target js`，工具链同上），不是设计意图的转述：

`examples/version_upgrade` —— 2000 段文本，中间插入一行：

```text
old bytes: 120890
new bytes: 120935
| delta 字节 | 8346 |        复制操作数 2，复制字节 114688，字面量字节 8237，节省比例 0.9310
delta bytes on the wire: 8346
rebuilt bytes: 120935 (verified 14 blocks)
identical to the new version: true
```

`examples/chunk_dedup` —— 两个版本各约 139 KiB，只有一个 generation 标记不同：

```json
{"kind":"chunk","path":"snapshot-1","length":142471,"chunk_count":13,"new_chunks":13,"reused_chunks":0,"stored_bytes":142471,"saved_bytes":0,"root_hex":"e23b35b5…"}
{"kind":"chunk","path":"snapshot-2","length":142471,"chunk_count":13,"new_chunks":1,"reused_chunks":12,"stored_bytes":148786,"saved_bytes":136156,"root_hex":"80b61929…"}
distinct chunks in the store: 14
bytes actually kept: 148786
bytes deduplication avoided: 136156
matches the source: true
```

`examples/corruption_check` —— 同一个 delta 在三种情况下的结局：

```text
intact delta rebuilds 25089 bytes, all checksums agree
damaged delta: rejected: the rebuilt bytes do not match the digest the delta carries
same delta against a different old version: rejected: block 1 does not match the signature
```

`examples/streaming_sign` —— 300 KB 数据按 4 KiB 窗口喂进 `ByteSource`，再与整缓冲入口比对：

```text
streamed signature: 300000 bytes, 37 blocks
identical to the buffered signature: true
streamed manifest: 10 chunks, root 1f28b3754124134af3b85943283cfebb815c3ebd9a7943879810ec2ecded4df0
same root as the buffered manifest: true
```

这个示例是流式入口的验收点：**同样的数据，流式与整缓冲得到同一个签名、同一个 `root`**，不是「差不多」。

最后两行是本文档最有说服力的部分：**篡改被拒绝**，而且拒绝原因是可区分的——整体摘要不符（`DigestMismatch`）与块级不符（`BlockMismatch(1)`）走的是不同构造子。

## 字节格式

四类整数默认**大端**，magic 是 4 字节 ASCII，`version` 固定为 1。以下是实现的实际布局（与 [docs/design.md](docs/design.md) §5 一致，逐字节由测试与外部校验器复核）：

**`DSIG` 签名 v1** — 定长头 22 字节，签名总长 = `22 + block_count * (4 + strong_len)`：

```text
"DSIG"(4) version:u8 block_size:u32 strong_len:u8 total_length:u64 block_count:u32
repeat block_count 次: weak:u32 strong:u8[strong_len]
```

**`DDLT` delta v1** — 头部带目标数据摘要，每个复制 op 自带强校验：

```text
"DDLT"(4) version:u8 block_size:u32 strong_len:u8 new_length:u64 content_digest:u8[32] op_count:u32
repeat op_count 次:
  tag:u8=0 COPY:      block_index:u32 strong:u8[strong_len]
  tag:u8=1 LITERAL:   length:u32 bytes[length]
  tag:u8=2 COPY_RUN:  start:u32 count:u32 strong:u8[strong_len]
```

**`DCHK` manifest v1** — 头部记录分块参数，块长用 varint：

```text
"DCHK"(4) version:u8 min_size:u32 max_size:u32 mask_bits:u8 chunk_count:u32
repeat chunk_count 次: sha256:u8[32] length:varint
root:u8[32]    // = SHA-256(concat(每个块的 32 字节 sha256))
```

三个解析器都会拒绝**尾部多余字节**，而不是忽略它们。`strong_len` 只接受 8 或 16；`block_count` 必须等于 `ceil(total_length / block_size)`。`root` 由块指纹确定性导出，不掺时间戳或随机量。

## 公开 API

按层分组，全部来自 [pkg.generated.mbti](pkg.generated.mbti)（`moon info` 生成，请以它为准）：

| 层 | 入口 |
| --- | --- |
| 签名 | `sign_bytes(input, block_size?, strong_len?) -> FileSignature`、`decode_signature`、`FileSignature::{encode, block_count, block_length, digest_hex}`、`signature_matches` |
| 流式 | `pub(open) trait ByteSource { fn next(Self) -> Bytes? }`、`MemorySource::new(data, window?)`、`sign_source(source, block_size?, strong_len?, total_length?)`、`chunk_source(source, params?)`、便捷包装 `sign_memory` / `chunk_memory`（无条件等于整缓冲入口） |
| delta | `compute_delta(new, signature) -> Delta`、`Delta::encode`、`decode_delta`、`apply_delta(old, delta) -> ApplyResult`、`Delta::{digest_hex, op_count, copy_ops, copied_blocks, copied_bytes, literal_bytes}` |
| 工作流 | `plan_transfer(old, new, block_size?, strong_len?)`、`plan_from_signature(sig, new)`、`verified_update(old, delta_bytes)`、`apply_chain(old, deltas) -> ChainResult raise ChainError`、`TransferPlan::{delta, signature, delta_bytes, new_length, copy_ops, copied_bytes, literal_bytes, savings_ppm}` |
| 分块 | `chunk_boundaries(input, params?)`、`chunk_manifest(input, params?)`、`ChunkManifest::{encode, verify, chunk_count, total_length, unique_chunks, root_hex}`、`decode_manifest` |
| 块存储 | `ChunkStore::{new, ingest, assemble, unique_chunks, stored_bytes, saved_bytes, total_bytes_ingested, references, retain, release, collect}`、`ingest_snapshot(store, input, params?)` |
| 报告 | `render_signature_json(signature, path, content_sha256_hex, content_xxh64_hex)`、`render_delta_json`、`render_apply_json`、`render_chunk_json`、`render_error_json`、`render_plan_text`、`render_plan_markdown`、`ppm_text` |
| 基础 | `sha256`、`sha256_hex`、`sha256_prefix`、`weak_checksum`、`WeakRoll`、`xxh64`、`hex_encode`、`hex_decode`、`constant_time_equal`、`ByteSink` |

`pkg.generated.mbti` 当前暴露 **99 个函数、16 个结构体、1 个 `pub(open)` trait、1 个枚举**，另有 `FormatError` 与 `ChainError` 两个 `suberror`。

三个值得注意的类型细节：`BlockSignature.index` / `weak` 是 `Int32` / `UInt32`；`Delta` 含 `content_digest : Bytes`，`DeltaOp::Copy` 是 `Copy(Int32, Bytes)`（块号 + 该块强校验），`CopyRun(Int32, Int32, Bytes)`，`Literal(Bytes)`；`ChainResult` / `GcReport` 都是只读结果结构（字段见 [docs/usage.md](docs/usage.md) §3）。

## 命令行

```sh
moon-deltasync sign    <path>                       # 签名摘要与统计
moon-deltasync delta   <old> <new>   --out <d>      # 计算 delta，可写出 DDLT 原始字节
moon-deltasync apply   <old> <delta> --out <f>      # 应用并逐块校验，可写出重建结果
moon-deltasync chunk   <path>                       # 分块与去重率报告
moon-deltasync verify  <path> <sha256-hex>          # 全流校验
```

四个子命令的 `--out` 都可省略；省略时只打印 JSON。带 `--out` 时 `sign` / `chunk` / `delta` / `apply` 分别写出 `DSIG` / `DCHK` / `DDLT` / 重建结果。

本仓库里通过 `moon run` 调用：

```sh
moon run cmd/main --target js -- sign  old.txt --out old.dsig
moon run cmd/main --target js -- delta old.txt new.txt --out patch.ddlt
moon run cmd/main --target js -- apply old.txt patch.ddlt --out rebuilt.txt
moon run cmd/main --target js -- chunk new.txt --out new.dchk
```

每条命令向 stdout 打印**一行** JSON。以下是同一对文件（120890 → 120935 字节文本）的实跑输出：

```json
{"kind":"sign","path":"old.txt","total_length":120890,"block_size":8192,"strong_len":16,"block_count":15,"signature_bytes":322,"signature_sha256_hex":"add8904b…","sha256_hex":"d242f2a7…","xxh64_hex":"8d32c2ca93e03df3"}
{"kind":"delta","old":"old.txt","new":"new.txt","new_length":120935,"op_count":3,"copy_ops":2,"copy_blocks":14,"copied_bytes":114688,"literal_bytes":8237,"delta_bytes":8346,"delta_sha256_hex":"7830b34f…","savings_ratio":0.9310}
{"kind":"apply","ok":true,"bytes_written":120935,"blocks_verified":14,"ops_applied":3,"sha256_hex":"970caa0e…"}
{"kind":"chunk","path":"new.txt","length":120935,"chunk_count":4,"unique_chunks":4,"new_chunks":4,"reused_chunks":0,"stored_bytes":120935,"saved_bytes":0,"dedup_ratio":0.0000,"manifest_bytes":190,"root_hex":"ba92558c…"}
{"kind":"verify","ok":true,"sha256_hex":"970caa0e…"}
{"kind":"error","code":"usage","message":"the expected digest is not hexadecimal"}
```

字段含义有几处容易混：

- `signature_bytes` 是 `DSIG` 序列化长度（`322 = 22 + 15 × 20`）。`sha256_hex` 是**被签名内容**的全流 SHA-256，`xxh64_hex` 是同内容的 XXH64，二者让外部脚本可以独立复核内容；`signature_sha256_hex` 则是 `DSIG` 字节本身的哈希，用于比较两份签名是否相同。
- `delta` 行同时给出 `op_count`（op 总数）、`copy_ops`（复制 op 数）、`copy_blocks`（复制的块数）、`copied_bytes`（复制字节）。**op 数与块数不是一回事**：本例 3 个 op 里 2 个是复制，覆盖 14 个块。
- `chunk` 行的 `manifest_bytes` 是 `DCHK` 序列化长度，`dedup_ratio` 是 4 位小数文本；`unique_chunks` / `stored_bytes` / `saved_bytes` 是**存储累计视角**（CLI 每次新建 store，所以等于本文件的数）。
- `savings_ratio` 由整数 ppm 渲染成 4 位小数，**不受浮点后端差异影响**。

四条实测行为，写清楚以免踩坑：

- **四个子命令的 `--out` 都生效**：`sign` 写 `DSIG`、`chunk` 写 `DCHK`、`delta` 写 `DDLT`、`apply` 写重建结果，写的都是**原始字节**而不是 JSON。实测 `sign --out` 得到 322 字节、`chunk --out` 得到 190 字节，与对应 JSON 里的 `signature_bytes` / `manifest_bytes` 一致。
- **`verify` 有两档失败，语义不同**：① 参数个数不是 2、摘要不是合法十六进制或不是 32 字节 → `{"kind":"error","code":"usage",…}` 且**退出码 1**；② 摘要合法但与文件不符 → `{"kind":"verify","ok":false,…}` 且**退出码 0**——这是正常结论（「这份文件不是这个摘要」），不是错误。
- **未知命令与未知参数都返回 `usage` 错误 + 退出码 1**，不会静默丢弃参数（实测 `sign f --bogus` → `unexpected argument: --bogus`）。
- 文件不可读、格式损坏分别走 `read_failed` / `format_error`，退出码 1。

## 不变量

以下 11 条是工程契约，每条都有对应测试（`moon test` 52 项，见「验证状态」）：

1. **重建一致**：任意 `old`、`new`，`apply_delta(old, compute_delta(new, sign_bytes(old)))` 的输出等于 `new`。
2. **规范化**：`compute_delta` 的输出满足「相邻同类 op 已合并」，重新序列化后逐字节相同。
3. **局部性**：`new` 相对 `old` 只改 1% 的块时，`delta_bytes <= 块数*8 + 改动字节 + 16`。
4. **检测损坏（三层）**：① 翻转 delta 中任意一个 LITERAL 字节 → 逐 op 校验或整体摘要拒绝；② 把 `COPY`/`COPY_RUN` 指向内容不同的旧数据 → `BlockMismatch(index)`；③ 翻转或截断 `DDLT` 头部的 `content_digest` → `DigestMismatch`。第三层挡住了字面量与长度字段被改坏这类逐块校验看不见的损坏。
5. **分块稳定**：数据前缀插入 1 字节后，≥ 90% 的块指纹仍复用（默认参数、≥ 1 MiB 输入）。
6. **去重正确**：manifest 重建出的字节与输入相同，`root` 由块指纹确定性导出。
7. **跨后端一致**：相同输入在 `wasm` / `wasm-gc` / `js` / `native` 上的签名、delta、manifest 逐字节相同。
8. **无 panic**：截断、错 magic、错长度、超大 count、错块号等畸形输入全部返回 `FormatError` 诊断。
9. **流式等价**：窗口切成多大都不影响产物（1 / 7 / 1024 / 64 KiB 结果相同）；块大小需一致——`sign_source` 用 `block_size` 或 `total_length?` 指定（给了 `total_length` 就按 `default_block_size(total_length)` 走与 `sign_bytes` 相同的自适应默认，不给且不给 `block_size` 时才默认 8192），而 `sign_memory` 总是把 `data.length()` 作为提示传入，因此**无条件等于 `sign_bytes`**（含空输入与 < 4096 字节的输入）；`chunk_source` / `chunk_memory` 与 `chunk_manifest` **无条件相等**。
10. **链式校验**：`apply_chain` 逐步应用、逐步验证；任何一环用错基准版本都会在该环停下，抛 `ChainError::StepFailed(step, 原因)`——`step` 是从 0 开始的 delta 下标，底层 `FormatError` 原样保留，不会把错误数据交给下一环。
11. **回收安全**：`release` 之后只有引用计数为 0 的块会被 `collect` 删除；仍被某个 manifest 引用的块，`assemble` 之后仍能重建出原字节。

错误类型有两组：`FormatError`（8 个构造子：`BadMagic` / `UnsupportedVersion` / `Truncated` / `BadField` / `TooLarge` / `BlockMismatch` / `UnsupportedOp` / `DigestMismatch`，用于解析与应用）和 `ChainError`（1 个构造子 `StepFailed(Int32, FormatError)`，只由 `apply_chain` 抛出）。两者都有 `message()` 方法：`ChainError::message()` 输出形如 `delta #0 failed: block 1 does not match the signature`。

## 复杂度与上界

| 操作 | 时间 | 额外空间 |
| --- | --- | --- |
| `sign_bytes` | O(n) 单遍 | 签名 = `22 + block_count * (4 + strong_len)` 字节 |
| `sign_source` / `sign_memory` | O(n) 单遍 | **常数**：一次只缓冲一个块（外加签名本身） |
| `compute_delta` | O(新数据长度)，未命中时最多额外 `block_size` 次字节比较 | 弱校验分桶索引 + 输出 delta |
| `apply_delta` | O(新数据长度) | 输出缓冲 |
| `apply_chain` | 各环相加 | 逐环输出缓冲 |
| `chunk_boundaries` / `chunk_manifest` | O(n) 单遍，窗口恒定 | 每块 32 字节指纹 + varint 长度 |
| `chunk_source` / `chunk_memory` | O(n) 单遍 | **常数**：一次只缓冲一个 chunk |

规模上界（越界即 `TooLarge`/`BadField`，不做静默降级）：`block_size ∈ [256, 1 MiB]`，`strong_len ∈ {8, 16}`，`block_count ≤ 1_000_000`，`total_length ≤ 2^40`。未指定 `block_size` 时按长度自适应：`length < 4096` 用 512，否则 8192。

签名与数据成比例，这是 rsync 类方法的固有成本：`strong_len=16`、`block_size=8192` 时签名约为原文的 0.24%。块越小定位越精确、签名越大，这是可配置的取舍。

## 与现有 MoonBit 生态的关系

在 mooncakes 全量索引快照（3,337 个包，`mooncakes-index-20261026.json`）中按名称与描述检索：`rsync`、`delta sync`、`delta encoding`、`rolling hash` **均为 0 命中**；`content-defined` 命中 2 个（`cn-ybm/MoonHashKit`、`xgzh1111/moonchunk`），`deduplicat` 4 个，`content-address` 3 个，`merkle` 3 个。

**这一组数字在 2026-11-09 的在线注册表上已经变了**：在线共 3,665 个包，`rsync` 在名称+描述口径下命中 **1** 个——`YKDshaxing/moonlibsync`（LGPL-2.1-or-later，2026-11-09 发布，自述「Librsync-compatible byte-buffer library and Native single-file CLI」，keywords 含 `librsync`/`delta`/`sync`）。这是目前最接近的相邻项目，因为 librsync 本身就是 rsync 算法的库化实现。`delta sync`、`delta encoding`、`rolling hash` 在在线索引中仍为 0 命中；`content-defined`、`deduplicat` 的在线计数比快照各多 1 个，因为本项目自身已发布进索引。

扩大口径到 `keywords` 字段后，相邻能力更清楚地暴露出来：`yangxixi00/moon_vcdiff`（RFC 3284 VCDIFF 二进制 delta）、`YKDshaxing/moonlibsync`（librsync 兼容）、`bzhangui/moonrestore`（可验证增量备份 + 内容寻址）、`yuzhiblue/moon-diff`（文本 LCS/Myers diff、git patch）、`gaato/*`（流式解压缩 codec）、`zploc/loci`、`ggbond44439/moonloom`、`Yingqingxue/mooncas`、`any07557-wq/moonvcs`。

因此本项目**不宣称**「MoonBit 生态没有增量传输 / 去重 / 内容寻址相关代码」——那是不成立的，librsync 兼容的包与 VCDIFF 编解码器都在。它主张的是：把块签名、可逐块校验的 delta、内容定义分块放在**同一个库、同一套字节格式**里，delta 自带逐 op 强校验与整体 `content_digest`，并在四个后端上逐字节一致；本项目用的是自定义的 `DSIG`/`DDLT`/`DCHK` 格式，与 librsync、VCDIFF 都不互通。逐包比对、检索命令与命中计数见 [SOURCES.md](SOURCES.md)；本库与上述包无代码依赖、无移植关系、无作者背书。

## 验证状态

**本机实测**（2026-11-10，`moonc v0.10.17+d971670cd`）：

| 项目 | 结果 |
| --- | --- |
| `moon check --deny-warn --target all` | 通过，0 warning |
| `moon build --target js` / `--target wasm-gc` | 通过 |
| `moon test --deny-warn --target js` | 52 tests, 52 passed, 0 failed |
| `moon test --deny-warn --target wasm` / `wasm-gc` | 各 52/52 通过 |
| `moon test --target native` | **未在本机运行**：`moon build --target native` 报缺少 MSVC（`cl.exe`/`clang-cl`），由 CI 覆盖 |
| 四个示例 | 全部实跑，输出见上文（`streaming_sign`：300 KB 数据流式签名 37 块、与整缓冲逐字节相同、10 个 chunk 且 `root` 一致） |
| CLI 端到端 | `sign`→`delta`→`apply` 重建结果与新文件 SHA-256 一致；`verify` 与 PowerShell `Get-FileHash` 一致 |
| CLI `--out` 四个子命令 | 全部写出原始字节：`sign` 322 B（= `signature_bytes`）、`chunk` 190 B（= `manifest_bytes`）、`delta` 与 `apply` 同样落地，均与 JSON 内的字节数一致 |
| 代码规模 | 实现 2,554 行 + CLI 231 行 + 测试 712 行 + 示例 221 行 = **3,718 行** `.mbt` |

CI（`.github/workflows/ci.yml`）在 ubuntu-latest 上跑 `check`/`build`/`test --target all`，并用 `moon fmt` + `git diff --exit-code` 与 `moon info` + `git diff --exit-code` 检查格式化与接口文件是否稳定。`main` 上最近若干次运行均为 `success`（`gh run list` 复核，最近一次耗时 36s）。

**外部独立校验器**：`scripts/` 下的 Python 工具按 design.md 语义**独立重写**了弱校验、XXH64、三个格式的解析与 delta 重放，用来交叉验证本实现；它不读本仓库的 `.mbt` 源码。它在 0.2.0 代码上重跑，结论与之前一致——`scripts/verify-report.txt`（2026-11-10 12:29:39，耗时 27.3s）：

| 指标 | 结果 |
| --- | --- |
| 硬断言 | **775 / 775 通过，0 失败** |
| advisory（不计入失败） | 26 / 26 |
| 阻塞项 | **0** |
| 退出码 | **0**（0 = 硬断言全过；1 = 有硬断言失败；2 = 自测通过但 CLI 联调被阻塞） |

分类覆盖 selftest（hash 4、weak 3、format 36、replay 9、planner 5、cdc 4）与 CLI（sign 190、delta 200、apply 80、interop 30、chunk 154、verify 21、malformed 29、chunk-stability 2、cross-backend 7）。其中四条证据特别值得单独看：

- **delta 字节数与校验器自己的独立 rsync 规划器逐字节相等**（10/10 语料，ratio 1.000，最大 96755 B / 2 MiB 语料）——规划质量不是自评出来的。
- **双向互操作 30/30**：它用自己生成的 `DDLT` 喂 CLI `apply`，重建逐字节相同；CLI 产出的 delta 用它的独立重放器也能重建。
- **跨后端 `js` vs `wasm-gc` 7/7 一致**；弱校验与 `zlib.adler32` 逐位一致（含空窗口），滑动更新 20034 次滑窗与直接计算一致。
- **畸形输入 29/29 只报错、不崩溃**。§7.5 分块稳定性与 `DSIG`/`DCHK` 导出两项阻塞均已解除。

复现：在仓库根目录执行 `D:\anaconda3\python.exe scripts\verify_deltasync.py`（或在 `scripts/` 下执行 `--mode auto`）。该报告是**外部佐证**，不是官方验收结论。契约与实现的对齐状态逐条列在 [docs/usage.md](docs/usage.md) §11。

## 发布状态与残余不确定

**已核实的发布事实**（2026-11-10 复核，用 `gh`、mooncakes 注册表与本地发布产物交叉验证）：

- **GitHub**：`niuniu513-ask/moon-deltasync` 是 **PUBLIC** 仓库，默认分支 `main`，本机 `main` 与 `origin/main` 指向同一提交（仓库仍在活跃提交，SHA 会变）。
- **CI**：`gh run list` 显示 `main` 上最近若干次运行均为 `success`，最近一次是「docs: make the type declarations and the --out note match the code」，耗时 36s。
- **Mooncakes**：`niuniu513-ask/moon-deltasync@0.2.1` 已发布（MIT，PUBLIC，未 yank）。注册表回读的 checksum 与本地发布产物 `_build/publish/niuniu513-ask-moon-deltasync-0.2.1.zip` 的 SHA-256 **逐位相同**，可随时用 registry API 复核；`moon.mod` 也是 0.2.1。历史版本 0.1.0 / 0.1.1 / 0.1.2 / 0.2.0 仍在。

仍然只是「未被本文核实」、而不是「已知有问题」的部分：

1. **CI 只看了最近几次运行**：没有逐条回溯全部历史运行结果，也没有核对分支保护、必需检查等仓库设置。
2. **相邻包的实现深度**：`SOURCES.md` 的逐包比对基于**索引元数据**（名称、描述、keywords、许可证、仓库地址），没有阅读任何相邻包的源码或 README 正文，因此不对其能力细节下定论。
3. **检索快照时效**：逐关键词统计基于 2026-10-26 的快照；2026-11-09 的在线注册表为 3,665 个包，中间新增的包（包括 `moonlibsync`）已在上文单独说明，但未对全部新增包重做逐项比对。

## 许可证

MIT，见 [LICENSE](LICENSE)。来源、相邻项目逐项比对与有限查重边界见 [SOURCES.md](SOURCES.md)；使用示例与 API 细节见 [docs/usage.md](docs/usage.md)。
