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
moon run   examples/version_upgrade --target js
moon run   examples/chunk_dedup     --target js
moon run   examples/corruption_check --target js
```

JS 后端需要 Node.js；`wasm`、`wasm-gc` 由 `moonrun` 直接执行；native 后端需要 MSVC（`cl.exe`/`clang-cl`），本机未安装，见下文「验证状态」。四个后端必须产生**逐字节相同**的签名、delta 与 manifest（不变量 7）；本机已在 js / wasm / wasm-gc 上跑通，native 由 CI 覆盖。

作为依赖引用（发布到 mooncakes.io 之后）：

```moonbit
import {
  "niuniu513-ask/moon-deltasync" @ds,
}
```

也可以把本目录作为工作区模块直接引用，跳过下载。完整公开接口见 [pkg.generated.mbti](pkg.generated.mbti)。

## 三个示例的实际输出

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
| delta | `compute_delta(new, signature) -> Delta`、`Delta::encode`、`decode_delta`、`apply_delta(old, delta) -> ApplyResult`、`Delta::{digest_hex, copy_ops, copied_bytes, literal_bytes}` |
| 工作流 | `plan_transfer(old, new, block_size?, strong_len?)`、`plan_from_signature(sig, new)`、`verified_update(old, delta_bytes)`、`TransferPlan::{delta, signature, delta_bytes, new_length, copy_ops, copied_bytes, literal_bytes, savings_ppm}` |
| 分块 | `chunk_boundaries(input, params?)`、`chunk_manifest(input, params?)`、`ChunkManifest::{encode, verify, chunk_count, total_length, unique_chunks, root_hex}`、`decode_manifest` |
| 块存储 | `ChunkStore::{new, ingest, assemble, unique_chunks, stored_bytes, saved_bytes}`、`ingest_snapshot(store, input, params?)` |
| 报告 | `render_signature_json`、`render_delta_json`、`render_apply_json`、`render_chunk_json`、`render_error_json`、`render_plan_text`、`render_plan_markdown`、`ppm_text` |
| 基础 | `sha256`、`sha256_hex`、`sha256_prefix`、`weak_checksum`、`WeakRoll`、`xxh64`、`hex_encode`、`hex_decode`、`constant_time_equal`、`ByteSink` |

两个值得注意的类型细节：`BlockSignature.index` / `weak` 是 `Int32` / `UInt32`；`Delta` 含 `content_digest : Bytes`，`DeltaOp::Copy` 是 `Copy(Int32, Bytes)`（块号 + 该块强校验），`CopyRun(Int32, Int32, Bytes)`，`Literal(Bytes)`。

## 命令行

```sh
moon-deltasync sign    <path>                       # 签名摘要与统计
moon-deltasync delta   <old> <new>   --out <d>      # 计算 delta，可写出 DDLT 原始字节
moon-deltasync apply   <old> <delta> --out <f>      # 应用并逐块校验，可写出重建结果
moon-deltasync chunk   <path>                       # 分块与去重率报告
moon-deltasync verify  <path> <sha256-hex>          # 全流校验
```

本仓库里通过 `moon run` 调用：

```sh
moon run cmd/main --target js -- delta old.txt new.txt --out patch.ddlt
moon run cmd/main --target js -- apply old.txt patch.ddlt --out rebuilt.txt
```

每条命令向 stdout 打印**一行** JSON。以下字段是实跑输出，不是示意：

```json
{"kind":"sign","path":"old.txt","total_length":120890,"block_size":8192,"strong_len":16,"block_count":15,"signature_bytes":322,"signature_sha256_hex":"add8904b…"}
{"kind":"delta","old":"old.txt","new":"new.txt","new_length":120935,"copy_ops":2,"copied_bytes":114688,"literal_bytes":8237,"delta_bytes":8346,"delta_sha256_hex":"7830b34f…","savings_ratio":0.9310}
{"kind":"apply","ok":true,"bytes_written":120935,"blocks_verified":14,"ops_applied":3,"sha256_hex":"970caa0e…"}
{"kind":"chunk","path":"new.txt","length":120935,"chunk_count":4,"new_chunks":4,"reused_chunks":0,"stored_bytes":120935,"saved_bytes":0,"root_hex":"ba92558c…"}
{"kind":"verify","ok":true,"sha256_hex":"970caa0e…"}
{"kind":"error","code":"format_error","message":"bad magic: expected DSIG, found 0x01020304"}
```

`signature_bytes` 是 `DSIG` 序列化长度（`322 = 22 + 15 × 20`）。`savings_ratio` 由整数 ppm 渲染成 4 位小数，**不受浮点后端差异影响**。字段名以本文与 `report.mbt` 为准。

三条实测行为，写清楚以免踩坑：

- **`--out` 只对 `delta` 和 `apply` 生效**。`sign --out` 与 `chunk --out` 会被**静默忽略**（返回 0 且不写文件）。需要签名或 manifest 字节时，请调用库的 `FileSignature::encode()` / `ChunkManifest::encode()`。
- **`verify` 的失败不体现在退出码上**：哈希不符或传入非十六进制字符串时，输出 `{"kind":"verify","ok":false,…}` 且**退出码为 0**。判断成败请看 `ok` 字段。参数错误、文件不可读、格式损坏才返回非零（`code` 为 `usage` / `read_failed` / `format_error` / `write_failed`）。
- 未知命令返回 `{"kind":"error","code":"usage",…}` 与退出码 1。

## 不变量

以下 8 条是工程契约，每条都有对应测试（`moon test` 38 项，见「验证状态」）：

1. **重建一致**：任意 `old`、`new`，`apply_delta(old, compute_delta(new, sign_bytes(old)))` 的输出等于 `new`。
2. **规范化**：`compute_delta` 的输出满足「相邻同类 op 已合并」，重新序列化后逐字节相同。
3. **局部性**：`new` 相对 `old` 只改 1% 的块时，`delta_bytes <= 块数*8 + 改动字节 + 16`。
4. **检测损坏（三层）**：① 翻转 delta 中任意一个 LITERAL 字节 → 逐 op 校验或整体摘要拒绝；② 把 `COPY`/`COPY_RUN` 指向内容不同的旧数据 → `BlockMismatch(index)`；③ 翻转或截断 `DDLT` 头部的 `content_digest` → `DigestMismatch`。第三层挡住了字面量与长度字段被改坏这类逐块校验看不见的损坏。
5. **分块稳定**：数据前缀插入 1 字节后，≥ 90% 的块指纹仍复用（默认参数、≥ 1 MiB 输入）。
6. **去重正确**：manifest 重建出的字节与输入相同，`root` 由块指纹确定性导出。
7. **跨后端一致**：相同输入在 `wasm` / `wasm-gc` / `js` / `native` 上的签名、delta、manifest 逐字节相同。
8. **无 panic**：截断、错 magic、错长度、超大 count、错块号等畸形输入全部返回 `FormatError` 诊断。

`FormatError` 有 8 个构造子：`BadMagic` / `UnsupportedVersion` / `Truncated` / `BadField` / `TooLarge` / `BlockMismatch` / `UnsupportedOp` / `DigestMismatch`，并提供 `message()` 取人读文本。

## 复杂度与上界

| 操作 | 时间 | 额外空间 |
| --- | --- | --- |
| `sign_bytes` | O(n) 单遍 | 签名 = `22 + block_count * (4 + strong_len)` 字节 |
| `compute_delta` | O(新数据长度)，未命中时最多额外 `block_size` 次字节比较 | 弱校验分桶索引 + 输出 delta |
| `apply_delta` | O(新数据长度) | 输出缓冲 |
| `chunk_boundaries` / `chunk_manifest` | O(n) 单遍，窗口恒定 | 每块 32 字节指纹 + varint 长度 |

规模上界（越界即 `TooLarge`/`BadField`，不做静默降级）：`block_size ∈ [256, 1 MiB]`，`strong_len ∈ {8, 16}`，`block_count ≤ 1_000_000`，`total_length ≤ 2^40`。未指定 `block_size` 时按长度自适应：`length < 4096` 用 512，否则 8192。

签名与数据成比例，这是 rsync 类方法的固有成本：`strong_len=16`、`block_size=8192` 时签名约为原文的 0.24%。块越小定位越精确、签名越大，这是可配置的取舍。

## 与现有 MoonBit 生态的关系

在 mooncakes 全量索引快照（3,337 个包，`mooncakes-index-20261026.json`）中按名称与描述检索：`rsync`、`delta sync`、`delta encoding`、`rolling hash` **均为 0 命中**；`content-defined` 命中 2 个（`cn-ybm/MoonHashKit`、`xgzh1111/moonchunk`），`deduplicat` 4 个，`content-address` 3 个，`merkle` 3 个。

扩大口径到 `keywords` 字段后，相邻能力更清楚地暴露出来：`yangxixi00/moon_vcdiff`（RFC 3284 VCDIFF 二进制 delta）、`bzhangui/moonrestore`（可验证增量备份 + 内容寻址）、`yuzhiblue/moon-diff`（文本 LCS/Myers diff、git patch）、`gaato/*`（流式解压缩 codec）、`zploc/loci`、`ggbond44439/moonloom`、`Yingqingxue/mooncas`、`any07557-wq/moonvcs`。

因此本项目**不宣称**「MoonBit 生态没有增量传输 / 去重 / 内容寻址相关代码」——那是不成立的。它主张的是：把块签名、可逐块校验的 delta、内容定义分块放在**同一个库、同一套字节格式**里，并在四个后端上逐字节一致。逐包比对、检索命令与命中计数见 [SOURCES.md](SOURCES.md)；本库与上述包无代码依赖、无移植关系、无作者背书。

## 验证状态与已知不一致

**本机实测**（2026-11-09，`moonc v0.10.17+d971670cd`）：

| 项目 | 结果 |
| --- | --- |
| `moon check --deny-warn --target all` | 通过，0 warning |
| `moon build --target js` / `--target wasm-gc` | 通过 |
| `moon test --deny-warn --target js` | 38 tests, 38 passed, 0 failed |
| `moon test --deny-warn --target wasm` / `wasm-gc` | 各 38/38 通过 |
| `moon test --target native` | **未在本机运行**：`moon build --target native` 报缺少 MSVC（`cl.exe`/`clang-cl`），由 CI 覆盖 |
| 三个示例 | 全部实跑，输出见上文 |
| CLI 端到端 | `sign`→`delta`→`apply` 重建结果与新文件 SHA-256 一致；`verify` 与 PowerShell `Get-FileHash` 一致 |

CI（`.github/workflows/ci.yml`）在 ubuntu-latest 上跑 `check`/`build`/`test --target all`，并用 `moon fmt` + `git diff --exit-code` 与 `moon info` + `git diff --exit-code` 检查格式化与接口文件是否稳定。

**外部独立校验器**：`scripts/` 下的 Python 工具按 design.md 语义**独立重写**了弱校验、XXH64、三个格式的解析与 delta 重放，用来交叉验证本实现。它当前**未全绿**：`scripts/verify-report.txt` 最新一版为硬断言 429/460 通过、31 失败、3 阻塞、退出码 1。失败项**全部**是 `docs/design.md` §8.1 的示例字段名与本实现不一致造成的结构断言（例如 §8.1 的 sign 示例含 `sha256_hex`/`xxh64_hex`，实现不输出；`op_count`/`copy_blocks` 实际为 `copy_ops`/`copied_bytes`；`unique_chunks`/`dedup_ratio`/`manifest_bytes` 实际为 `new_chunks`/`reused_chunks`/`stored_bytes`/`saved_bytes`），不含算法或重建类失败（`cli-apply`、`cli-interop` 的硬断言全通过）。3 个阻塞项都源于 CLI 不导出 `DSIG`/`DCHK` 字节（即上文 `--out` 的行为）。

该报告由第三方校验器生成，是**外部佐证**，不是官方验收结论；数字随校验器与契约同步修订而变动，引用前请重跑 `python scripts/verify_deltasync.py` 取当时的值。契约与实现仍有一批需要收敛的措辞差异，集中列在 [docs/usage.md](docs/usage.md) 末尾的「待校准」一节。

## 待确认

本地无法核实、因此不写成结论的事项：

1. **远端仓库状态**：本机 `git` 记录显示仓库已初始化、`origin` 为 `https://github.com/niuniu513-ask/moon-deltasync.git`、`refs/heads/main` 与 `refs/remotes/origin/main` 指向同一提交（`353ae62`，reflog 14 条）。但本会话无外网，无法向 GitHub 核对远端是否可访问、CI 是否已运行，故不表述为「已推送成功」。
2. **mooncakes 发布状态**：该包不在 2026-10-26 的索引快照中（快照时点未发布）；当前是否已发布未核实，`moon add` 在确认前不保证可用。

## 许可证

MIT，见 [LICENSE](LICENSE)。来源、相邻项目逐项比对与有限查重边界见 [SOURCES.md](SOURCES.md)；使用示例与 API 细节见 [docs/usage.md](docs/usage.md)。
