# moon-deltasync 设计文档

本文件是工程契约：代码、测试、示例、外部校验脚本都以这里的类型、格式与不变量为准。修改语义时请同时更新本文件。

## 1. 项目定位

`moon-deltasync` 是纯 MoonBit 的**增量传输内核**：在两个版本的数据之间只传差异，并在接收端可验证地重建出与源**逐字节相同**的结果。

它解决的问题与 rsync / 增量 OTA / 备份去重 / CI 构建缓存是同一类：数据有历史版本，下一次传输只需要传「变了的部分」，而正确性必须能被验证，而不是被相信。

边界（重要，避免过度承诺）：

- 本库**不做网络**、不做文件系统、不做压缩、不做加密。它只做字节到字节的算法与格式。
- 本库不实现 rsync 的 ssh 通道、不做并发调度、不做断点续传协议。
- 强校验是**完整性校验**，不是数字签名：不提供身份认证，也不防篡改者伪造。
- 所有算法都有明确的上界；不追求比成熟 C 实现更快，追求**确定性、可验证、零依赖、四后端一致**。

## 2. 三个完整工作流

| 使用者 | 输入 | 库内计算 | 输出 |
| --- | --- | --- | --- |
| 客户端更新一个文件 | 旧文件原文 + 服务端算出的 delta | 生成签名、应用 delta、逐块强校验 | 新文件 + 校验结论（成功/第几块失败） |
| 服务端响应更新请求 | 客户端签名 + 新文件原文 | 滑动匹配、COPY/LITERAL 规划、估算节省 | delta 字节流 + 传输统计 |
| 备份/缓存去重 | 两个版本的大对象 | 内容定义分块、块指纹索引、引用计数 | manifest + 去重率 + 可重建校验 |

## 3. 模块划分

| 文件 | 职责 |
| --- | --- |
| `foundation.mbt` | 字节工具：小端/大端整数读写、varint、hex 编解码、字节比较 |
| `hash.mbt` | SHA-256（全流与分块）、XXH64（快速指纹）、Adler-32 风格弱校验与滑动更新 `WeakRoll`、常量时间比较 |
| `signature.mbt` | 块签名构建、序列化/反序列化、格式错误类型 |
| `delta.mbt` | delta 生成、序列化/反序列化、应用与逐块校验 |
| `chunk.mbt` | 内容定义分块（gear hash）、manifest、去重块存储、引用计数与回收 |
| `sync.mbt` | 三个工作流的高层封装与统计、delta 链 |
| `stream.mbt` | 流式入口 `ByteSource`：按块/按块读入签名与分块，不需要整块数据在内存里 |
| `report.mbt` | 文本 / JSON / Markdown 三态报告 |
| `cmd/main` | 命令行入口（js / native 后端） |

## 4. 数据类型

```moonbit
pub struct BlockSignature {
  index : Int32         // 块序号，从 0 开始
  weak : UInt32         // 弱校验
  strong : Bytes        // 强校验，长度 = strong_len
}

pub struct FileSignature {
  block_size : Int32
  strong_len : Int32
  total_length : Int32  // 被签名数据的字节数
  blocks : Array[BlockSignature]
}

pub enum DeltaOp {
  Copy(Int32, Bytes)          // 复制第 index 块，并校验它等于 strong
  CopyRun(Int32, Int32, Bytes) // 从 start 起连续 count 块，并校验拼接结果等于 strong
  Literal(Bytes)               // 直接携带新数据
}

pub struct Delta {
  block_size : Int32
  strong_len : Int32
  new_length : Int32
  content_digest : Bytes       // 目标数据的 SHA-256，apply 结束时比对
  ops : Array[DeltaOp]
}

pub struct ChunkParams {
  min_size : Int32
  max_size : Int32
  mask_bits : Int32
}

pub struct ChunkManifest {
  params : ChunkParams        // 分块参数随 manifest 存储，重建才能复现同样的边界
  chunks : Array[ChunkRef]    // sha256 + length
  root : Bytes                // 所有块指纹拼接后的 SHA-256
}
```

错误统一用 `pub suberror FormatError`（8 个构造子：`BadMagic` / `UnsupportedVersion` / `Truncated` / `BadField` / `TooLarge` / `BlockMismatch` / `UnsupportedOp` / `DigestMismatch`），**不允许 panic 出现在公开 API 上**：损坏的输入必须变成诊断信息。

### 4.1 块大小与规模上界（实现即契约）

- `sign_bytes(input, block_size?, strong_len?)` 的默认块大小由 `default_block_size(length)` 决定：`length < 4096` 用 512 字节，否则 8192 字节。
- 允许范围：`block_size ∈ [256, 1 MiB]`，`strong_len ∈ {8, 16}`，`block_count ≤ 1_000_000`，`total_length ≤ 2^40`。
- 越界一律 `TooLarge` / `BadField`，不做截断或静默降级。

## 5. 二进制格式

所有整数除注明外均为**大端**定长；magic 均为 4 字节 ASCII。

### 5.1 签名 `DSIG` v1

```
"DSIG"(4) version:u8=1 block_size:u32 strong_len:u8 total_length:u64 block_count:u32
repeat block_count 次:
  weak:u32
  strong:u8[strong_len]
```

- `strong_len` 只接受 8 或 16。
- 解析时必须校验 `block_count == ceil(total_length / block_size)`，不一致即 `FormatError::BadField`。

### 5.2 delta `DDLT` v1

```
"DDLT"(4) version:u8=1 block_size:u32 strong_len:u8 new_length:u64 content_digest:u8[32] op_count:u32
repeat op_count 次:
  tag:u8   // 0=COPY, 1=LITERAL, 2=COPY_RUN
  COPY:     block_index:u32 strong:u8[strong_len]
  COPY_RUN: start:u32 count:u32 strong:u8[strong_len]
  LITERAL:  length:u32 bytes[length]
```

- `content_digest` 是目标数据的 SHA-256。`apply` 在写完后重算并比对，不一致即
  `FormatError::DigestMismatch`。这一条挡住了「字面量被改坏」和「长度字段被改坏」
  这两类无法靠逐块校验发现的损坏。
- delta **自带校验**：每个 COPY / COPY_RUN 都携带所复制内容的强校验（COPY 是单块，
  COPY_RUN 是连续 count 块拼接后的整体），`apply` 无需签名文件即可逐 op 验证。
  这是与 §6.3 的第 3 条对应关系，也是「不信任旧数据」的具体落点。
- 相邻 COPY 必须合并成一个 COPY_RUN；相邻 LITERAL 必须合并成一个 LITERAL（规范化要求，测试会检查）。
- `apply` 时若某 op 的重算强校验与 delta 中记录的不一致，返回 `BlockMismatch(index)`。

### 5.3 manifest `DCHK` v1

```
"DCHK"(4) version:u8=1 min_size:u32 max_size:u32 mask_bits:u8 chunk_count:u32
repeat chunk_count 次: sha256:u8[32] length:varint
root:u8[32]    // = SHA-256(concat(每个块的 32 字节 sha256))
```

- 分块参数随 manifest 一起存储，重建时用同一组参数重新分块，`verify` 才有意义。
- 块长用无符号 LEB128 `varint` 编码：小块的 manifest 更短；解析时最多 10 字节，超出即 `Truncated`。
- 解析后必须重算 `root` 并与尾部 32 字节比较，不一致即 `BadField`。

## 6. 算法

### 6.1 弱校验（Adler-32 变体，模 65521）

对窗口 `w[0..n)`：

```
a = 1 + Σ w[i]                          (mod 65521)
b = n + Σ (n - i) * w[i]                (mod 65521)   // 即每个前缀 a 的累加
weak = (b << 16) | a
```

滑动一字节（移出 `out`，移入 `in`，窗口长度 `n` 不变）：

```
a' = a - out + in
b' = b - n * out + a' - 1     // 常数 1 每移动一位就给 b 多贡献 1，故减 1
```

### 6.2 强校验

- 全流：SHA-256（标准实现，NIST 测试向量校验）。
- 块级：`sha256(block)[0..strong_len]`。
- 快速指纹：XXH64，用于分块索引与报告，不用于安全用途。

### 6.3 delta 生成

1. 用签名里的弱校验建桶：`weak -> [block_index...]`。
2. 在**新数据**上滑动窗口（窗口 = `block_size`），弱校验命中候选后再比强校验；命中则发出 COPY（连续块合并），窗口跳过 `block_size`。
3. 未命中则累积 LITERAL 字节。
4. 输出前做规范化（合并同类 op）并校验 op 覆盖的新数据长度 == `new_length`。

复杂度 O(新数据长度)：窗口在新数据上滑过一遍，每次命中后再比较 `block_size` 字节的强校验。

### 6.4 内容定义分块（gear hash）

```
h = 0
for byte in stream:
  h = (h << 1) + gear_table[byte]      // UInt64 自然溢出
  if h & mask == 0 and len >= min: 切分
  if len >= max: 强制切分
```

- 默认 `min=2048, avg=8192, max=32768`，`mask` 取 `avg` 的二进制位数减一的全 1 掩码。
- `gear_table[i] = XXH64(单字节 i)`（seed=0），由代码推导而非抄表，读者可自行复现。
- `mask = (1 << mask_bits) - 1`，默认 `mask_bits = 13`。
- 边界只依赖尾部窗口，插入/删除前缀不改变后续边界（测试断言）。

## 7. 不变量（全部有测试）

1. **重建一致**：任意 `old`、`new`，`apply(old, compute_delta(new, sign(old))) == new`。
2. **规范化**：`compute_delta` 的输出满足「相邻同类 op 已合并」，且重新序列化后逐字节相同。
3. **局部性**：`new` 相对 `old` 只改 1% 的块时，delta 字节数 ≤ `块数*8 + 改动字节 + 16`。
4. **检测损坏**：翻转 delta 中任意一个 LITERAL 字节或把 COPY 指向内容不同的块，`apply` 必须返回错误而不是错误数据。
5. **分块稳定**：在数据前缀插入 1 字节后，≥ 90% 的块指纹仍然复用（默认参数、≥ 1 MiB 输入）。
6. **去重正确**：manifest 重建出的字节与输入相同，`root` 由块指纹确定性导出。
7. **跨后端一致**：相同输入在 wasm / wasm-gc / js / native 上产生逐字节相同的签名、delta 与 manifest。
8. **无 panic**：截断、错 magic、错长度、超大 count 等畸形输入全部返回诊断错误。
9. **流式等价**：同一份数据，无论切成多大的窗口喂给 `ByteSource`（1 字节、7 字节、64 KiB 都一样），`sign_source` / `chunk_source` 产出的字节与 `sign_bytes` / `chunk_manifest` **完全相同**。
   - 前提：块大小必须一致。`sign_bytes` 对 `< 4096` 字节的输入默认用 512，而流无法预读总长；因此 `sign_source` 在未显式给 `block_size` 时默认 8192，除非用 `total_length?` 提示总长（给了就按 `default_block_size(total_length)`）。`sign_memory` 总是传这个提示，所以它无条件等于 `sign_bytes`。`chunk_source` 与 `chunk_manifest` 无条件相等（分块参数默认值相同）。
10. **链式校验**：`apply_chain` 逐步应用并逐步验证；任何一环用错基准版本，都会停下并抛 `ChainError::StepFailed(step, 原因)` —— 段号是从 0 开始的 delta 下标，原因保留底层 `FormatError`，不会把错误数据交给下一环。
11. **回收安全**：`release` 之后只有引用计数为 0 的块会被 `collect` 删除；仍被某个 manifest 引用的块，`assemble` 之后仍能重建出原字节。

## 8. 命令行

```
moon-deltasync sign    <old>   [--out dsig]        # 输出签名摘要与统计，可导出 DSIG
moon-deltasync delta   <old> <new>   [--out d]     # 计算 delta 并报告节省
moon-deltasync apply   <old> <delta> [--out f]     # 应用并逐块校验
moon-deltasync chunk   <file>  [--out dchk]        # 分块与去重率报告，可导出 DCHK
moon-deltasync verify  <file> <sha256-hex>         # 全流校验
```

### 8.1 CLI 的 JSON 契约（外部校验脚本按此解析）

每条命令向 stdout 打印一行 JSON；**所列字段必须存在（按字段名取值），允许实现追加额外字段，不承诺字段顺序**。未知命令、未知参数、参数数量不符、非法十六进制摘要，一律打印 `{"kind":"error","code":"...","message":"..."}` 并以非零退出码结束；`verify` 遇到「摘要不匹配」属于正常结论（`ok:false`，退出码 0），不属于错误。

`sign` 与 `chunk` 支持 `--out`，分别导出 `DSIG` 与 `DCHK` 的原始字节；`delta` 与 `apply` 的 `--out` 分别导出 `DDLT` 与重建结果。

约定：`xxh64_hex` 是大端规范写法（16 个十六进制字符，与 `xxhsum -H64` 输出一致）；`dedup_ratio` 与 `savings_ratio` 都是 4 位小数文本；`manifest_bytes` 是 `DCHK` 的实际字节数（`18 + Σ(32 + varint(块长)) + 32`）。

```json
{"kind":"sign","path":"old.bin","total_length":1048576,"block_size":8192,"strong_len":16,
 "block_count":128,"signature_bytes":2582,"signature_sha256_hex":"…64位…",
 "sha256_hex":"…64位…","xxh64_hex":"…16位…"}

{"kind":"delta","old":"old.bin","new":"new.bin","new_length":1048576,
 "op_count":12,"copy_ops":11,"copy_blocks":127,"copied_bytes":1040384,"literal_bytes":8192,
 "delta_bytes":8260,"delta_sha256_hex":"…64位…","savings_ratio":0.9921}

{"kind":"apply","ok":true,"bytes_written":1048576,"blocks_verified":127,"ops_applied":12,"sha256_hex":"…64位…"}

{"kind":"chunk","path":"big.bin","length":4194304,"chunk_count":512,
 "unique_chunks":510,"new_chunks":510,"reused_chunks":2,"stored_bytes":4177920,"saved_bytes":16384,
 "dedup_ratio":0.0039,"manifest_bytes":17458,"root_hex":"…64位…"}

{"kind":"verify","ok":true,"sha256_hex":"…64位…"}
```

`savings_ratio` 定义为 `1 - delta_bytes / new_length`（裁剪到 `[0,1]`，保留 4 位小数）。
`--out` 的导出对象见本节开头的说明：`sign` 写 `DSIG`，`delta` 写 `DDLT`，`apply` 写重建结果，`chunk` 写 `DCHK`。

## 9. 明确不做的事

- 不做传输层、不做鉴权、不做压缩（可与任意压缩层叠加，本库不感知）。
- 不做 rsync 的 `--checksum` 全量模式、不做多文件目录树同步。
- 不做大规模并发、不做内存映射文件读取；输入统一是内存字节。
