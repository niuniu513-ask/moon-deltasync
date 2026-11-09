# 使用指南

本文说明 `moon-deltasync` 的公开用法。**语义契约的来源是 [design.md](design.md)**：类型、字节格式、不变量、CLI JSON 都以那里为准。本文只复述它已经确定的内容，不发明新接口。

> **状态：部分校准。** 本文写作时实现正在并行落地，已直接读取 `foundation.mbt`、`hash.mbt`、`signature.mbt` 核对符号（截至 2026-11-09）；`delta.mbt`、`chunk.mbt`、`sync.mbt`、`report.mbt`、`cmd/main` **尚未出现**，相关段落一律标「待校准」。若实现与本文冲突，以 `pkg.generated.mbti` 与代码为准，并同步修正本文。
>
> 已经发现**契约与实现不一致**的地方，本文按实际代码记录并单独标注（见 §8），不要据此改代码，也不要默默沿用 design.md 里的旧名。

## 1. 三种用法，选一个入口

| 你的角色 | 你需要先有 | 你要的产出 |
| --- | --- | --- |
| 接收方，手里只有旧文件 | 旧的字节 + 对方给的 `DDLT` 字节流 | 新的字节 + 「每一块都通过强校验」的结论 |
| 发布方，手里有旧签名和新文件 | `DSIG` 字节流（或已解析的 `FileSignature`）+ 新文件字节 | 可发送的 `DDLT` 字节流 + 字节数统计 |
| 备份/缓存，手里有两个版本 | 版本 A、版本 B 的字节 | `DCHK` manifest + 去重率 + 可重建校验 |

三者都不做 I/O：入口和出口都是内存字节。文件读写、压缩、加密、传输都在你的代码里。

## 2. 数据类型

字段名与 design.md §4 一致，且已与 `signature.mbt` 核对：

```moonbit
pub struct BlockSignature {
  index : Int          // 块序号，从 0 开始
  weak : UInt          // 弱校验，见 design.md §6.1
  strong : Bytes       // 强校验前缀，长度 = strong_len
}

pub struct FileSignature {
  block_size : Int     // 每块字节数，同时是滑动窗口大小
  strong_len : Int     // 只接受 8 或 16
  total_length : Int   // 被签名数据的字节数
  blocks : Array[BlockSignature]
}
```

`Delta` / `DeltaOp` / `ChunkManifest` 在 design.md §4 中已定义，但对应模块尚未落地——**字段名待校准**。

一个必须注意的约定：**公开 API 的分片一律用 `BytesView`，不是 `Bytes`**。`sign_bytes`、`weak_checksum`、`sha256`、`sha256_prefix`、`xxh64` 都接受 `BytesView`，`FileSignature::encode()` 返回 `Bytes`。这意味着调用方通常不需要为切片复制数据，也不要写死 `Bytes` 到 `BytesView` 的隐式转换。

## 3. 生成签名

```moonbit
let sig = @ds.sign_bytes(old)                                  // 默认 block_size 与 strong_len=16
let sig2 = @ds.sign_bytes(old, block_size=8192, strong_len=16) // 显式指定
```

已核对的实际签名（`signature.mbt`）：

```moonbit
pub fn sign_bytes(
  input : BytesView,
  block_size? : Int,
  strong_len? : Int,
) -> FileSignature raise FormatError
```

- `strong_len` 只接受 8 或 16，其他值 `raise BadField`。
- `block_size` 必须落在 `[256, 1048576]`（`min_block_size` / `max_block_size`），越界 `raise TooLarge`；块数上限 1,000,000。
- 未指定 `block_size` 时走 `default_block_size(length)`：`length < 4096` 用 512，否则 8192（始终是 2 的幂，落在上述区间内）。**这是 design.md 没有规定的自适应默认值**，见 §8。
- 最后一个块可能短于 `block_size`，`FileSignature::block_length(index)` 给出它的真实长度（越界返回 `None`）。
- 签名本身可序列化：`sig.encode()` 得到 `DSIG` 字节，`@ds.decode_signature(bytes_view)` 读回并校验结构——magic、版本、`block_count` 与实际记录数、以及**尾部多余字节**（有残余即 `BadField`）。

常用辅助：`FileSignature::block_count()`、`FileSignature::digest_hex()`（签名自身的 SHA-256 十六进制，便于做缓存键）。

## 4. 接收方：应用一个 delta

这是唯一会拒绝数据的路径，也是整个库的验收点。**`delta.mbt` 尚未落地，以下为契约语义，符号名待校准。**

```moonbit
let result = @ds.apply(old, delta)   // 待校准：模块落地后核对参数与返回类型
```

`apply` 的行为已由不变量 4 固定：

- 逐块重算 `sha256(block)[0..strong_len]`，与签名里对应块比对。
- 不一致返回 `BlockMismatch(index)`（`FormatError` 的一个构造子），**不做**部分恢复、不返回「尽力而为」的字节。
- 不信任 delta 里任何长度或块号，越界即为错误。

## 5. 发布方：算一个 delta

```moonbit
let sig   = @ds.sign_bytes(old)
let delta = @ds.compute_delta(new, sig)   // 待校准：符号名与参数顺序
// delta_bytes / new_length 决定了这一趟要传多少
```

生成过程（design.md §6.3）：用签名里的 `weak` 建 `weak -> [block_index...]` 桶；在旧数据上以 `block_size` 为窗口滑动，弱命中后再比强校验；命中则发 `COPY`，连续命中的块合并为 `COPY_RUN` 并检查内容确实连续；未命中累积成 `LITERAL`。

两件事值得先知道：

- **输出是规范化的**：相邻同类 op 必须合并，且 op 覆盖长度之和 == `new_length`（不变量 2）。同一个 `(old, new)` 只会产生**唯一**的 delta 字节串，可以当缓存键用。
- **`block_size` 是主要旋钮**：变小 → 定位更准、delta 更小、签名更大；变大 → 反之。`strong_len=16`、`block_size=8192` 时签名约占原文 0.25%（布局见 design.md §5.1，`22 + block_count * (4 + strong_len)` 字节）。没有自动调参，值由调用方负责。

## 6. 备份/缓存：分块与去重

**`chunk.mbt` 尚未落地，符号名待校准。**

```moonbit
let manifest = @ds.chunk(bytes)   // 待校准：是否能覆盖 min/avg/max 也未定
```

- 默认参数 `min=2048`、`avg=8192`、`max=32768`，`mask` 由 `avg` 的二进制位数减一取全 1。
- 切分点是 `h & mask == 0` 且长度达标，或长度触顶强制切分；单遍、窗口恒定。
- `root` 只由块指纹决定，相同内容必得相同 `root`。
- `chunks` 里可能出现重复指纹，这正是去重率的来源；`unique_chunks / chunk_count` 是判断值不值得去重的依据。

不变量 5 的承诺是「前缀插入 1 字节后 ≥ 90% 块指纹复用（默认参数、≥ 1 MiB 输入）」，不是 100%。小文件、高熵数据、或参数改小后复用率会下降，这不是缺陷。

## 7. 命令行

```sh
moon-deltasync sign    <old>                        # 签名摘要与统计
moon-deltasync delta   <old> <new>   [--out d]      # 计算 delta 并报告节省
moon-deltasync apply   <old> <delta> [--out f]      # 应用并逐块校验
moon-deltasync chunk   <file>                       # 分块与去重率报告
moon-deltasync verify  <file> <sha256-hex>          # 全流校验
```

`cmd/main` 尚未落地，上面的命令形态来自 design.md §8。落地后在本仓库里通过 `moon run` 调用：

```sh
moon run cmd/main --target js -- sign old.bin
moon run cmd/main --target js -- delta old.bin new.bin --out patch.ddlt
moon run cmd/main --target js -- apply old.bin patch.ddlt --out rebuilt.bin
moon run cmd/main --target js -- chunk big.bin
moon run cmd/main --target js -- verify big.bin <64-hex>
```

`--target` 可取 `wasm`、`wasm-gc`、`js`、`native`。`--out` 只对 `sign`（写 `DSIG`）和 `delta`（写 `DDLT`）有效，写的是**原始字节**，不是 JSON。

### 7.1 stdout 的 JSON

每条命令打印**一行** JSON，`kind` 区分类型。字段固定，外部脚本按此解析。

```json
{"kind":"sign","path":"old.bin","total_length":1048576,"block_size":8192,"strong_len":16,
 "block_count":128,"sha256_hex":"…64位…","xxh64_hex":"…16位…","signature_sha256_hex":"…64位…",
 "signature_bytes":2068}

{"kind":"delta","old":"old.bin","new":"new.bin","new_length":1048576,"op_count":12,
 "copy_blocks":127,"literal_bytes":8192,"delta_bytes":8260,"delta_sha256_hex":"…64位…",
 "savings_ratio":0.9921}

{"kind":"apply","ok":true,"bytes_written":1048576,"blocks_verified":127,"sha256_hex":"…64位…"}

{"kind":"chunk","path":"big.bin","length":4194304,"chunk_count":512,"unique_chunks":510,
 "dedup_ratio":0.996,"root_hex":"…64位…","manifest_bytes":16416}

{"kind":"verify","ok":true,"sha256_hex":"…64位…"}
```

`signature_bytes` 与 `manifest_bytes` 是**序列化后的字节数**，用来算签名开销，不是内存占用。`savings_ratio` = `1 - delta_bytes / new_length`，裁剪到 `[0,1]`、保留 4 位小数；它不含传输协议开销，也不是与 rsync 的对比结论。

> 待校准：上面 `sign` 示例写 `block_count:128`、`strong_len:16`、`signature_bytes:2068`，但按 design.md §5.1 布局应为 `22 + 128 * 20 = 2582`。**不要**拿示例里的 `2068` 当断言基线；等 CLI 落地后以实际输出为准，并回填 design.md。

### 7.2 错误

未知命令或参数错误时，打印一行错误 JSON 并以非零退出码结束：

```json
{"kind":"error","code":"…","message":"…"}
```

`code` 的取值集合尚未在 design.md 中逐条固定（待校准）。业务失败通过 `kind:"error"` 表达；成功与否请看 JSON，不要只看退出码。

## 8. 已落地的错误类型（与契约的差异）

实现把「所有能出错的地方」收在一个 `suberror` 里，**名字是 `FormatError`，不是 design.md §5.1 写的 `FormatMismatch`**：

```moonbit
pub suberror FormatError {
  BadMagic(String)         // magic 不是 DSIG/DDLT/DCHK
  UnsupportedVersion(Int)  // 版本号不认识
  Truncated(Int)           // 在指定偏移处数据截断
  BadField(String)         // 字段值非法，如 strong_len 不是 8/16
  TooLarge(String)         // 越界，如 block_size、block_count
  BlockMismatch(Int)       // 第 index 块与签名不符
  UnsupportedOp(Int)       // delta 的 op tag 不认识
}
```

`FormatError` 实现了 `Show`，`to_string()` 给出可读诊断（例如 `block 7 does not match the signature`）。调用方按构造子匹配即可区分「结构性损坏」与「内容损坏」，这两种情况恢复策略不同。

## 9. 边界与常见误用

- **`weak` 不是校验**：它只用于把候选块缩小到常数个，真正的判断在 `strong`。不要只比 `weak` 就接受数据。
- **强校验不是签名**：SHA-256 前缀能发现损坏，不能证明来源。需要身份认证就外加固签名，本库不提供。
- **`sha256_hex` 一致 ≠ 全库正确**：它只说明这一次输出与预期哈希一致；逐块结论要看 `blocks_verified` 与 `kind:"error"`。
- **不要用 XXH64 做安全判断**：它是快速指纹，用于分块索引与报告，design.md §6.2 明确写了「不用于安全用途」。
- **输入全是内存字节**：不做文件系统、不做内存映射、不做流式增量解析；超大对象需要调用方自己切分，切分策略会影响去重率。
- **畸形输入必须报错而不是崩溃**（不变量 8）：如果你在自己的封装里遇到某个输入导致 panic，那是实现的 bug，不是用法问题。
- **四个后端结果必须逐字节相同**（不变量 7）：如果 `js` 与 `native` 的 delta 字节不同，那是缺陷，不能当成「实现差异」放过。

## 10. 待校准清单

| 项目 | 现状（2026-11-09 读取） |
| --- | --- |
| 签名入口名 | **已定**：`sign_bytes(BytesView, block_size?, strong_len?)`，非 design.md 写的 `sign(old)` |
| 错误类型名 | **已定**：`FormatError`，非 design.md 写的 `FormatMismatch`；含 7 个构造子 |
| 默认 `block_size` | **已定**：`default_block_size(length)`，`<4096` 用 512、否则 8192；design.md 未规定该自适应行为 |
| `compute_delta` 的符号名与参数顺序 | 未落地（`delta.mbt` 缺失），design.md 只在 §7 不变量 1 的表述里提过 |
| `apply` 的返回类型（`Result[Bytes, E]` 还是带统计结构） | 未落地（`delta.mbt` 缺失），语义已定 |
| 分块入口名与 `min/avg/max` 可配置性 | 未落地（`chunk.mbt` 缺失） |
| `Delta` / `DeltaOp` / `ChunkManifest` / `ChunkRef` 字段名 | 未落地；`ChunkRef` 在 design.md 里只有「sha256 + length」的语义 |
| `report.mbt` 的三态报告公开函数 | 未落地 |
| 错误 JSON 的 `code` 取值表 | 未定 |
| `signature_bytes` 示例值 `2068` | 与 §5.1 布局算出的 2582 冲突，待回填 |

`pkg.generated.mbti` 是这份清单的权威答案来源；`moon info` 可重新生成。
