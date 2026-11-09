# moon-deltasync

MoonBit 增量传输内核。在两个版本的数据之间只传差异，并在接收端**可验证地**重建出与源逐字节相同的结果。

核心代码由 MoonBit 实现，唯一编译依赖 `moonbitlang/core`。三个能力在同一套字节格式上闭合：rsync 风格**块签名**、**可逐块校验的 delta**、**内容定义分块与去重**。算法全部来自公开定义，本项目是独立实现，不宣称发明 rsync、Rabin/gear CDC 或 SHA-256。与 MoonBit 相邻包的关系和有限查重结论见 [SOURCES.md](SOURCES.md)。

## 定位与边界

它解决的是和 rsync、增量 OTA、备份去重、CI 构建缓存同一类的问题：数据有历史版本，下一次只需要传「变了的部分」，而正确性必须能被验证，不是被相信。

本库**不做**的事，逐条写清楚，避免过度承诺：

- **不做网络**：没有 socket、没有协议握手、没有断点续传，不做 rsync 的 ssh 通道与并发调度。传输层由调用者决定。
- **不做文件系统**：输入输出统一是内存字节（`Bytes` / `BytesView`）；不读目录树、不做多文件同步、不做内存映射。
- **不做压缩**：可与任意压缩层叠加，本库不感知也不内嵌 deflate/zstd/brotli。
- **不做加密，也不做签名认证**：强校验是**完整性校验**，不是数字签名。它能发现传输或存储造成的损坏，**不能**阻止有能力的篡改者伪造数据并同步伪造指纹。
- 不追求比成熟 C 实现更快。追求的是**确定性、可验证、零第三方依赖、四后端逐字节一致**。

所有算法都有明确上界，见下文「复杂度与上界」。

## 三个完整工作流

| 使用者与问题 | 输入 → 库内计算 → 输出 | 可运行入口 |
| --- | --- | --- |
| 收到增量包的客户端：这个 delta 能不能安全落到本地？ | 旧文件原文 + 服务端给出的 delta → 反序列化、重放 COPY/LITERAL、逐块重算强校验 → 新文件 + 校验结论（成功，或第几块失败） | `cmd/main apply` |
| 发布方 / 服务端：这次更新实际要传多少字节？ | 客户端上传的签名 + 新文件原文 → 弱校验分桶、滑动匹配、COPY/LITERAL 规划、规范化 → `DDLT` delta 字节流 + 字节数与节省比例 | `cmd/main delta` |
| 备份 / 构建缓存：两个版本重复了多少？ | 客户端旧数据签名、或两个版本的大对象 → 内容定义分块、块指纹索引、引用计数 → `DCHK` manifest + 去重率 + 可重建校验 | `cmd/main sign`、`cmd/main chunk` |

第一条是唯一会**拒绝**数据的路径：`apply` 不信任 delta，逐块比对强校验，任何不一致都变成带块号的诊断错误，而不是错误数据。

## 字节格式

三份格式都是定长头 + 重复记录，整数默认**大端**，magic 是 4 字节 ASCII。完整布局以 [docs/design.md](docs/design.md) §5 为准，这里是速览：

| magic | 名称 | 头部字段 | 记录 |
| --- | --- | --- | --- |
| `DSIG` | 签名 v1 | `version:u8=1` `block_size:u32` `strong_len:u8` `total_length:u64` `block_count:u32` | `weak:u32` + `strong:u8[strong_len]` |
| `DDLT` | delta v1 | `version:u8=1` `block_size:u32` `strong_len:u8` `new_length:u64` `op_count:u32` | `tag:u8` + `block_index:u32` / `start:u32,count:u32` / `length:u32,bytes` |
| `DCHK` | manifest v1 | `version:u8=1` `chunk_count:u32` | `sha256:u8[32]` + `length:u32`，尾部 `root:u8[32]` |

`strong_len` 只接受 8 或 16。解析时校验 `block_count == ceil(total_length / block_size)`，不一致即报格式错误（实现中统一为 `FormatError`，见下）。

公开入口一律接受 `BytesView` 而不是 `Bytes`，切片不复制数据。已落地的签名入口是：

```moonbit
pub fn sign_bytes(
  input : BytesView,
  block_size? : Int,     // 落在 [256, 1048576]，未指定时按长度自适应（512 或 8192）
  strong_len? : Int,     // 8 或 16，默认 16
) -> FileSignature raise FormatError
```

所有可出错的地方收敛到一个 `suberror FormatError`：`BadMagic` / `UnsupportedVersion` / `Truncated` / `BadField` / `TooLarge` / `BlockMismatch(index)` / `UnsupportedOp`，且实现了 `Show`。公开 API 上不出现 panic。

`root` 定义为 `SHA-256(concat(每个块的 32 字节 sha256))`，由指纹确定性导出，不额外引入时间戳或随机量。

## 能力范围（契约定义）

下面是 design.md 定义的完整能力。**落地进度**：截至 2026-11-09，`foundation.mbt`、`hash.mbt`、`signature.mbt` 已在仓库中；`delta.mbt`、`chunk.mbt`、`sync.mbt`、`report.mbt`、`cmd/main` 尚未出现。因此下面关于 delta、分块、报告与 CLI 的条目是**契约**而非当前可运行的既成事实。

- **弱校验**：Adler-32 变体（模 65521），`weak = (b << 16) | a`，带 O(1) 滑动更新（移出/移入各一字节），用于粗筛候选块。
- **强校验**：SHA-256 全流与块级前缀 `sha256(block)[0..strong_len]`；XXH64 只作快速指纹与报告用途，**不用于安全目的**。
- **delta 生成**：`weak -> [block_index...]` 分桶，窗口 = `block_size` 滑动，弱命中后再比强校验；连续命中的块合并为 `COPY_RUN` 并检查内容确实连续，未命中累积为 `LITERAL`。输出前规范化：相邻同类 op 必须合并，且 op 覆盖长度 == `new_length`。
- **delta 应用**：逐块重算强校验，失败返回 `BlockMismatch(index)`；不做「尽力恢复」。
- **内容定义分块**：gear hash，`h = (h << 1) + gear_table[byte]`，`h & mask == 0` 且长度 ≥ `min` 时切分，达到 `max` 强制切分；默认 `min=2048`、`avg=8192`、`max=32768`。
- **报告**：文本 / JSON / Markdown 三态。
- **错误处理**：损坏输入一律走 `FormatError`（7 个构造子）或 `Result`，公开 API 上不出现 panic。

## 安装与本地运行

要求 MoonBit CLI，`moonc >= 0.10.16`。本机使用 `D:\moonbit\_tools\moon-0.10.17\bin` 下的工具链，`moon version --all` 实测输出：

```text
moon  0.1.20261023 (3778465 2026-10-23)
moonc v0.10.17+d971670cd (2026-10-23)
moonrun 0.1.20261023 (3778465 2026-10-23)
```

在该目录外使用时，把工具链 bin 放进 `PATH`，或直接调用绝对路径：

```powershell
$env:PATH = 'D:\moonbit\_tools\moon-0.10.17\bin;' + $env:PATH
```

在项目根目录执行：

```sh
moon version --all
moon check --deny-warn --target all
moon build --target all
moon test --deny-warn --target all
```

JS 后端需要 Node.js，native 后端需要系统 C 编译器；`wasm`、`wasm-gc` 由 `moonrun` 直接执行。四个后端产生**逐字节相同**的签名、delta 与 manifest，这是不变量 7，不是「大致一致」。

作为依赖引用（发布到 mooncakes.io 之后）：

```moonbit
import {
  "niuniu513-ask/moon-deltasync" @ds,
}
```

也可以把本目录作为工作区模块直接引用，跳过下载。

## 命令行

```sh
moon-deltasync sign    <old>                        # 输出签名摘要与统计
moon-deltasync delta   <old> <new>   [--out d]      # 计算 delta 并报告节省
moon-deltasync apply   <old> <delta> [--out f]      # 应用并逐块校验
moon-deltasync chunk   <file>                       # 分块与去重率报告
moon-deltasync verify  <file> <sha256-hex>          # 全流校验
```

每条命令向 stdout 打印**一行** JSON，字段固定；未知命令或参数错误时打印 `{"kind":"error","code":"...","message":"..."}` 并以非零退出码结束。

```sh
moon run cmd/main --target js -- delta old.bin new.bin --out patch.ddlt
```

```json
{"kind":"delta","old":"old.bin","new":"new.bin","new_length":1048576,"op_count":12,
 "copy_blocks":127,"literal_bytes":8192,"delta_bytes":8260,"delta_sha256_hex":"…",
 "savings_ratio":0.9921}
```

`savings_ratio` 定义为 `1 - delta_bytes / new_length`，裁剪到 `[0,1]` 并保留 4 位小数；它是**字节数比例**，不含传输协议开销，也不承诺与 rsync 逐字节相同。完整 JSON 契约（五个 `kind` 的全部字段）见 [docs/design.md](docs/design.md) §8.1，逐字段说明与调用示例见 [docs/usage.md](docs/usage.md)。

## 不变量

以下 8 条是工程契约，每条都有对应测试，不是描述性文档：

1. **重建一致**：任意 `old`、`new`，`apply(old, compute_delta(new, sign(old))) == new`。
2. **规范化**：`compute_delta` 的输出满足「相邻同类 op 已合并」，重新序列化后逐字节相同。
3. **局部性**：`new` 相对 `old` 只改 1% 的块时，`delta_bytes <= 块数*8 + 改动字节 + 16`。
4. **检测损坏**：翻转 delta 中任意一个 LITERAL 字节，或把 COPY 指向内容不同的块，`apply` 必须返回错误而不是错误数据。
5. **分块稳定**：数据前缀插入 1 字节后，≥ 90% 的块指纹仍复用（默认参数、≥ 1 MiB 输入）。
6. **去重正确**：manifest 重建出的字节与输入相同，`root` 由块指纹确定性导出。
7. **跨后端一致**：相同输入在 `wasm` / `wasm-gc` / `js` / `native` 上的签名、delta、manifest 逐字节相同。
8. **无 panic**：截断、错 magic、错长度、超大 count 等畸形输入全部返回诊断错误。

## 复杂度与上界

| 操作 | 时间 | 额外空间 |
| --- | --- | --- |
| `sign` | O(n) 单遍 | 签名 = `22 + block_count * (4 + strong_len)` 字节（22 字节定长头） |
| `delta` | O(旧数据长度)，未命中时最多额外 `block_size` 次字节比较 | 分桶索引 + 输出 delta |
| `apply` | O(新数据长度) | 输出缓冲 |
| 内容定义分块 | O(n) 单遍，窗口恒定 | 每块 32 字节指纹 + 长度 |

签名本身与数据成比例，这是 rsync 类方法的固有成本：`strong_len=16`、`block_size=8192` 时签名约为原文的 0.25%。块越小定位越精确、签名越大；这是可配置的取舍，不是实现缺陷。

> 注：design.md §8.1 的 `sign` 示例给了 `block_count:128`、`strong_len:16`、`signature_bytes:2068`。按 §5.1 的字节布局计算应为 `22 + 128 * 20 = 2582`，与该示例值不一致。本表按 §5.1 布局推导；`2068` 视为示意值，实现落地时以 §5.1 为准并回填该示例。此差异已列入待确认。

## 与现有 MoonBit 生态的关系

在 mooncakes 全量索引快照（3,337 个包，`D:\moonbit\contest-submission\mooncakes-index-20261026.json`）中按名称与描述检索：

- `rsync`、`delta sync`、`delta encoding`、`rolling hash` **均为 0 命中**。
- `content-defined` 命中 2 个（`cn-ybm/MoonHashKit`、`xgzh1111/moonchunk`），`deduplicat` 4 个，`content-address` 3 个，`merkle` 3 个。
- 扩大口径到 `keywords` 字段后，相邻能力更清楚地暴露出来：`yangxixi00/moon_vcdiff`（RFC 3284 VCDIFF 编解码）、`bzhangui/moonrestore`（可验证增量备份 + 内容寻址）、`zploc/loci`、`ggbond44439/moonloom`、`Yingqingxue/mooncas`、`any07557-wq/moonvcs`、`yuzhiblue/moon-diff`（文本 LCS/Myers diff、git patch）以及 `gaato/*` 的流式解压缩 codec。

因此本项目**不宣称**「MoonBit 生态没有增量传输 / 去重 / 内容寻址相关代码」——那是不成立的。相邻包已经覆盖了其中的若干片段。本项目主张的是另一件事：把块签名、可逐块校验的 delta、内容定义分块放在**同一个零依赖内核、同一套字节格式**里，并且在四个后端上逐字节一致；上述检索范围内没有找到同时覆盖这三段、并以「可验证重建」为验收标准的包。逐包比对、检索命令与命中计数见 [SOURCES.md](SOURCES.md)。

本库与上述包**没有代码依赖、没有移植关系**，也未与其作者建立适配或背书关系。

## 状态与待确认

诚实标注当前状态，读者不必猜：

- 本文与 `docs/` 依据 [docs/design.md](docs/design.md) 编写，该文件是类型、字节格式与不变量的唯一契约来源；实现同期并行落地。
- 截至 2026-11-09，**尚未在完整实现上复跑** `moon check/build/test --target all` 与四个后端的 CLI。通过状态以仓库实际运行为准，不以本文为准。
- **未发布到 mooncakes.io**：在 2026-10-26 索引快照中检索 `deltasync` 为 0 命中，该快照只含 `niuniu513-ask/moon-postal` 与 `niuniu513-ask/MoonRetrieve`。上面的 `moon add` 命令在发布前不可用。
- **GitHub 推送状态未在本地核实**：本目录当前没有 `.git`，无法从工作副本确认远端是否存在、默认分支与 CI 是否运行。`moon.mod` 声明的仓库地址是 <https://github.com/niuniu513-ask/moon-deltasync>。
- 外部第三方校验脚本（`scripts/` 下的 Python 参考实现）由独立一方按本契约另写一份实现做交叉验证，其产物是**外部佐证**，不是官方验收结论。
- **契约与实现已出现命名差异**：design.md §5.1 写 `FormatMismatch`、§7 写 `sign(old)`，而落地的 `signature.mbt` 使用 `FormatError`（7 个构造子）与 `sign_bytes(BytesView, block_size?, strong_len?)`，并引入了 design.md 未规定的自适应默认 `block_size`（`<4096` 用 512，否则 8192）。本 README 与 [docs/usage.md](docs/usage.md) 按**实际代码**记录，design.md 待回填。
- **契约内部有一处数字待校准**：design.md §8.1 的 `signature_bytes:2068` 与 §5.1 布局算出的 `2582`（128 块、`strong_len=16`）不自洽，二者必有一处需修改。这不影响字节格式本身，但会影响任何按该字段做断言的校验脚本。

## 许可证

MIT（`moon.mod` 中声明 `license = "MIT"`）。来源、相邻项目逐项比对与有限查重边界见 [SOURCES.md](SOURCES.md)。
