# 来源、选题边界与有限查重

检索日期：2026-11-09（Asia/Shanghai）。主数据源是本地保存的 mooncakes 全量索引快照 `D:\moonbit\contest-submission\mooncakes-index-20261026.json`，快照日期 2026-10-26，共 **3,337** 个包记录。

结论一句话：**在快照的名称与描述字段范围内，`rsync`、`delta sync`、`delta encoding`、`rolling hash` 四个词 0 命中；但在线注册表已经变化（见下），且「二进制 delta」与「内容定义分块 + 去重」的能力在生态中本来就存在，因此本项目不主张生态空白，只主张「块签名 + 可逐块校验的 delta + 内容定义分块」三者落在同一个库内、并逐字节跨四后端一致的组合未被找到。** 这不是「任何项目都不重合」的承诺，也不是赛事立项结论。

**快照之后的变化（必须和第 3 段一起读）**：2026-11-09 直接查询在线注册表（`https://mooncakes.io/api/v0/modules?limit=10000&offset=0`）得到 **3,665** 个包。按名称+描述重跑同一组关键词：

| 关键词 | 快照（3,337，2026-10-26） | 在线（3,665，2026-11-09） | 变化 |
| --- | --- | --- | --- |
| `rsync` | 0 | **1**（`YKDshaxing/moonlibsync`） | 新增一个包；本项目自身不在该口径内（它的 `rsync` 只出现在 keywords，名称与描述都不含该词） |
| `delta sync` | 0 | 0 | — |
| `delta encoding` | 0 | 0 | — |
| `rolling hash` | 0 | 0 | — |
| `content-defined` | 2 | 2（不含自身） | 计数含本项目自身时为 3 |
| `deduplicat` | 4 | 4（不含自身） | 计数含自身时为 5 |
| `content-address` | 3 | 3 | — |
| `merkle` | 3 | 3 | — |

也就是说：**「`rsync` 0 命中」这个说法只对 2026-10-26 的快照成立，现在已经不成立**。`YKDshaxing/moonlibsync`（v0.1.0，LGPL-2.1-or-later，2026-11-09 发布，自述「Librsync-compatible byte-buffer library and Native single-file CLI」，keywords 含 `librsync` / `delta` / `sync`）是目前最接近的相邻项目——librsync 本身就是 rsync 算法的库化实现。它不改变本项目「不主张生态空白」的立场，反而进一步说明不能把「某个词没命中」当作空白证明。

## 检索方法与局限

- 数据源是**已落盘的索引快照**，不是本次在线请求；快照之后新增或撤回的包不在覆盖范围内，提交前需刷新。
- 字段范围：每条记录含 `name` / `version` / `yanked` / `license` / `repository` / `keywords` / `description`。检索只命中这些元数据字段，**不检索源码**。元数据不能证明某个包没有未在描述中声明的功能，这是本文件全部结论的边界。
- 口径 A（与任务给定的数字一致）：`name + description`，3,337 条全量。
- 口径 B（更宽）：`name + keywords + description`，3,332 条。缺的 5 条（`bobzhang/myshell`、`bobzhang/portable_cli`、`bobzhang/zipc`、`conglinyizhi/moonbit-llm-faceoff-web`、`moonbit-community/debug`）已逐条确认 `yanked: true`，其 `yanked_reason` 含逗号导致正则未匹配，不是漏检。所以口径 B 是 3,332 条的下界读数。
- **未阅读**上述任何包的源码、README 正文或已发布文档。下表的「本项目关系」是对其**索引中声明能力**的比较，不是逐行审计，也不据此断言其永久不具备某功能。

复现命令（PowerShell）：

```powershell
$raw = Get-Content 'D:\moonbit\contest-submission\mooncakes-index-20261026.json' -Raw
$entries = [regex]::Matches($raw, '\{"name": "([^"]+)", "version": "([^"]*)".*?"description": (".*?")[,}]') |
  ForEach-Object { [pscustomobject]@{ Name=$_.Groups[1].Value; Desc=$_.Groups[3].Value } }
$entries.Count          # 3337
$entries | Where-Object { ($_.Name + ' ' + $_.Desc) -match 'rsync' } | Measure-Object   # 0
[regex]::Matches($raw, '(?i)rsync').Count                                               # 0
```

## 逐关键词命中计数

| 关键词 | 口径 A：名称+描述 | 口径 B：名称+keywords+描述 |
| --- | --- | --- |
| `rsync` | **0** | **0** |
| `delta sync` | **0** | **0** |
| `delta encoding` | **0** | **0** |
| `rolling hash` | **0** | **0** |
| `content-defined` | 2 | 2 |
| `deduplicat`（前缀） | 4 | 7 |
| `content-address`（前缀） | 3 | 5 |
| `merkle` | 3 | 5 |
| `delta`（单字） | — | 5 |
| `rolling`（单字） | — | 3 |

口径 A 的命中名单（已逐个核对包名）：
`content-defined` → `cn-ybm/MoonHashKit`、`xgzh1111/moonchunk`；
`deduplicat` → `cn-ybm/MoonHashKit`、`didiLjf/moon-record-linkage`、`Hjyyutr/moon-minhash`、`zbhzs1/moonbit-phonetic`；
`content-address` → `bzhangui/moonrestore`、`ggbond44439/moonloom`、`Yingqingxue/mooncas`；
`merkle` → `ShiChengxu/moonappend`、`wch6766/MoonSecureCodec`、`zploc/loci`。

口径 B 相对 A 的**有效新增**：`deduplicat` 增 `bzhangui/moonrestore`、`xgzh1111/moonchunk`、`Yingqingxue/mooncas`；`content-address` 增 `any07557-wq/moonvcs`、`zploc/loci`；`merkle` 增 `xgzh1111/moonchunk`、`starlittle/MoonEvidence`。

两点必须说明，否则数字会被误读：

1. `content-defined` 在原始文件里出现 3 次、但只对应 2 个包——`cn-ybm/MoonHashKit` 的 `keywords` 写了 `content-defined-chunking`、`description` 又写了一次 `Content-defined chunking`。按包计数是 2，按字符串出现是 3。
2. `delta` 单字在口径 B 命中 5 个包，其中 **4 个是误报**：`xiguaAp6y3/moondelta-core` 是 Delta Lake 表格式内核、`youyong5/racedelta` 是赛车策略仿真、`Ag108/MoonReduce` 是 delta-debugging、`bobzhang/dateutil` 是 python-dateutil 移植（`relativedelta`）。真正相关的只有 `yangxixi00/moon_vcdiff`（RFC 3284 VCDIFF）——**这一个直接反驳了「MoonBit 没有二进制 delta」的说法，见下表。**

## 相邻生态逐项比较

版本、许可证、仓库地址、keywords、描述均取自上述索引快照，逐字可复核。

| 包（索引版本） | 索引中声明的能力 | 与本项目的关系 | 本项目不主张的 |
| --- | --- | --- | --- |
| `YKDshaxing/moonlibsync` v0.1.0，LGPL-2.1-or-later，**2026-11-09 新增，不在 3,337 快照内**，kw 含 `librsync` / `delta` / `sync` | 自述「Librsync-compatible byte-buffer library and Native single-file CLI」 | **最接近的相邻项目**：librsync 是 rsync 算法的库化实现，同属「签名 → delta → patch」这一族；发布时间只比本项目早约 1 小时 | 不主张「MoonBit 没有 rsync 类库」；本项目格式是自定义的 `DSIG`/`DDLT`/`DCHK`，与 librsync 格式不互通，也未做互操作测试；其许可证是 LGPL-2.1-or-later，本项目 MIT 且无代码关系。其自述只提 Native 单文件 CLI，本项目在 js / wasm / wasm-gc / native 上跑同一套测试 |
| `cn-ybm/MoonHashKit` v0.3.0，Apache-2.0，kw 含 `rolling` / `content-defined-chunking` / `dedupe` / `sync` | 内容定义分块、rolling 指纹、去重 | **正面重叠**：§6.4 的 CDC 与去重目的与其一致 | 不主张 CDC / rolling 指纹 / 去重本身是新增贡献；差异只在本项目还提供 `DSIG`/`DDLT` 两段与逐块强校验重建 |
| `xgzh1111/moonchunk` v0.1.0，Apache-2.0，kw 含 `chunking` / `deduplication` / `merkle` / `sync` / `storage` | 「内容定义分块与增量同步原语」 | 措辞上与本文「增量传输」最接近；同属分块 + 同步 | 不主张「MoonBit 没有增量同步原语」；无法从索引判断其 delta 是否逐块强校验，因此**也不主张它没有** |
| `yangxixi00/moon_vcdiff` v0.1.0，Apache-2.0，kw 含 `vcdiff` / `delta` / `binary` / `rfc3284` | RFC 3284 VCDIFF 编解码器、inspector 与 CLI | 已有标准化**二进制 delta 格式**实现 | 不主张「MoonBit 没有二进制 delta」；差异在格式与验收：VCDIFF 是 RFC 定义的指令流，本项目是定长头 + weak/strong 块签名 + `COPY`/`COPY_RUN`/`LITERAL` 规范化 + apply 逐块强校验，未做 VCDIFF 互操作，也不是其移植 |
| `bzhangui/moonrestore` v0.5.0，Apache-2.0，kw 含 `backup` / `restore` / `integrity` / `deduplication` | 可验证增量备份、内容寻址存储、安全恢复 | 与工作流③（备份去重）目标重叠，同样强调完整性 | 不主张「可验证增量备份」是生态空白；本项目不做存储层、不做恢复策略，只输出 `DCHK` manifest 与根指纹 |
| `zploc/loci` v0.1.0，Apache-2.0，kw 含 `merkle` / `content-addressed` | 确定性哈希、Merkle 封存、运行时基底 | 共用 Merkle/内容寻址术语 | 与增量传输无直接重叠，不比较优劣 |
| `ggbond44439/moonloom` v0.1.6，Apache-2.0，kw 含 `cid` / `multihash` / `multicodec` | 自描述内容寻址层（multiformats 风格 CID） | 同属内容寻址，但对象是 CID 编码而非块去重 | 本项目的 `root` 是单一 SHA-256，**不是** CID/multihash，不做跨格式互操作 |
| `Yingqingxue/mooncas` v0.1.0，Apache-2.0，kw 含 `cas` / `storage` / `sha256` | 可移植内容寻址存储内核 | 与工作流③的块存储概念相邻 | 本项目不含存储内核、无 I/O、无引用计数持久化 |
| `any07557-wq/moonvcs` v0.1.0，Apache-2.0，kw 含 `version-control` / `content-addressed-storage` | 原生 VCS 内核、typed SHA-256 对象、惰性存储 | 版本控制方向的内容寻址存储 | 不做版本库、不做对象数据库、不做分支模型 |
| `yuzhiblue/moon-diff` v0.2.2，Apache-2.0，kw 含 `diff` / `patch` / `myers` / `unified` / `three-way` | 文本 diff/patch：LCS、Myers 等 5 种算法、unified/git patch、三方合并、JSON diff | 同为「只传差异」，但对象是文本行/结构 | 本项目**不做**文本 diff、不做行级/语义级 diff、不做三方合并；`delta` 是定长块级，不对文本格式做假设 |
| `gaato/deflate`、`gaato/zstd`、`gaato/brotli`、`gaato/codec_bytes`（`gaato/codecs.mbt`，Apache-2.0） | 流式 DEFLATE/zlib/gzip、Zstandard、Brotli 编解码；统一流式契约、有界内存 | 同为「对字节流做处理」的库 | 本项目**不做压缩**，不与压缩层竞争也不内嵌；可与其中任意一层叠加，叠加后的净收益未测 |
| `ShiChengxu/moonappend` v0.3.0、`wch6766/MoonSecureCodec` v0.1.1、`starlittle/MoonEvidence` v0.5.1 | Merkle 日志 / 包含性与一致性证明、供应链校验、证据包校验 | 共用 Merkle 与完整性校验概念 | 本项目不做 append-only 日志、不做包含性/一致性证明、不做签名与公证 |
| `tonyfettes/xxh64` v0.1.0（BSD-2-Clause）、`AXiX-official/xxhash` v0.1.0（Apache-2.0） | **已存在**的 MoonBit XXH64 / xxHash 实现，其一标注为参考实现的忠实移植 | 本项目 `hash.mbt` 也做 XXH64 | **不主张** XXH64 算法或其 MoonBit 实现是新增贡献；本项目不依赖它们，自行实现只为避免为一个哈希引入依赖，未做性能对比 |

## 本项目的独立贡献

在承认上表重叠的前提下，本项目声称的新增内容只有这几条，均可被契约与测试检验：

1. **一条闭合的可验证链**：`DSIG`（签名）→ `DDLT`（delta）→ `apply` 逐块重算强校验 → `DCHK`（分块/去重 manifest），三份格式在同一个包内、同一套 `Bytes` 语义上互通，不跨包拼接。检索范围内未找到同时覆盖这三段的包，但这一条是「未找到」而非「不存在」。
2. **把「拒绝」当正确性**：`apply` 对每一块比对强校验前缀，失败返回 `BlockMismatch(index)`；不变量 4 要求翻转任一 LITERAL 字节或错指 COPY 必须报错。「损坏必须变成诊断信息」被写成可失败的测试，不是文档承诺。
3. **规范化可判定**：`compute_delta` 输出必须满足「相邻同类 op 已合并」且重新序列化逐字节相同（不变量 2）。这让 delta 有唯一表示，可做字节级比较与缓存键。
4. **四后端逐字节一致**：`wasm` / `wasm-gc` / `js` / `native` 产生相同签名、delta、manifest（不变量 7）。这类等价性在实现上受整数宽度与溢出语义影响，需要专门约束，不是自动成立的。
5. **确定性内容定义分块的复现结论**：齿轮哈希单遍、默认 `min/avg/max = 2048/8192/32768`，并断言前缀插入 1 字节后 ≥ 90% 块指纹复用（不变量 5）。
6. **依赖面很小且可核对**：库的根包只 import `moonbitlang/core`（Apache-2.0，经官方工具链链接使用）；模块级依赖仅 `moonbitlang/x@0.5.6` 一项，供 `cmd/main` 读写文件。不内嵌任何第三方源码。

## 上游与合规

- 算法来源是公开定义：rsync 的 weak/strong checksum 与 `--block-size` 思路（Andrew Tridgell 的 rsync 算法论文与 rsync 技术报告）、Rabin/gear 风格的内容定义分块、Adler-32 的模 65521 结构、SHA-256（FIPS 180-4）、XXH64（xxHash 规范）、RFC 3284 的 VCDIFF 作为**相邻格式的参照**。参考这些公开定义不等于复制其代码。
- 本项目**不含**任何第三方源码、测试向量文件或数据；未复制、翻译或链接 rsync、VCDIFF 参考实现或其他上游工程。因此「原项目许可证」不适用，根目录按 MIT 发布。
- 与上表所有包**无代码依赖、无移植关系、无作者背书**；未与其作者沟通，也未提交适配层。
- 本项目自己的 `moon.mod` 在 `keywords` 中声明了 `rsync` / `delta` / `incremental` / `content-defined-chunking` / `deduplication`。其中 `rsync` 一词在索引快照中 0 命中，说明该词此前未被占用；这不构成原创性证明，只说明该检索词是有效的区分度检验。

## 发布状态与残余不确定

**已核实**（2026-11-09 用 `gh` 与 mooncakes 注册表 API 直接查询，不是推测）：

1. **GitHub**：`niuniu513-ask/moon-deltasync` 为 **PUBLIC** 仓库，默认分支 `main`；本机 `refs/heads/main` 与 `refs/remotes/origin/main` 指向同一提交（仓库仍在活跃提交，SHA 会变）。CI 在 `main` 上最近若干次运行均 `success`（`gh run list` 复核）。
2. **mooncakes**：`niuniu513-ask/moon-deltasync@0.1.1` 已发布（MIT，`is_new: true`，`created_at` 2026-11-09T14:32:03Z）。它在 2026-10-26 的快照里当然不存在——那是快照时点的事实，不是现在的状态。

**仍未被本文件核实**的部分：

1. **相邻包的实际实现深度**：本文件只读索引元数据。上表中「其能力」是**其自我声明**，未验证是否完整、是否与描述一致。若需更强的比对结论，必须逐个拉取源码与 README 复核。`YKDshaxing/moonlibsync` 尤其如此：只据其描述与 keywords 归类，未读其格式文档，因此不对「librsync 兼容到什么程度」下判断。
2. **快照时效**：逐关键词统计基于 2026-10-26 的快照（3,337 包）；在线注册表已是 3,665 包，中间新增/撤回的包只复核了上面那八个关键词，未做全量差异审计。提交前应重新拉取索引并重跑复现命令。
