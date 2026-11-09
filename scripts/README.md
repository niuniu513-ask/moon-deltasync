# scripts/ — 外部独立校验器

本目录是 `moon-deltasync` 的**第三方校验工具**，不属于库的实现代码，也不参与 `moon build`。

> 定位说明：这是**外部校验器**，不是官方验收结论。它按 `docs/design.md` 的语义**独立重写**了
> 哈希、二进制格式、delta 重放与 rsync 规划器，用来交叉验证被测实现；它不读取、不翻译
> `*.mbt` 源码，也不修改仓库中的任何 `.mbt` / `moon.mod` / `moon.pkg` / `docs/` 文件。

## 文件

| 文件 | 作用 |
| --- | --- |
| `dsref.py` | 按 design.md 独立实现的参考语义：Adler-32 变体弱校验（含滑动更新）、XXH64、DSIG/DDLT/DCHK 解析与序列化、delta 重放（逐 op 强校验 + content_digest）、rsync 风格规划器、CDC 参考实现（仅参考） |
| `verify_deltasync.py` | 自测 + CLI 联调 driver：生成固定种子语料、驱动 CLI、逐项断言、写 `verify-report.txt`、返回退出码 |
| `verify-report.txt` | 最近一次运行的证据（命令、语料规模、断言数、通过数、delta 规模对比表、失败/阻塞明细、文档歧义清单） |

依赖关系：`verify_deltasync.py` 是同目录 `dsref.py` 的唯一调用方（脚本会把自身所在目录加入
`sys.path` 并 `import dsref`）。两个文件必须放在同一个目录下一起使用；`dsref.py` 不依赖任何
第三方包，也不被被测项目引用。两者都不会写入 `__pycache__`（脚本设置 `sys.dont_write_bytecode`）。

## 用法

```powershell
# 全量（自测 + CLI 联调），从仓库根目录或 scripts/ 目录运行均可
D:\anaconda3\python.exe scripts\verify_deltasync.py

# 只跑自测（不需要 MoonBit 工具链 / CLI）：合成字节流验证解析器、重放器、规划器
D:\anaconda3\python.exe scripts\verify_deltasync.py --mode selftest

# 只跑 CLI 联调；--quick 跳过 2 MiB 大语料；--keep-temp 保留临时语料目录
D:\anaconda3\python.exe scripts\verify_deltasync.py --mode cli --quick

# 指定工具链与后端
D:\anaconda3\python.exe scripts\verify_deltasync.py `
  --moon 'D:\moonbit\_tools\moon-0.10.17\bin\moon.exe' --target js --timeout 300
```

退出码：

| 码 | 含义 |
| --- | --- |
| 0 | 全部硬断言通过 |
| 1 | 存在硬断言失败（见报告「失败明细」） |
| 2 | 自测通过，但 CLI 联调被阻塞（CLI 未实现 / 无法构建 / 探测失败，见「阻塞项」） |

## 断言覆盖（按类别）

- `selftest-hash` / `selftest-weak`：XXH64 官方测试向量（空/payload/39 字节跨 lane）、§6.1 弱校验公式、
  **与 `zlib.adler32` 逐位一致**（外部实现交叉验证）、滑动更新与直接计算一致性（约 1.5 万次滑窗）。
- `selftest-format`：DSIG/DDLT/DCHK 序列化↔解析逐字节往返；截断、错 magic、错版本、非法
  `strong_len`、`block_size=0`、超大 `block_count`/`op_count`/`chunk_count`/`literal length`、
  非法 op tag、DCHK `min>max`/`mask_bits>=64`/root 不符、尾部多余字节全部必须抛 `FormatError`。
- `selftest-replay`：重放 == new；篡改 delta 内强校验 → `BlockMismatch`；旧数据被替换 → `BlockMismatch`；
  块号越界 → `block-index`；长度不符 → `length`；delta 与签名摘要不一致 → `sig-mismatch`；
  **翻转 LITERAL 字节 → `digest-mismatch`**（由 §5.2 `content_digest` 兜底）。
- `selftest-planner`：相同数据 → 单 COPY_RUN（字节数 == 54+9+strong_len）；完全不同 → 纯 LITERAL；
  插入场景 literal 只承载改动区；规范化无相邻同类 op；规划→序列化→解析→重放闭环。
- `selftest-cdc`：`gear_table[i] == XXH64(单字节 i)`、块长上下界、可无损拼接、root 确定性、前缀复用率。
- `cli-sign`：JSON 契约字段与顺序、`block_count == ceil(total/block)`、§4.1 默认块大小、
  SHA-256 与 `hashlib` 一致、XXH64 与独立实现一致、`signature_bytes == 22+block_count*(4+strong_len)`、
  **每块 weak/strong 逐块独立重算一致**、`signature_sha256_hex`、DSIG 文件结构。
- `cli-delta`：DDLT 结构自洽、`op_count`/`copy_ops`/`copy_blocks`/`copied_bytes`/`literal_bytes`/
  `delta_bytes`/`savings_ratio` 全部按独立真值核对、规范化、**每个 COPY/COPY_RUN 自带强校验与独立重算一致**、
  `content_digest == sha256(new)`、独立重放逐字节相同、`delta_bytes ≤ 2 × 独立规划器`、§7.3 局部性上界。
- `cli-apply`：`ok`/`bytes_written`/`sha256_hex`/`blocks_verified`（== COPY 展开块数）/`ops_applied`、
  重建文件与 new 逐字节相同。
- `cli-interop`：把**独立规划器产出的 DDLT** 喂给 CLI `apply`，要求重建结果逐字节正确（双向互操作）。
- `cli-chunk`：JSON 字段与 `dedup_ratio == saved_bytes/length`、`stored_bytes+saved_bytes == length`；
  DCHK 独立解析 + root 重算 + 块长上下界；**§6.4 独立复现分块边界**（块数/块长/每块 sha256 逐块一致）；
  `manifest_bytes == DCHK 实际字节数`。
- `cli-verify`：正确摘要 → `ok:true` 且 rc=0；摘要合法但不匹配 → `ok:false` 且 rc=0（§8.1 语义）。
- `cli-malformed`：截断/错 magic/错版本/超大 count/非法 tag/块号越界/超大 new_length/block_size 越界/
  篡改强校验/篡改 content_digest/翻转 LITERAL/旧数据被替换/参数与路径错误 —— 一律要求
  `{"kind":"error",...}` + 非零退出码 + 无 panic。
- `cli-chunk-stability`：§7.5 前缀插入 1 字节后 ≥90% 块指纹复用（1 MiB 输入），并用本脚本 CDC 复算。
- `cli-cross-backend`：§7.7 js vs wasm-gc 的 DSIG 摘要、DDLT 字节、chunk root、apply 输出逐项一致，
  并把 js 的 DDLT 交给 wasm-gc `apply` 重建（跨后端互操作）。

## 已知限制

- **§7.4 的 LITERAL 翻转**依赖 `§5.2 content_digest` 兜底；若调用方手写 delta 且把 `content_digest`
  置零，则该类损坏不可检出（契约层面已由 content_digest 覆盖，报告 A2 记录）。
- DCHK 的 `manifest_bytes` 示例值与 §5.3 新布局的实际大小不一致（报告 A4）；本脚本断言「等于实际字节数」。
- `xxh64_hex` 字节序、JSON 字段顺序等文档未硬性规定处按 advisory 处理，并在报告「设计文档歧义」段落列出。
- 语料写入系统临时目录（`deltasync-verify-*`），默认运行结束即删除，不向仓库提交大文件；脚本也不会留下 `__pycache__`。
