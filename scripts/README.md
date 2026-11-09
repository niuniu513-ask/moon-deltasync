# scripts/ — 外部独立校验器

本目录是 `moon-deltasync` 的**第三方校验工具**，不属于库的实现代码，也不参与 `moon build`。

> 定位说明：这是**外部校验器**，不是官方验收结论。它按 `docs/design.md` 的语义**独立重写**了
> 哈希、二进制格式、delta 重放与 rsync 规划器，用来交叉验证被测实现；它不读取、不翻译
> `*.mbt` 源码，也不修改仓库中的任何 `.mbt` / `moon.mod` / `moon.pkg` / `docs/` 文件。

## 文件

| 文件 | 作用 |
| --- | --- |
| `dsref.py` | 按 design.md 独立实现的参考语义：Adler-32 变体弱校验（含滑动更新）、XXH64、DSIG/DDLT/DCHK 解析与序列化、delta 重放（逐 op 强校验）、rsync 风格规划器、CDC 参考实现（仅参考） |
| `verify_deltasync.py` | 自测 + CLI 联调 driver：生成固定种子语料、驱动 CLI、逐项断言、写 `verify-report.txt`、返回退出码 |
| `verify-report.txt` | 最近一次运行的证据（命令、语料规模、断言数、通过数、失败/阻塞明细、文档歧义清单） |

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

- `selftest-hash` / `selftest-weak`：XXH64 官方测试向量（空/payload/39 字节跨 lane）、弱校验公式、
  滑动更新与直接计算一致性（约 1.5 万次滑窗）。
- `selftest-format`：DSIG/DDLT/DCHK 序列化↔解析逐字节往返；截断、错 magic、错版本、非法
  `strong_len`、`block_size=0`、超大 `block_count`/`op_count`/`chunk_count`/`literal length`、
  非法 op tag、尾部多余字节全部必须抛 `FormatError`。
- `selftest-replay`：重放 == new；篡改 delta 内强校验 → `BlockMismatch`；旧数据被替换 → `BlockMismatch`；
  块号越界 → `block-index`；长度不符 → `length`；delta 与签名摘要不一致 → `sig-mismatch`。
- `selftest-planner`：相同数据 → 单 COPY_RUN；完全不同 → 纯 LITERAL；插入场景 literal 只承载改动区；
  规范化无相邻同类 op；规划→序列化→解析→重放闭环。
- `cli-sign`：JSON 契约字段、`total_length`、`block_count == ceil(total/block)`、§4.1 默认块大小、
  SHA-256 与 `hashlib` 一致、XXH64 与独立实现一致、DSIG 字节数 == 22+block_count*(4+strong_len)、
  **每块 weak/strong 逐块独立重算一致**、`signature_sha256_hex`。
- `cli-delta`：DDLT 结构自洽、JSON 各项统计（`op_count`/`copy_blocks`/`literal_bytes`/`delta_bytes`/
  `savings_ratio`）、规范化、**每个 COPY/COPY_RUN 自带强校验与独立重算一致**、独立重放逐字节相同、
  `delta_bytes ≤ 2 × 独立规划器`、§7.3 局部性上界。
- `cli-apply`：`ok`/`bytes_written`/`sha256_hex`、重建文件与 new 逐字节相同、`blocks_verified` 语义。
- `cli-interop`：把**独立规划器产出的 DDLT** 喂给 CLI `apply`，要求重建结果逐字节正确（双向互操作）。
- `cli-chunk`：`length`/`chunk_count`/`unique_chunks`/`dedup_ratio`/`root_hex`/`manifest_bytes`；
  若 `chunk --out` 能导出 DCHK，则独立解析 DCHK 并重算 root、块长守恒、去重计数、块长上下界。
- `cli-verify`：正确 SHA-256 → `ok:true`；错误 SHA-256 → `error` JSON + 非零退出码。
- `cli-malformed`：截断/错 magic/错版本/超大 count/非法 tag/块号越界/超大 new_length/block_size 越界、
  篡改 COPY 强校验、旧数据被替换、参数与路径错误 —— 一律要求 `{"kind":"error",...}` + 非零退出码 + 无 panic。
- `cli-chunk-stability`：§7.5 前缀插入 1 字节后 ≥90% 块指纹复用（需要 DCHK 可导出）。

## 已知限制

- **CDC 边界不可独立复现**：design.md 未规定 gear 表，本工具只校验结构性质，不比较切分边界。
- **§7.4 的 LITERAL 翻转不可检出**：DDLT v1 不为 LITERAL 携带校验，该场景只记录行为（INFO），不作为失败。
- `xxh64_hex` 字节序、`manifest_bytes` 统计口径等文档未定义项，按 advisory 处理并在报告「设计文档歧义」段落列出。
- 语料写入系统临时目录（`deltasync-verify-*`），默认运行结束即删除，不向仓库提交大文件。
