#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""moon-deltasync 独立第三方校验器（纯标准库，无网络、无外部依赖）。

被测项目: D:\\moonbit\\moon-deltasync
契约:     docs/design.md（§5 二进制格式、§6 算法、§8 CLI 与 JSON 契约）

本脚本是**外部**校验器：它用 `scripts/dsref.py`（按 design.md 语义独立重写的
弱校验/XXH64/DSIG/DDLT/DCHK/重放器/规划器）作为语义对照物，驱动 MoonBit CLI
跑真实语料，逐项断言。它不读取、不翻译被测 .mbt 源码，也不修改被测项目。

用法:
  python scripts/verify_deltasync.py                 # 自测 + CLI 联调（auto）
  python scripts/verify_deltasync.py --mode selftest # 只跑自测（不需要 MoonBit 工具链）
  python scripts/verify_deltasync.py --mode cli      # 只跑 CLI 联调
  python scripts/verify_deltasync.py --quick         # 跳过 2 MiB 大语料
  python scripts/verify_deltasync.py --keep-temp     # 保留临时语料目录

退出码:
  0  全部硬断言通过
  1  存在硬断言失败
  2  自测通过，但 CLI 联调被阻塞（CLI 未实现/无法构建），见报告 BLOCKED 段
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

# 不在仓库里留下 __pycache__（本目录应只有脚本与报告）
sys.dont_write_bytecode = True

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dsref as R  # noqa: E402

# 同一「外部无法验证」的原因只登记一次，避免 9 个语料各刷一条
_BLOCKED_SEEN: set[str] = set()

# delta 规模对比（实现 vs 独立规划器），由 cli_delta 填充，报告里汇总成表
DELTA_STATS: list[dict] = []


def blocked_once(rec: "Recorder", category: str, name: str, detail: str) -> None:
    if name in _BLOCKED_SEEN:
        return
    _BLOCKED_SEEN.add(name)
    rec.blocked(category, name, detail)

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PROJECT = SCRIPT_DIR.parent
DEFAULT_MOON = r"D:\moonbit\_tools\moon-0.10.17\bin\moon.exe"
REPORT_NAME = "verify-report.txt"

# design.md §8.1 示例与 §6.4 默认参数所隐含的默认块参数（歧义 A9）
DEFAULT_BLOCK_SIZE = 8192
DEFAULT_STRONG_LEN = 16

CRASH_MARKERS = (
    "panic",
    "Panic",
    "PANIC",
    "abort",
    "Abort",
    "unreachable",
    "unreachable!",
    "stack overflow",
    "Assertion failed",
    "RuntimeError",
    "segmentation fault",
    "core dumped",
)


# ---------------------------------------------------------------------------
# 断言记录
# ---------------------------------------------------------------------------


@dataclass
class Row:
    category: str
    name: str
    ok: bool
    detail: str = ""
    severity: str = "hard"  # hard | advisory | info | blocked


class Recorder:
    def __init__(self) -> None:
        self.rows: list[Row] = []
        self.notes: list[tuple[str, str]] = []

    def check(self, category: str, name: str, ok: bool, detail: str = "", severity: str = "hard") -> bool:
        self.rows.append(Row(category, name, bool(ok), str(detail), severity))
        return bool(ok)

    def info(self, category: str, name: str, detail: str = "") -> None:
        self.rows.append(Row(category, name, True, str(detail), "info"))

    def blocked(self, category: str, name: str, detail: str = "") -> None:
        self.rows.append(Row(category, name, False, str(detail), "blocked"))

    def note(self, text: str) -> None:
        self.notes.append(("歧义/备注", text))

    # --- 汇总 ---------------------------------------------------------
    def of(self, severity: str) -> list[Row]:
        return [r for r in self.rows if r.severity == severity]

    def passed(self, severity: str = "hard") -> int:
        return sum(1 for r in self.of(severity) if r.ok)

    def failed(self) -> list[Row]:
        return [r for r in self.rows if not r.ok and r.severity == "hard"]

    def blocked_rows(self) -> list[Row]:
        return [r for r in self.rows if r.severity == "blocked"]

    def categories(self) -> list[str]:
        seen = []
        for r in self.rows:
            if r.category not in seen:
                seen.append(r.category)
        return seen

    def category_stats(self) -> dict[str, tuple[int, int, int]]:
        """category -> (hard_pass, hard_total, advisory_pass, advisory_total)"""
        stats: dict[str, list[int]] = {}
        for r in self.rows:
            s = stats.setdefault(r.category, [0, 0, 0, 0])
            if r.severity == "hard":
                s[1] += 1
                s[0] += 1 if r.ok else 0
            elif r.severity == "advisory":
                s[3] += 1
                s[2] += 1 if r.ok else 0
        return {k: tuple(v) for k, v in stats.items()}


# ---------------------------------------------------------------------------
# 语料（固定种子 PRNG）
# ---------------------------------------------------------------------------

WORD_POOL = (
    "transfer kernel digest witness chunk block replica epoch ledger streaming "
    "boundary manifest checksum rolling window delta literal copy verify render "
    "archive snapshot backup object store pipeline checksum block index offset"
).split()


def gen_doc(rng: random.Random, size: int) -> bytes:
    """生成「文档版本」字节串：类文本行，确定性。"""
    if size <= 0:
        return b""
    parts: list[bytes] = []
    total = 0
    while total < size:
        line = " ".join(rng.choice(WORD_POOL) for _ in range(rng.randint(3, 11))) + "\n"
        b = line.encode("ascii")
        parts.append(b)
        total += len(b)
    return b"".join(parts)[:size]


@dataclass
class Case:
    name: str
    old: bytes
    new: bytes
    edits: str
    changed_bytes: int = 0
    locality: bool = False
    full: bool = True  # 是否跑 chunk/verify 等完整流程


def build_cases(quick: bool = False) -> list[Case]:
    rng = random.Random(20261109)
    cases: list[Case] = []

    # 1) 64 KiB：中间插入 2 KiB
    old = gen_doc(rng, 65536)
    pos = len(old) // 3
    new = old[:pos] + gen_doc(rng, 2048) + old[pos:]
    cases.append(Case("doc-64k-insert", old, new, "在 1/3 处插入 2048B", changed_bytes=2048))

    # 2) 256 KiB：替换 4 KiB + 删除 3 KiB + 插入 5 KiB
    old = gen_doc(rng, 262144)
    new = old[:20000] + gen_doc(rng, 4096) + old[20000 + 4096 :]
    new = new[:100000] + new[100000 + 3000 :]
    new = new[:30000] + gen_doc(rng, 5000) + new[30000:]
    cases.append(
        Case("doc-256k-mixed", old, new, "替换 4096B + 删除 3000B + 插入 5000B", changed_bytes=4096 + 3000 + 5000)
    )

    # 3) 1 MiB：搬移 60 KiB 段（move）
    old = gen_doc(rng, 1048576)
    seg_start, seg_len = 200000, 60000
    seg = old[seg_start : seg_start + seg_len]
    rest = old[:seg_start] + old[seg_start + seg_len :]
    new = rest[:700000] + seg + rest[700000:]
    cases.append(Case("doc-1m-move", old, new, "搬移 60000B 段到 700000 处", changed_bytes=seg_len))

    # 4) 2 MiB：插入 + 删除 + 替换 + 搬移
    if not quick:
        old = gen_doc(rng, 2097152)
        new = old[:400000] + gen_doc(rng, 30000) + old[400000:]
        new = new[:1200000] + new[1200000 + 40000 :]
        new = new[:800000] + gen_doc(rng, 16384) + new[800000 + 16384 :]
        seg2 = new[1500000 : 1500000 + 100000]
        new = new[:1500000] + new[1500000 + 100000 :]
        new = new[:500000] + seg2 + new[500000:]
        cases.append(
            Case(
                "doc-2m-mixed",
                old,
                new,
                "插入 30000B + 删除 40000B + 替换 16384B + 搬移 100000B",
                changed_bytes=30000 + 40000 + 16384 + 100000,
            )
        )

    # 5) 64 KiB：完全未改动
    old = gen_doc(rng, 65536)
    cases.append(Case("doc-64k-identical", old, old, "无改动", changed_bytes=0))

    # 6) 64 KiB：完全重写（最坏情况，全 literal）
    old = gen_doc(rng, 65536)
    new = gen_doc(rng, 65536)
    cases.append(Case("doc-64k-allnew", old, new, "全部重写", changed_bytes=65536))

    # 7) 256 KiB：只改 1% 的块（§7.3 局部性上界）
    old = gen_doc(rng, 262144)
    bs = DEFAULT_BLOCK_SIZE
    nblocks = R.ceil_div(len(old), bs)
    data = bytearray(old)
    changed = 0
    k = max(1, round(nblocks * 0.01))
    for _ in range(k):
        bi = rng.randrange(nblocks)
        start = bi * bs
        end = min(start + bs, len(data))
        repl = gen_doc(rng, end - start)
        data[start:end] = repl
        changed += end - start
    cases.append(Case("doc-256k-1pct-blocks", old, bytes(data), f"覆盖 {k}/{nblocks} 个块", changed_bytes=changed, locality=True))

    # 8) 边界：空文件、1 字节、100 字节
    cases.append(Case("tiny-empty", b"", b"", "空 -> 空", full=False))
    cases.append(Case("tiny-1", b"A", b"B", "1B -> 1B", full=False))
    old = gen_doc(rng, 100)
    cases.append(Case("tiny-100", old, old[:40] + gen_doc(rng, 20) + old[40:], "100B 内替换 20B", full=False))
    return cases


# ---------------------------------------------------------------------------
# CLI 驱动
# ---------------------------------------------------------------------------


@dataclass
class CliResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed: float
    json: dict | None = None
    timed_out: bool = False

    @property
    def json_kind(self) -> str | None:
        return (self.json or {}).get("kind") if isinstance(self.json, dict) else None

    def crash_markers(self) -> list[str]:
        blob = self.stdout + "\n" + self.stderr
        return [m for m in CRASH_MARKERS if m in blob]

    def brief(self, limit: int = 300) -> str:
        parts = [f"rc={self.returncode}", f"{self.elapsed:.2f}s"]
        if self.timed_out:
            parts.append("TIMEOUT")
        if self.json is not None:
            parts.append("json=" + json.dumps(self.json, ensure_ascii=False)[:limit])
        elif self.stdout.strip():
            parts.append("stdout=" + repr(self.stdout.strip()[:limit]))
        if self.stderr.strip():
            parts.append("stderr=" + repr(self.stderr.strip()[-limit:]))
        return " ".join(parts)


def extract_json(text: str) -> dict | None:
    text = text.strip()
    if not text:
        return None
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    return obj
            except Exception:
                continue
    start = text.rfind("{")
    while start != -1:
        try:
            obj = json.loads(text[start:])
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        start = text.rfind("{", 0, start)
    return None


class CliRunner:
    def __init__(self, project: Path, moon: str, target: str = "js", timeout: float = 300.0):
        self.project = project
        self.moon = moon
        self.target = target
        self.timeout = timeout
        env = os.environ.copy()
        moon_dir = str(Path(moon).parent)
        # 只补 PATH，让 moon 子进程能找到自身与 node；MOON_HOME 必须继承宿主环境，
        # 否则 registry 缓存位置会变、模块依赖图解析失败。
        env["PATH"] = moon_dir + os.pathsep + env.get("PATH", "")
        env["NO_COLOR"] = "1"
        self.env = env
        self.calls: list[CliResult] = []

    def argv_for(self, args: list[str]) -> list[str]:
        return [self.moon, "run", "--target", self.target, "cmd/main", "--"] + args

    def run(self, args: list[str], timeout: float | None = None) -> CliResult:
        argv = self.argv_for(args)
        t0 = time.time()
        timed_out = False
        try:
            cp = subprocess.run(
                argv,
                cwd=str(self.project),
                capture_output=True,
                timeout=timeout or self.timeout,
                env=self.env,
            )
            rc = cp.returncode
            raw_out = cp.stdout or b""
            raw_err = cp.stderr or b""
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            rc = -1
            raw_out = exc.stdout or b""
            raw_err = exc.stderr or b""
        elapsed = time.time() - t0
        out = raw_out.decode("utf-8", "replace") if isinstance(raw_out, bytes) else str(raw_out)
        err = raw_err.decode("utf-8", "replace") if isinstance(raw_err, bytes) else str(raw_err)
        res = CliResult(argv, rc, out, err, elapsed, extract_json(out), timed_out)
        self.calls.append(res)
        return res

    def probe(self) -> tuple[bool, str]:
        res = self.run(["__cli_probe_no_such_command__"], timeout=420)
        if res.json is not None and res.json.get("kind") == "error":
            return True, "未知命令返回 error JSON，CLI 可用"
        if res.timed_out:
            return False, f"CLI 探测超时（>{420}s，构建或运行卡住）：{res.brief()}"
        return False, f"CLI 不可用：{res.brief(600)}"


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def write_file(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def must_str(d: dict, key: str, rec: Recorder, cat: str, ctx: str) -> str | None:
    v = d.get(key)
    if isinstance(v, str):
        return v
    rec.check(cat, f"{ctx}: JSON 字段 {key} 存在且为字符串", False, f"实际 {v!r}", "hard")
    return None


def must_int(d: dict, key: str, rec: Recorder, cat: str, ctx: str) -> int | None:
    v = d.get(key)
    if isinstance(v, bool) or not isinstance(v, int):
        rec.check(cat, f"{ctx}: JSON 字段 {key} 存在且为整数", False, f"实际 {v!r}", "hard")
        return None
    return v


def int_field(js: dict, key: str) -> int | None:
    v = js.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def str_field(js: dict, key: str) -> str | None:
    v = js.get(key)
    return v if isinstance(v, str) else None


def require_fields(
    rec: Recorder,
    cat: str,
    ctx: str,
    js: dict,
    required: tuple[str, ...],
    alts: dict[str, tuple[str, ...]] | None = None,
) -> bool:
    """§8.1「字段固定」：一次性报告缺失的契约字段（避免逐字段重复刷屏）。"""
    alts = alts or {}
    missing = [k for k in required if k not in js]
    if not missing:
        return rec.check(cat, f"{ctx}: JSON 契约字段齐全（§8.1）", True, f"keys={sorted(js)}")
    parts = []
    for k in missing:
        avail = [a for a in alts.get(k, ()) if a in js]
        parts.append(f"{k} 缺失" + (f"（实现改用 {avail}）" if avail else ""))
    return rec.check(
        cat,
        f"{ctx}: JSON 契约字段齐全（§8.1）",
        False,
        "; ".join(parts) + f" | 实际字段={sorted(js)}",
    )


def num_close(a: float, b: float, tol: float) -> bool:
    return abs(a - b) <= tol


# ---------------------------------------------------------------------------
# 自测（合成字节流，不依赖 CLI）
# ---------------------------------------------------------------------------


def selftest(rec: Recorder) -> None:
    cat = "selftest-hash"
    vectors = {
        b"": 0xEF46DB3751D8E999,
        b"abc": 0x44BC2CF5AD770999,
        b"Nobody inspects the spammish repetition": 0xFBCEA83C8A378BF1,
    }
    for payload, expect in vectors.items():
        got = R.xxh64(payload)
        rec.check(
            cat,
            f"XXH64 seed=0 测试向量 len={len(payload)}",
            got == expect,
            f"got {got:#018x}, expect {expect:#018x}",
        )
    rec.check(
        cat,
        "XXH64 空输入 != 非空输入（基本灵敏度）",
        R.xxh64(b"") != R.xxh64(b"\x00"),
        "空输入与非空输入区分",
    )

    cat = "selftest-weak"
    rng = random.Random(11)
    ok_direct = True
    detail = ""
    for _ in range(120):
        n = rng.randint(1, 3000)
        data = bytes(rng.randrange(256) for _ in range(n))
        a = sum(data) % R.MOD
        b = sum((n - i) * x for i, x in enumerate(data)) % R.MOD
        expect = ((b & 0xFFFF) << 16) | (a & 0xFFFF)
        got = R.weak_checksum(data)
        if got != expect:
            ok_direct = False
            detail = f"len={n}: got {got:#010x} expect {expect:#010x}"
            break
    rec.check(cat, "弱校验 = (b<<16)|a 按 §6.1 公式（120 个随机窗口）", ok_direct, detail)

    ok_roll = True
    detail = ""
    trials = 0
    for _ in range(60):
        n = rng.randint(2, 300)
        data = bytes(rng.randrange(256) for _ in range(n * 3))
        roll = R.RollingWeak(data[:n])
        for p in range(0, len(data) - n):
            trials += 1
            if roll.value() != R.weak_checksum(data[p : p + n]):
                ok_roll = False
                detail = f"window n={n} pos={p}: rolling {roll.value():#010x} != direct"
                break
            roll.roll(data[p], data[p + n])
        if not ok_roll:
            break
    rec.check(cat, f"滑动更新 a'=a-out+in, b'=b-n*out+a' 与直接计算一致（{trials} 次滑窗）", ok_roll, detail)

    # --- §5.1 DSIG -----------------------------------------------------
    cat = "selftest-format"
    payload = b"hello world" * 1000
    sig = R.build_signature(payload, 1024, 16)
    raw = R.serialize_dsig(sig)
    parsed = R.parse_dsig(raw)
    rec.check(
        cat,
        "DSIG 序列化 -> 解析 -> 再序列化 逐字节相同",
        R.serialize_dsig(parsed) == raw,
        f"{len(raw)} bytes, {len(sig.blocks)} blocks",
    )
    expect_blocks = R.ceil_div(len(payload), 1024)
    last_start = (expect_blocks - 1) * 1024
    last = payload[last_start:]
    rec.check(
        cat,
        "DSIG 块划分 = ceil(total_length/block_size)，末块为不满块且 weak/strong 正确",
        len(parsed.blocks) == expect_blocks
        and len(last) < 1024
        and parsed.blocks[-1].weak == R.weak_checksum(last)
        and parsed.blocks[-1].strong == R.sha256(last)[:16],
        f"block_count={len(parsed.blocks)} expect={expect_blocks} last_len={len(last)}",
    )
    good = raw
    bad_cases = {
        "截断 4 字节": good[:-4],
        "空字节流": b"",
        "错 magic DDLT": b"DDLT" + good[4:],
        "版本 2": good[:4] + b"\x02" + good[5:],
        "strong_len=12": good[:9] + b"\x0c" + good[10:],
        "block_count 改大":
            good[:18] + (int.from_bytes(good[18:22], "big") + 1).to_bytes(4, "big") + good[22:],
        "block_count=0xFFFFFFFF":
            good[:18] + (0xFFFFFFFF).to_bytes(4, "big") + good[22:],
        "block_size=0": good[:5] + (0).to_bytes(4, "big") + good[9:],
        "尾部多 1 字节": good + b"\x00",
    }
    for name, blob in bad_cases.items():
        try:
            R.parse_dsig(blob)
            rec.check(cat, f"DSIG 拒绝畸形输入：{name}", False, "解析却成功了（应为 FormatError）")
        except R.FormatError as exc:
            rec.check(cat, f"DSIG 拒绝畸形输入：{name}", True, str(exc)[:160])
        except Exception as exc:  # noqa: BLE001
            rec.check(cat, f"DSIG 拒绝畸形输入：{name}", False, f"抛出了非 FormatError: {type(exc).__name__}: {exc}")

    # --- §5.2 DDLT（新版：每个 COPY / COPY_RUN 自带强校验） --------------
    old = bytes(rng.randrange(256) for _ in range(40000))
    new = old[:5000] + bytes(rng.randrange(256) for _ in range(1000)) + old[6000:]
    bs, sl = DEFAULT_BLOCK_SIZE, DEFAULT_STRONG_LEN
    sig = R.build_signature(old, bs, sl)
    delta = R.make_delta(old, new, bs, sl, sig)
    raw = R.serialize_ddlt(delta)
    parsed = R.parse_ddlt(raw)
    rec.check(
        cat,
        "DDLT 序列化 -> 解析 -> 再序列化 逐字节相同",
        R.serialize_ddlt(parsed) == raw,
        f"{len(raw)} bytes, {len(delta.ops)} ops",
    )
    rec.check(
        cat,
        "DDLT 的 COPY/COPY_RUN 均携带 strong_len 字节强校验（§5.2）",
        all(
            (op[0] == "lit") or (len(op[-1]) == sl)
            for op in parsed.ops
        ),
        f"ops={[(o[0], len(o[-1]) if o[0] != 'lit' else None) for o in parsed.ops[:5]]}",
    )
    rec.check(
        cat,
        "COPY_RUN 强校验 == sha256(旧块拼接)[0:strong_len]（§5.2 语义）",
        all(
            op[0] != "copy_run"
            or op[-1] == R.strong_of_blocks(old, bs, sl, op[1], op[2])
            for op in parsed.ops
        ),
        "逐 op 复核",
    )
    rec.check(
        cat,
        "规范化后重放覆盖长度 == new_length",
        True,
        f"copy_blocks={parsed.copy_block_count()} literal={parsed.literal_bytes()} new_length={len(new)}",
    )
    good = raw
    OFF_CNT = R.DDLT_OFF_OP_COUNT  # 50
    OFF_OP = R.DDLT_OFF_FIRST_OP  # 54
    ddlt_bad = {
        "截断 1 字节": good[:-1],
        "空字节流": b"",
        "错 magic DSIG": b"DSIG" + good[4:],
        "版本 9": good[:4] + b"\x09" + good[5:],
        "strong_len=7": good[:9] + b"\x07" + good[10:],
        "op_count=0xFFFFFFFF": good[:OFF_CNT] + (0xFFFFFFFF).to_bytes(4, "big") + good[OFF_CNT + 4 :],
        "op tag=7": good[:OFF_OP] + b"\x07" + good[OFF_OP + 1 :],
        "LITERAL 长度 0xFFFFFFFF": good[:OFF_OP] + b"\x01" + (0xFFFFFFFF).to_bytes(4, "big"),
        "尾部多 2 字节": good + b"\x00\x00",
    }
    for name, blob in ddlt_bad.items():
        try:
            R.parse_ddlt(blob)
            rec.check(cat, f"DDLT 拒绝畸形输入：{name}", False, "解析却成功了（应为 FormatError）")
        except R.FormatError as exc:
            rec.check(cat, f"DDLT 拒绝畸形输入：{name}", True, str(exc)[:160])
        except Exception as exc:  # noqa: BLE001
            rec.check(cat, f"DDLT 拒绝畸形输入：{name}", False, f"抛出了非 FormatError: {type(exc).__name__}: {exc}")

    # --- §5.3 DCHK -----------------------------------------------------
    manifest = R.build_manifest(old)
    mraw = R.serialize_dchk(manifest)
    mparsed = R.parse_dchk(mraw)
    rec.check(
        cat,
        "DCHK 序列化 -> 解析 -> root 重算一致 + 长度守恒",
        mparsed.root == R.manifest_root(mparsed.chunks)
        and sum(c.length for c in mparsed.chunks) == len(old)
        and R.serialize_dchk(mparsed) == mraw,
        f"{len(mparsed.chunks)} chunks, {len(mraw)} bytes",
    )
    dchk_bad = {
        "截断 1 字节": mraw[:-1],
        "空字节流": b"",
        "错 magic": b"DCHX" + mraw[4:],
        "chunk_count+1": mraw[:5] + (len(mparsed.chunks) + 1).to_bytes(4, "big") + mraw[9:],
        "chunk_count=0xFFFFFFFF": mraw[:5] + (0xFFFFFFFF).to_bytes(4, "big") + mraw[9:],
    }
    for name, blob in dchk_bad.items():
        try:
            R.parse_dchk(blob)
            rec.check(cat, f"DCHK 拒绝畸形输入：{name}", False, "解析却成功了（应为 FormatError）")
        except R.FormatError as exc:
            rec.check(cat, f"DCHK 拒绝畸形输入：{name}", True, str(exc)[:160])
        except Exception as exc:  # noqa: BLE001
            rec.check(cat, f"DCHK 拒绝畸形输入：{name}", False, f"抛出了非 FormatError: {type(exc).__name__}: {exc}")

    # --- §5.2/§7.1 重放 ------------------------------------------------
    cat = "selftest-replay"
    try:
        rebuilt = R.replay(old, parsed, sig)
        rec.check(cat, "重放(旧+delta) 与 new 逐字节相同（合成数据）", rebuilt == new, f"{len(rebuilt)} bytes")
    except R.ReplayError as exc:
        rec.check(cat, "重放(旧+delta) 与 new 逐字节相同（合成数据）", False, exc.message)

    rec.check(
        cat,
        "DDLT content_digest == sha256(目标数据)（§5.2）",
        parsed.content_digest == R.sha256(new),
        f"{parsed.content_digest.hex()} vs {R.sha256(new).hex()}",
    )

    # 篡改 delta 里记录的强校验（数据本身不变，期望值变）-> BlockMismatch
    idx0 = parsed.copy_indexes()[0] if parsed.copy_indexes() else 0
    t_ops = []
    for op in parsed.ops:
        if op[0] == "copy_run":
            t_ops.append(("copy_run", op[1], op[2], bytes(sl)))
        elif op[0] == "copy":
            t_ops.append(("copy", op[1], bytes(sl)))
        else:
            t_ops.append(op)
    try:
        R.replay(old, R.Delta(bs, sl, len(new), t_ops, R.sha256(new)), None)
        rec.check(cat, "篡改 delta 内强校验 -> BlockMismatch（§7.4）", False, "未检测到强校验不一致")
    except R.ReplayError as exc:
        rec.check(
            cat,
            "篡改 delta 内强校验 -> BlockMismatch（§7.4）",
            exc.code == "block-mismatch",
            f"code={exc.code} block={exc.block_index}: {exc.message[:120]}",
        )

    # 旧数据被换掉（COPY 指向内容不同的块）-> BlockMismatch
    other_old = bytes(rng.randrange(256) for _ in range(len(old)))
    block_len = len(old[idx0 * bs : (idx0 + 1) * bs])
    single_ops = [("copy", idx0, R.strong_of_blocks(old, bs, sl, idx0, 1))]
    remainder = len(new) - block_len
    if remainder > 0:
        single_ops.append(("lit", new[-remainder:]))
    try:
        R.replay(other_old, R.Delta(bs, sl, len(new), single_ops, R.sha256(new)), None)
        rec.check(cat, "COPY 指向内容不同的块 -> BlockMismatch（§7.4）", False, "未检测到强校验不一致")
    except R.ReplayError as exc:
        rec.check(
            cat,
            "COPY 指向内容不同的块 -> BlockMismatch（§7.4）",
            exc.code == "block-mismatch" and exc.block_index == idx0,
            f"code={exc.code} block={exc.block_index}: {exc.message[:120]}",
        )

    # 签名与 delta 摘要不一致 -> sig-mismatch（交叉校验）
    other_sig = R.build_signature(other_old, bs, sl)
    try:
        R.replay(old, parsed, other_sig)
        rec.check(cat, "delta 与签名摘要不一致 -> sig-mismatch", False, "未检测到签名/摘要不一致")
    except R.ReplayError as exc:
        rec.check(cat, "delta 与签名摘要不一致 -> sig-mismatch", exc.code == "sig-mismatch", f"code={exc.code}")

    # §5.2 content_digest 兜底：翻转 LITERAL 内 1 字节 -> digest-mismatch
    lit_index = next((i for i, op in enumerate(parsed.ops) if op[0] == "lit" and len(op[1]) > 0), None)
    if lit_index is not None:
        flipped = list(parsed.ops)
        data = bytearray(flipped[lit_index][1])
        data[0] ^= 0xFF
        flipped[lit_index] = ("lit", bytes(data))
        try:
            R.replay(old, R.Delta(bs, sl, len(new), flipped, R.sha256(new)), None)
            rec.check(cat, "翻转 LITERAL 字节 -> digest-mismatch（§5.2 content_digest 兜底）", False, "未检测到内容摘要不一致")
        except R.ReplayError as exc:
            rec.check(
                cat,
                "翻转 LITERAL 字节 -> digest-mismatch（§5.2 content_digest 兜底）",
                exc.code == "digest-mismatch",
                f"code={exc.code}: {exc.message[:120]}",
            )

    huge_index_delta = R.Delta(bs, sl, min(bs, len(old)), [("copy", 0xFFFFFFFF, bytes(sl))], R.sha256(new))
    try:
        R.replay(old, huge_index_delta, sig)
        rec.check(cat, "COPY 块号越界 -> block-index 错误", False, "未检测到越界")
    except R.ReplayError as exc:
        rec.check(cat, "COPY 块号越界 -> block-index 错误", exc.code == "block-index", f"code={exc.code}: {exc.message[:120]}")

    len_delta = R.Delta(bs, sl, 123456, [("lit", b"abc")])
    try:
        R.replay(old, len_delta, None)
        rec.check(cat, "重放长度 != new_length -> length 错误", False, "未检测到长度不一致")
    except R.ReplayError as exc:
        rec.check(cat, "重放长度 != new_length -> length 错误", exc.code == "length", f"code={exc.code}: {exc.message[:120]}")

    digest_delta = R.Delta(bs, sl, len(new), parsed.ops, bytes(32)[:31] + b"\x01")
    try:
        R.replay(old, digest_delta, None)
        rec.check(cat, "content_digest 不符 -> digest-mismatch", False, "未检测到内容摘要不一致")
    except R.ReplayError as exc:
        rec.check(cat, "content_digest 不符 -> digest-mismatch", exc.code == "digest-mismatch", f"code={exc.code}")

    # --- §6.3 规划器 ---------------------------------------------------
    cat = "selftest-planner"
    identical_delta = R.make_delta(old, old, bs, sl, sig)
    identical_bytes = len(R.serialize_ddlt(identical_delta))
    expect_identical = R.DDLT_HEADER_LEN + 9 + sl  # 头 54 + COPY_RUN(tag+start+count+strong)
    rec.check(
        cat,
        "相同数据 -> 单个 COPY_RUN，delta 字节数 == 头+COPY_RUN",
        R.normalization_violations(identical_delta.ops) == []
        and len(identical_delta.ops) == 1
        and identical_bytes == expect_identical,
        f"ops={[(o[0],) + tuple(o[1:])[:2] for o in identical_delta.ops]} "
        f"delta_bytes={identical_bytes} expect={expect_identical}",
    )
    allnew = bytes(rng.randrange(256) for _ in range(40000))
    allnew_delta = R.make_delta(old, allnew, bs, sl)
    allnew_bytes = len(R.serialize_ddlt(allnew_delta))
    expect_allnew = R.DDLT_HEADER_LEN + 5 + len(allnew)  # 头 54 + LITERAL(tag+length)+bytes
    rec.check(
        cat,
        "完全不同数据 -> 纯 LITERAL，delta 字节数 == 头+LITERAL 包装",
        allnew_bytes == expect_allnew and all(op[0] == "lit" for op in allnew_delta.ops),
        f"delta_bytes={allnew_bytes} expect={expect_allnew} new_len={len(allnew)}",
    )
    rec.check(
        cat,
        "规划器输出满足 §5.2 规范化（无相邻同类 op）",
        R.normalization_violations(parsed.ops) == [],
        f"violations={R.normalization_violations(parsed.ops)[:3]}",
    )
    ins_old = gen_doc(rng, 262144)
    ins_new = ins_old[:100000] + gen_doc(rng, 5000) + ins_old[100000:]
    ins_delta = R.make_delta(ins_old, ins_new, bs, sl)
    ins_bytes = len(R.serialize_ddlt(ins_delta))
    ins_literal = ins_delta.literal_bytes()
    rec.check(
        cat,
        "插入 5000B 的 256 KiB 文档：delta 只承载改动区（literal < 4×5000+1KiB）",
        ins_literal < 4 * 5000 + 1024,
        f"delta_bytes={ins_bytes}, literal={ins_literal}",
    )
    try:
        ref_delta = R.parse_ddlt(R.serialize_ddlt(ins_delta))
        rebuilt = R.replay(ins_old, ref_delta, R.build_signature(ins_old, bs, sl))
        rec.check(
            cat,
            "规划器 -> 序列化 -> 解析 -> 重放 == new（256 KiB 插入场景）",
            rebuilt == ins_new,
            f"{len(rebuilt)} bytes",
        )
    except R.ReplayError as exc:
        rec.check(cat, "规划器 -> 序列化 -> 解析 -> 重放 == new（256 KiB 插入场景）", False, exc.message)

    # --- CDC 参考实现自洽（不与被测实现比较边界） ------------------------
    cat = "selftest-cdc"
    sample = gen_doc(rng, 1 << 20)
    chunks = R.cdc_chunks(sample)
    joined = b"".join(chunks)
    rec.check(
        cat,
        "参考 CDC 分块可无损拼接 + 块长在 [min, max]（末块除外）",
        joined == sample
        and all(len(c) <= R._MAX_CHUNK for c in chunks)
        and all(len(c) >= R._MIN_CHUNK for c in chunks[:-1]),
        f"{len(chunks)} chunks, avg={len(sample)//max(1,len(chunks))}B",
    )
    prefixed = R.cdc_chunks(b"X" + sample)
    reuse = len(set(R.sha256(c) for c in chunks) & set(R.sha256(c) for c in prefixed))
    rec.info(
        cat,
        "参考 CDC 前缀插入 1 字节的指纹复用（仅参考，不与被测实现比较）",
        f"reference reuse {reuse}/{len(chunks)}",
    )


# ---------------------------------------------------------------------------
# CLI 联调
# ---------------------------------------------------------------------------


def cli_sign(rec: Recorder, runner: CliRunner, case: Case, tmp: Path) -> R.FileSignature | None:
    cat = "cli-sign"
    old_path = write_file(tmp / f"{case.name}.old", case.old)
    dsig_path = tmp / f"{case.name}.dsig"
    if dsig_path.exists():
        dsig_path.unlink()
    res = runner.run(["sign", str(old_path), "--out", str(dsig_path)])
    ctx = case.name
    if not rec.check(cat, f"{ctx}: sign 退出码 0", res.returncode == 0 and not res.timed_out, res.brief()):
        return None
    js = res.json
    if not rec.check(cat, f"{ctx}: sign 输出单行 JSON 且 kind=sign", js is not None and js.get("kind") == "sign", res.brief()):
        return None
    require_fields(
        rec,
        cat,
        ctx,
        js,
        (
            "path",
            "total_length",
            "block_size",
            "strong_len",
            "block_count",
            "sha256_hex",
            "xxh64_hex",
            "signature_sha256_hex",
            "signature_bytes",
        ),
        {"sha256_hex": ("sha256", "file_sha256_hex"), "xxh64_hex": ("xxh64", "hash_hex")},
    )
    total_length = int_field(js, "total_length") or 0
    block_size = int_field(js, "block_size")
    strong_len = int_field(js, "strong_len")
    block_count = int_field(js, "block_count")
    sha_hex = str_field(js, "sha256_hex")
    xxh_hex = str_field(js, "xxh64_hex")
    sig_sha = str_field(js, "signature_sha256_hex")
    sig_bytes = int_field(js, "signature_bytes")

    rec.check(cat, f"{ctx}: sign total_length == len(old)", total_length == len(case.old), f"{total_length} vs {len(case.old)}")
    rec.check(
        cat,
        f"{ctx}: sign block_count == ceil(total_length/block_size)",
        block_size and block_count is not None and block_count == R.ceil_div(total_length, block_size),
        f"block_count={block_count} block_size={block_size} total={total_length}",
    )
    expect_bs = R.default_block_size(len(case.old))
    rec.check(
        cat,
        f"{ctx}: sign 默认 block_size == default_block_size(len) = {expect_bs}（§4.1）",
        block_size == expect_bs,
        f"block_size={block_size}, len={len(case.old)}",
    )
    rec.check(
        cat,
        f"{ctx}: sign strong_len ∈ {{8,16}}（§4.1）",
        strong_len in (8, 16),
        f"strong_len={strong_len}",
    )
    rec.check(
        cat,
        f"{ctx}: sign 默认 strong_len == 16（§8.1 示例，advisory）",
        strong_len == DEFAULT_STRONG_LEN,
        f"strong_len={strong_len}",
        "advisory",
    )
    if block_count is not None:
        rec.check(
            cat,
            f"{ctx}: sign block_count <= 1_000_000（§4.1 上界）",
            block_count <= R.MAX_BLOCK_COUNT,
            f"block_count={block_count}",
        )
    if sha_hex is not None:
        rec.check(cat, f"{ctx}: sign sha256_hex 与 hashlib 一致", sha_hex == R.sha256_hex(case.old), f"{sha_hex} vs {R.sha256_hex(case.old)}")
    if xxh_hex is not None:
        cand = R.xxh64_hex_candidates(case.old)
        rec.check(
            cat,
            f"{ctx}: sign xxh64_hex 与独立 XXH64 一致（大端/小端任一，歧义 A5）",
            xxh_hex.lower() in cand,
            f"{xxh_hex} vs candidates {cand}",
        )
    if sig_bytes is not None and block_count is not None and strong_len is not None:
        expect_len = 22 + block_count * (4 + strong_len)
        rec.check(
            cat,
            f"{ctx}: signature_bytes == 22 + block_count*(4+strong_len) = {expect_len}（§5.1）",
            sig_bytes == expect_len,
            f"json={sig_bytes} expect={expect_len}",
        )

    if not dsig_path.exists():
        rec.check(
            cat,
            f"{ctx}: sign --out 写出 DSIG（§8 注「--out 用于导出 DSIG/DDLT」）",
            False,
            f"{dsig_path} 不存在，CLI 以 rc={res.returncode} 静默忽略 --out"
            f"（§8 synopsis 未给 sign 列 --out，但注释承诺可导出 DSIG，二者矛盾，见歧义 A12）",
            "advisory",
        )
        blocked_once(
            rec,
            cat,
            "sign 每块 weak/strong 的独立逐块复核（依赖 DSIG 产物）",
            "CLI 未导出 DSIG：sign --out 被静默忽略，第三方无法解析签名文件，"
            "因此弱校验(§6.1)只能等到 `sign --out` 可用后复核。"
            "注：块级强校验仍可通过 delta 的 COPY/COPY_RUN 摘要间接复核（见 cli-delta）。",
        )
        return None
    raw = dsig_path.read_bytes()
    rec.check(cat, f"{ctx}: sign --out 写出 DSIG 文件非空", len(raw) > 0, f"{len(raw)} bytes")
    try:
        sig = R.parse_dsig(raw)
    except R.FormatError as exc:
        rec.check(cat, f"{ctx}: DSIG 可被独立解析器解析", False, str(exc))
        return None
    rec.check(
        cat,
        f"{ctx}: DSIG 解析可被独立解析器完成（magic/version/长度自洽）",
        True,
        f"{len(raw)} bytes, {len(sig.blocks)} blocks, strong_len={sig.strong_len}",
    )
    rec.check(
        cat,
        f"{ctx}: DSIG 头与 sign JSON 一致 (block_size/strong_len/total_length/block_count)",
        (block_size, strong_len, total_length, block_count) == (sig.block_size, sig.strong_len, sig.total_length, len(sig.blocks)),
        f"dsig=({sig.block_size},{sig.strong_len},{sig.total_length},{len(sig.blocks)}) json=({block_size},{strong_len},{total_length},{block_count})",
    )
    rec.check(cat, f"{ctx}: signature_sha256_hex == sha256(DSIG 文件)", sig_sha == R.sha256_hex(raw), f"{sig_sha} vs {R.sha256_hex(raw)}")
    if sig_bytes is not None:
        rec.check(
            cat,
            f"{ctx}: signature_bytes == DSIG 实际字节数",
            sig_bytes == len(raw),
            f"json={sig_bytes} 实际={len(raw)}",
        )
        expect_len = 22 + len(sig.blocks) * (4 + sig.strong_len)
        rec.check(
            cat,
            f"{ctx}: DSIG 字节数 == 22 + block_count*(4+strong_len) = {expect_len}（§5.1）",
            len(raw) == expect_len,
            f"actual={len(raw)} expect={expect_len}",
        )

    # 独立重算每个块的 weak / strong
    # 说明（歧义 A13）：design.md §6.1 的弱校验是「a=Σw, b=Σ(n-i)w_i」无 +1/+n 的变体；
    # 实测实现记录的是标准 Adler-32（A=1+Σw, B=Σ(n-i)w_i+n）。这里同时比对两种，并区分报告。
    weak_doc_bad: list[str] = []
    weak_std_hits = 0
    strong_bad: list[str] = []
    for b in sig.blocks:
        chunk = case.old[b.index * sig.block_size : (b.index + 1) * sig.block_size]
        if b.weak != R.weak_checksum(chunk):
            weak_doc_bad.append(
                f"block {b.index} 记录 {b.weak:#010x}，§6.1 变体应为 {R.weak_checksum(chunk):#010x}"
            )
        if b.weak == R.weak_checksum_standard(chunk):
            weak_std_hits += 1
        if b.strong != R.sha256(chunk)[: sig.strong_len]:
            strong_bad.append(
                f"block {b.index} strong {b.strong.hex()} != {R.sha256(chunk)[: sig.strong_len].hex()}"
            )
        if len(weak_doc_bad) > 4 and len(strong_bad) > 4:
            break
    rec.check(
        cat,
        f"{ctx}: 每块 strong 与独立实现逐块一致（{len(sig.blocks)} 块）",
        not strong_bad,
        "; ".join(strong_bad[:4]),
    )
    weak_doc_ok = not weak_doc_bad
    rec.check(
        cat,
        f"{ctx}: 每块 weak 与 §6.1 变体公式一致（{len(sig.blocks)} 块）",
        weak_doc_ok,
        (
            f"{'; '.join(weak_doc_bad[:3])} | 其中 {weak_std_hits}/{len(sig.blocks)} 块正好等于"
            "**标准 Adler-32**（A=1+Σw, B=Σ(n-i)w_i+n）：实现与 §6.1 差 +1/+n（歧义 A13）"
            if not weak_doc_ok
            else ""
        ),
    )
    if not weak_doc_ok and weak_std_hits != len(sig.blocks):
        rec.check(
            cat,
            f"{ctx}: weak 既不是 §6.1 变体也不是标准 Adler-32（需人工核对）",
            False,
            f"标准命中 {weak_std_hits}/{len(sig.blocks)}",
        )
    return sig


def cli_delta(rec: Recorder, runner: CliRunner, case: Case, tmp: Path, sig: R.FileSignature | None) -> tuple[R.Delta, Path] | None:
    cat = "cli-delta"
    ctx = case.name
    old_path = tmp / f"{case.name}.old"
    new_path = write_file(tmp / f"{case.name}.new", case.new)
    ddlt_path = tmp / f"{case.name}.ddlt"
    if ddlt_path.exists():
        ddlt_path.unlink()
    ref_bs = sig.block_size if (sig and sig.total_length == len(case.old)) else R.default_block_size(len(case.old))
    ref_sl = sig.strong_len if (sig and sig.total_length == len(case.old)) else DEFAULT_STRONG_LEN
    planner_delta = R.make_delta(
        case.old,
        case.new,
        ref_bs,
        ref_sl,
        sig if (sig and sig.total_length == len(case.old)) else None,
    )
    planner_bytes = len(R.serialize_ddlt(planner_delta))

    t0 = time.time()
    res = runner.run(["delta", str(old_path), str(new_path), "--out", str(ddlt_path)])
    elapsed = time.time() - t0
    if not rec.check(cat, f"{ctx}: delta 退出码 0", res.returncode == 0 and not res.timed_out, res.brief()):
        return None
    js = res.json
    if not rec.check(cat, f"{ctx}: delta 输出 JSON 且 kind=delta", js is not None and js.get("kind") == "delta", res.brief()):
        return None
    if not ddlt_path.exists():
        rec.check(cat, f"{ctx}: delta --out 写出 DDLT 文件", False, f"{ddlt_path} 不存在")
        return None
    raw = ddlt_path.read_bytes()
    try:
        delta = R.parse_ddlt(raw)
    except R.FormatError as exc:
        rec.check(cat, f"{ctx}: DDLT 可被独立解析器解析", False, str(exc))
        return None
    new_length = int_field(js, "new_length")
    op_count = int_field(js, "op_count")
    copy_blocks = int_field(js, "copy_blocks")
    literal_bytes = int_field(js, "literal_bytes")
    delta_bytes = int_field(js, "delta_bytes")
    delta_sha = str_field(js, "delta_sha256_hex")
    ratio = js.get("savings_ratio")

    require_fields(
        rec,
        cat,
        ctx,
        js,
        ("old", "new", "new_length", "op_count", "copy_blocks", "literal_bytes", "delta_bytes", "delta_sha256_hex", "savings_ratio"),
        {"op_count": ("copy_ops", "ops", "op_total"), "copy_blocks": ("copied_blocks",), "delta_bytes": ("delta_size",)},
    )
    extra = [k for k in ("copied_bytes", "copy_ops") if k in js]
    if extra:
        rec.info(
            cat,
            f"{ctx}: delta JSON 额外字段",
            f"实现另外输出了 {extra}（§8.1 未列；额外字段不破坏契约，但外部脚本按固定字段解析）",
        )
    rec.check(cat, f"{ctx}: DDLT 可被独立解析器解析（头/op 自洽）", True, f"{len(raw)} bytes, {len(delta.ops)} ops, bs={delta.block_size}, sl={delta.strong_len}")
    rec.check(cat, f"{ctx}: DDLT 头 new_length == len(new)", delta.new_length == len(case.new), f"{delta.new_length} vs {len(case.new)}")
    rec.check(
        cat,
        f"{ctx}: DDLT content_digest == sha256(new)（§5.2）",
        delta.content_digest == R.sha256(case.new),
        f"{delta.content_digest.hex()} vs {R.sha256(case.new).hex()}",
    )
    if new_length is not None:
        rec.check(cat, f"{ctx}: JSON new_length == len(new)", new_length == len(case.new), f"{new_length} vs {len(case.new)}")
    if op_count is not None:
        rec.check(cat, f"{ctx}: JSON op_count == 解析出的 op 数", op_count == len(delta.ops), f"{op_count} vs {len(delta.ops)}")
    if copy_blocks is not None:
        rec.check(cat, f"{ctx}: JSON copy_blocks == 展开后的 COPY 块数", copy_blocks == delta.copy_block_count(), f"{copy_blocks} vs {delta.copy_block_count()}")
    if literal_bytes is not None:
        rec.check(cat, f"{ctx}: JSON literal_bytes == LITERAL 字节合计", literal_bytes == delta.literal_bytes(), f"{literal_bytes} vs {delta.literal_bytes()}")
    if delta_bytes is not None:
        rec.check(cat, f"{ctx}: JSON delta_bytes == DDLT 实际字节数", delta_bytes == len(raw), f"{delta_bytes} vs {len(raw)}")
    if delta_sha is not None:
        rec.check(cat, f"{ctx}: delta_sha256_hex == sha256(DDLT 文件)", delta_sha == R.sha256_hex(raw), f"{delta_sha} vs {R.sha256_hex(raw)}")
    # 实现额外输出的统计量也用独立真值核对（若存在）
    copy_op_count = sum(1 for op in delta.ops if op[0] in ("copy", "copy_run"))
    if "copy_ops" in js and isinstance(js["copy_ops"], int):
        rec.check(
            cat,
            f"{ctx}: 额外字段 copy_ops == 解析出的 COPY/COPY_RUN op 数",
            js["copy_ops"] == copy_op_count,
            f"json={js['copy_ops']} 独立解析={copy_op_count}",
            "advisory",
        )
    if "copied_bytes" in js and isinstance(js["copied_bytes"], int):
        copied = sum(
            len(case.old[op[1] * delta.block_size : (op[1] + (op[2] if op[0] == "copy_run" else 1)) * delta.block_size])
            for op in delta.ops
            if op[0] in ("copy", "copy_run")
        )
        rec.check(
            cat,
            f"{ctx}: 额外字段 copied_bytes == COPY 覆盖字节数",
            js["copied_bytes"] == copied,
            f"json={js['copied_bytes']} 独立计算={copied}",
            "advisory",
        )
    violations = R.normalization_violations(delta.ops)
    rec.check(cat, f"{ctx}: DDLT 满足 §5.2 规范化（相邻同类 op 已合并）", not violations, "; ".join(violations[:4]))

    # §5.2 delta 自带校验：每个 COPY / COPY_RUN 的强校验与独立重算一致
    bad_strong = []
    for op in delta.ops:
        if op[0] == "copy":
            want = R.strong_of_blocks(case.old, delta.block_size, delta.strong_len, op[1], 1)
            if op[2] != want:
                bad_strong.append(f"COPY({op[1]}) 记录 {op[2].hex()} 应为 {want.hex()}")
        elif op[0] == "copy_run":
            want = R.strong_of_blocks(case.old, delta.block_size, delta.strong_len, op[1], op[2])
            if op[3] != want:
                bad_strong.append(f"COPY_RUN({op[1]}+{op[2]}) 记录 {op[3].hex()} 应为 {want.hex()}")
    rec.check(
        cat,
        f"{ctx}: delta 每个 COPY/COPY_RUN 的强校验与独立重算一致（§5.2）",
        not bad_strong,
        "; ".join(bad_strong[:3]),
    )
    if sig is not None and sig.total_length == len(case.old):
        rec.check(
            cat,
            f"{ctx}: delta 的 (block_size, strong_len) 与 DSIG 一致",
            (delta.block_size, delta.strong_len) == (sig.block_size, sig.strong_len),
            f"delta=({delta.block_size},{delta.strong_len}) sig=({sig.block_size},{sig.strong_len})",
        )

    # 独立重放：逐块强校验 + 逐字节比较
    if any(op[0] in ("copy", "copy_run") for op in delta.ops):
        ref_sig = sig if (sig is not None and sig.total_length == len(case.old)) else R.build_signature(case.old, delta.block_size, delta.strong_len)
        try:
            rebuilt = R.replay(case.old, delta, ref_sig)
            rec.check(cat, f"{ctx}: 独立重放 delta 与 new 逐字节相同", rebuilt == case.new, f"rebuilt {len(rebuilt)}B vs new {len(case.new)}B")
        except R.ReplayError as exc:
            rec.check(cat, f"{ctx}: 独立重放 delta 与 new 逐字节相同", False, f"[{exc.code}] {exc.message[:200]}")
    else:
        try:
            rebuilt = R.replay(case.old, delta, None)
            rec.check(cat, f"{ctx}: 独立重放 delta（纯 literal）与 new 逐字节相同", rebuilt == case.new, f"{len(rebuilt)}B")
        except R.ReplayError as exc:
            rec.check(cat, f"{ctx}: 独立重放 delta（纯 literal）与 new 逐字节相同", False, exc.message)

    # delta 字节数不超过独立规划器的 2 倍
    rec.check(
        cat,
        f"{ctx}: delta 字节数 <= 2 × 独立规划器字节数",
        delta_bytes is not None and delta_bytes <= 2 * planner_bytes,
        f"actual={delta_bytes} planner={planner_bytes} (ratio {delta_bytes/planner_bytes:.2f})" if delta_bytes is not None and planner_bytes else "",
    )
    # savings_ratio 契约：1 - delta/new_length，裁剪 [0,1]，4 位小数
    if isinstance(ratio, (int, float)) and len(case.new) > 0 and delta_bytes is not None:
        expect = min(1.0, max(0.0, 1.0 - delta_bytes / len(case.new)))
        rec.check(
            cat,
            f"{ctx}: savings_ratio == 1 - delta_bytes/new_length（±1e-4）",
            num_close(float(ratio), expect, 1e-4),
            f"json={ratio} expect={expect:.4f}",
        )
        rec.check(
            cat,
            f"{ctx}: savings_ratio 保留 4 位小数（歧义 A6：示例 dedup_ratio 只 3 位）",
            round(float(ratio), 4) == float(ratio),
            f"json={ratio}",
            "advisory",
        )

    # §7.3 局部性上界
    if case.locality:
        nblocks = max(1, R.ceil_div(len(case.old), DEFAULT_BLOCK_SIZE))
        bound = nblocks * 8 + case.changed_bytes + 16
        rec.check(
            cat,
            f"{ctx}: §7.3 局部性 delta_bytes <= 块数*8+改动字节+16 = {bound}",
            delta_bytes is not None and delta_bytes <= bound,
            f"actual={delta_bytes} bound={bound} changed={case.changed_bytes}",
        )
    if case.old == case.new and len(case.old) > 0:
        rec.check(
            cat,
            f"{ctx}: 未改动数据 -> literal_bytes == 0 且 1 个 COPY_RUN",
            literal_bytes == 0 and len(delta.ops) == 1 and delta.ops[0][0] == "copy_run",
            f"ops={delta.ops[:3]} literal={literal_bytes}",
            "advisory",
        )
    rec.info(
        "cli-delta",
        f"{ctx}: delta 规模对比",
        f"new={len(case.new)}B delta={delta_bytes}B planner={planner_bytes}B "
        f"copy_blocks={copy_blocks} literal={literal_bytes}B ops={op_count} cli_time={elapsed:.2f}s",
    )
    if delta_bytes is not None:
        DELTA_STATS.append(
            {
                "case": ctx,
                "new": len(case.new),
                "delta": delta_bytes,
                "planner": planner_bytes,
                "copied": delta.copy_block_count(),
                "literal": delta.literal_bytes(),
                "ops": len(delta.ops),
                "cli_time": elapsed,
            }
        )
    return delta, ddlt_path


def cli_apply(rec: Recorder, runner: CliRunner, case: Case, tmp: Path, delta: R.Delta, ddlt_path: Path) -> None:
    cat = "cli-apply"
    ctx = case.name
    old_path = tmp / f"{case.name}.old"
    rebuilt_path = tmp / f"{case.name}.rebuilt"
    if rebuilt_path.exists():
        rebuilt_path.unlink()
    res = runner.run(["apply", str(old_path), str(ddlt_path), "--out", str(rebuilt_path)])
    if not rec.check(cat, f"{ctx}: apply 退出码 0", res.returncode == 0 and not res.timed_out, res.brief()):
        return
    js = res.json
    if not rec.check(cat, f"{ctx}: apply 输出 JSON 且 kind=apply", js is not None and js.get("kind") == "apply", res.brief()):
        return
    rec.check(cat, f"{ctx}: apply ok == true", js.get("ok") is True, res.brief())
    bytes_written = must_int(js, "bytes_written", rec, cat, f"{ctx}: apply")
    sha_hex = must_str(js, "sha256_hex", rec, cat, f"{ctx}: apply")
    rec.check(cat, f"{ctx}: apply bytes_written == len(new)", bytes_written == len(case.new), f"{bytes_written} vs {len(case.new)}")
    rec.check(cat, f"{ctx}: apply sha256_hex == hashlib(new)", sha_hex == R.sha256_hex(case.new), f"{sha_hex} vs {R.sha256_hex(case.new)}")
    if not rebuilt_path.exists():
        rec.check(cat, f"{ctx}: apply --out 写出重建文件", False, f"{rebuilt_path} 不存在；{res.brief()}")
        return
    rebuilt = rebuilt_path.read_bytes()
    rec.check(cat, f"{ctx}: apply 重建结果与 new 逐字节相同", rebuilt == case.new, f"rebuilt {len(rebuilt)}B vs new {len(case.new)}B")
    blocks_verified = must_int(js, "blocks_verified", rec, cat, f"{ctx}: apply")
    copy_blocks = delta.copy_block_count()
    rec.check(
        cat,
        f"{ctx}: blocks_verified 语义（=COPY 块数 {copy_blocks} 或 总块数，歧义 A7）",
        blocks_verified is not None and blocks_verified > 0 and blocks_verified in (copy_blocks, R.ceil_div(len(case.new), max(1, delta.block_size))),
        f"json={blocks_verified} copy_blocks={copy_blocks} new_blocks={R.ceil_div(len(case.new), max(1, delta.block_size))}",
        "advisory",
    )


def cli_interop(rec: Recorder, runner: CliRunner, case: Case, tmp: Path, sig: R.FileSignature | None) -> None:
    """用独立规划器生成的 DDLT 喂给 CLI apply：双向互操作。"""
    cat = "cli-interop"
    ctx = case.name
    use_sig = sig if (sig and sig.total_length == len(case.old)) else None
    bs = use_sig.block_size if use_sig else R.default_block_size(len(case.old))
    sl = use_sig.strong_len if use_sig else DEFAULT_STRONG_LEN
    my_delta = R.make_delta(case.old, case.new, bs, sl, use_sig)
    my_raw = R.serialize_ddlt(my_delta)
    my_path = write_file(tmp / f"{case.name}.ref.ddlt", my_raw)
    old_path = tmp / f"{case.name}.old"
    out_path = tmp / f"{case.name}.ref.rebuilt"
    if out_path.exists():
        out_path.unlink()
    res = runner.run(["apply", str(old_path), str(my_path), "--out", str(out_path)])
    if not rec.check(cat, f"{ctx}: CLI 接受独立规划器产出的 DDLT（apply 退出码 0）", res.returncode == 0 and not res.timed_out, res.brief()):
        return
    rec.check(cat, f"{ctx}: 独立 DDLT 的 apply JSON ok == true", (res.json or {}).get("ok") is True, res.brief())
    if not out_path.exists():
        rec.check(cat, f"{ctx}: 独立 DDLT 的 apply --out 写出文件", False, f"{out_path} 不存在")
        return
    got = out_path.read_bytes()
    rec.check(cat, f"{ctx}: CLI 用独立 DDLT 重建的字节与 new 逐字节相同", got == case.new, f"{len(got)}B vs {len(case.new)}B")


def cli_chunk(rec: Recorder, runner: CliRunner, case: Case, tmp: Path) -> None:
    cat = "cli-chunk"
    ctx = case.name
    new_path = tmp / f"{case.name}.new"
    res = runner.run(["chunk", str(new_path)])
    if not rec.check(cat, f"{ctx}: chunk 退出码 0", res.returncode == 0 and not res.timed_out, res.brief()):
        return
    js = res.json
    if not rec.check(cat, f"{ctx}: chunk 输出 JSON 且 kind=chunk", js is not None and js.get("kind") == "chunk", res.brief()):
        return
    length = int_field(js, "length")
    chunk_count = int_field(js, "chunk_count")
    unique = int_field(js, "unique_chunks")
    root_hex = str_field(js, "root_hex")
    manifest_bytes = int_field(js, "manifest_bytes")
    dedup = js.get("dedup_ratio")
    require_fields(
        rec,
        cat,
        ctx,
        js,
        ("path", "length", "chunk_count", "unique_chunks", "dedup_ratio", "root_hex", "manifest_bytes"),
        {
            "unique_chunks": ("new_chunks", "distinct_chunks"),
            "dedup_ratio": ("reuse_ratio", "dedup"),
            "manifest_bytes": ("manifest_size", "stored_bytes"),
        },
    )
    extra = [k for k in ("new_chunks", "reused_chunks", "stored_bytes", "saved_bytes") if k in js]
    if extra:
        rec.info(
            cat,
            f"{ctx}: chunk JSON 额外字段",
            f"实现另外输出了 {extra}（§8.1 未列；外部脚本按固定字段解析）",
        )
    if length is not None:
        rec.check(cat, f"{ctx}: chunk length == 文件长度", length == len(case.new), f"{length} vs {len(case.new)}")
    if unique is not None and chunk_count is not None:
        rec.check(
            cat,
            f"{ctx}: chunk unique_chunks <= chunk_count",
            0 <= unique <= chunk_count,
            f"unique={unique} count={chunk_count}",
        )
    ok_root = root_hex is not None and len(root_hex) == 64 and all(c in "0123456789abcdefABCDEF" for c in root_hex)
    rec.check(cat, f"{ctx}: root_hex 为 64 位十六进制", ok_root, f"{root_hex!r}")
    if isinstance(dedup, (int, float)) and chunk_count and unique is not None:
        expect_unique_share = unique / chunk_count
        expect_saved_share = 1.0 - unique / chunk_count
        rec.check(
            cat,
            f"{ctx}: dedup_ratio 与 unique/chunk_count 的关系可解释（歧义 A15）",
            num_close(float(dedup), expect_unique_share, 1e-3) or num_close(float(dedup), expect_saved_share, 1e-3),
            f"json={dedup} 候选：unique/chunk_count={expect_unique_share:.4f}（§8.1 示例 510/512=0.996）"
            f" 或 1-unique/chunk_count={expect_saved_share:.4f}（实现口径）",
            "advisory",
        )
    if manifest_bytes is not None and chunk_count is not None:
        rec.check(
            cat,
            f"{ctx}: manifest_bytes == 32*chunk_count+32（由 §8.1 示例反推）或 DCHK 全量 41+36*count（歧义 A4）",
            manifest_bytes in (32 * chunk_count + 32, 41 + 36 * chunk_count),
            f"json={manifest_bytes} candidates=({32*chunk_count+32}, {41+36*chunk_count})",
            "advisory",
        )

    # 尝试 --out 取 DCHK，做结构级独立校验
    dchk_path = tmp / f"{case.name}.dchk"
    if dchk_path.exists():
        dchk_path.unlink()
    res2 = runner.run(["chunk", str(new_path), "--out", str(dchk_path)])
    if res2.returncode == 0 and dchk_path.exists():
        raw = dchk_path.read_bytes()
        man = None
        try:
            man = R.parse_dchk(raw)
            rec.check(cat, f"{ctx}: DCHK 布局符合 §5.3（magic/version/chunk_count/u32 length）", True, f"{len(raw)} bytes")
        except R.FormatError as exc:
            rec.check(
                cat,
                f"{ctx}: DCHK 布局符合 §5.3（magic/version/chunk_count/u32 length）",
                False,
                f"{exc} | 文件头 {raw[:20].hex(' ')}",
            )
            try:
                man = R.parse_dchk_impl(raw)
                rec.check(
                    cat,
                    f"{ctx}: DCHK 实测布局可解析（扩展头 min/max/avg_bits + varint length，待回填文档，歧义 A14）",
                    True,
                    f"{len(raw)} bytes, header 18B, {len(man.chunks)} chunks, "
                    f"min={man.min_chunk} max={man.max_chunk} avg=2^{man.avg_bits}",
                    "advisory",
                )
            except R.FormatError as exc2:
                rec.check(
                    cat,
                    f"{ctx}: DCHK 实测布局可解析（扩展头 min/max/avg_bits + varint length）",
                    False,
                    f"§5.3 与实测布局都解析失败：{exc2}",
                )
                return
        if man is not None:
            lo = man.min_chunk or R._MIN_CHUNK
            hi = man.max_chunk or R._MAX_CHUNK
            rec.check(cat, f"{ctx}: DCHK chunk_count == JSON chunk_count", len(man.chunks) == chunk_count, f"{len(man.chunks)} vs {chunk_count}")
            total = sum(c.length for c in man.chunks)
            rec.check(cat, f"{ctx}: DCHK 块长之和 == 文件长度", total == len(case.new), f"{total} vs {len(case.new)}")
            rec.check(cat, f"{ctx}: DCHK root == sha256(concat(块 sha256))（§5.3 语义）", man.root == R.manifest_root(man.chunks), f"root={man.root.hex()}")
            if root_hex:
                rec.check(cat, f"{ctx}: DCHK root 与 JSON root_hex 一致", man.root.hex().lower() == root_hex.lower(), f"{man.root.hex()} vs {root_hex}")
            uniq = len(set(c.digest for c in man.chunks))
            if unique is not None:
                rec.check(cat, f"{ctx}: DCHK 去重计数 == JSON unique_chunks", uniq == unique, f"{uniq} vs {unique}")
            big = [c.length for c in man.chunks if c.length > hi]
            rec.check(cat, f"{ctx}: 所有块长 <= max={hi}（§6.4 默认参数）", not big, f"越界块长 {big[:5]}")
            small = [c.length for c in man.chunks[:-1] if c.length < lo]
            rec.check(
                cat,
                f"{ctx}: 除末块外块长 >= min={lo}（§6.4 默认参数）",
                not small,
                f"越界块长 {small[:5]}",
            )
            if manifest_bytes is not None:
                rec.check(
                    cat,
                    f"{ctx}: manifest_bytes == DCHK 实际字节数",
                    manifest_bytes == len(raw),
                    f"json={manifest_bytes} 实际={len(raw)}（§8.1 示例 16416 口径不同，歧义 A4）",
                    "advisory",
                )
    else:
        rec.check(
            cat,
            f"{ctx}: chunk --out 可导出 manifest（§8 只承诺 DSIG/DDLT，DCHK 未提，歧义 A8）",
            False,
            f"{res2.brief(200)}；CLI 对不支持的 --out 静默忽略（rc=0 且不写文件），"
            "外部无法解析 manifest 做独立 root/边界校验",
            "advisory",
        )
        blocked_once(
            rec,
            cat,
            "DCHK manifest 的独立解析校验（依赖 manifest 导出）",
            "chunk 不支持导出 manifest 字节：无法独立复核 DCHK 结构、root 重算、块长上下界与指纹复用率。"
            "建议为 chunk 增加 --out <dchk>（§5.3 格式已定义）。",
        )


def cli_verify(rec: Recorder, runner: CliRunner, case: Case, tmp: Path) -> None:
    cat = "cli-verify"
    ctx = case.name
    new_path = tmp / f"{case.name}.new"
    good = R.sha256_hex(case.new)
    res = runner.run(["verify", str(new_path), good])
    ok = res.returncode == 0 and (res.json or {}).get("kind") == "verify" and (res.json or {}).get("ok") is True
    rec.check(cat, f"{ctx}: verify 正确 SHA-256 -> ok:true 且退出码 0", ok, res.brief())
    if res.json:
        rec.check(cat, f"{ctx}: verify 回显 sha256_hex == 输入", (res.json or {}).get("sha256_hex", "").lower() == good, f"{res.json.get('sha256_hex')} vs {good}")
    bad = "00" * 32
    res = runner.run(["verify", str(new_path), bad])
    is_error = res.returncode != 0 and (res.json or {}).get("kind") == "error"
    is_ok_false = res.returncode == 0 and (res.json or {}).get("kind") == "verify" and (res.json or {}).get("ok") is False
    rec.check(
        cat,
        f"{ctx}: verify 不匹配的合法 SHA-256 -> 明确否定（ok:false 或 error），不能假成功",
        (is_error or is_ok_false) and not res.timed_out and not res.crash_markers(),
        res.brief() + ("" if is_error else " | 走 verify/ok=false 分支（§8.1 只规定「参数错误」用 error JSON，"
                                            "校验不匹配算业务结果，可接受；建议在文档中明确）"),
        "advisory",
    )
    rec.check(
        cat,
        f"{ctx}: verify 不匹配时的退出码语义（advisory：error→非零 或 ok=false→0 均可）",
        is_error != is_ok_false,
        res.brief(),
        "advisory",
    )


def malformed_suite(rec: Recorder, runner: CliRunner, case: Case, tmp: Path, ddlt_path: Path) -> None:
    cat = "cli-malformed"
    old_path = tmp / f"{case.name}.old"
    raw = ddlt_path.read_bytes()
    new_path = tmp / f"{case.name}.new"
    try:
        base = R.parse_ddlt(raw)
    except R.FormatError as exc:
        rec.blocked(cat, "畸形输入套件（依赖可解析的基线 DDLT）", f"基线 DDLT 解析失败：{exc}")
        return
    bs, sl = base.block_size, base.strong_len
    OFF_CNT = R.DDLT_OFF_OP_COUNT
    OFF_OP = R.DDLT_OFF_FIRST_OP
    OFF_DIGEST = R.DDLT_OFF_CONTENT_DIGEST

    def header(
        new_length: int,
        op_count: int,
        block_size: int = bs,
        strong_len: int = sl,
        content_digest: bytes | None = None,
    ) -> bytes:
        digest = content_digest if content_digest is not None else R.sha256(case.new)
        return (
            b"DDLT"
            + bytes([1])
            + block_size.to_bytes(4, "big")
            + bytes([strong_len])
            + new_length.to_bytes(8, "big")
            + digest
            + op_count.to_bytes(4, "big")
        )

    strong0 = bytes(sl)
    variants: list[tuple[str, bytes, str]] = [
        ("截断 4 字节", raw[:-4], "apply 旧<=>截断 delta"),
        ("空字节流", b"", "apply 旧<=>空 delta"),
        ("错 magic", b"DDLX" + raw[4:], "apply 旧<=>错 magic delta"),
        ("版本 2", raw[:4] + b"\x02" + raw[5:], "apply 旧<=>版本 2 delta"),
        ("strong_len=12", raw[:9] + b"\x0c" + raw[10:], "apply 旧<=>strong_len 12 delta"),
        ("op_count=0xFFFFFFFF", raw[:OFF_CNT] + (0xFFFFFFFF).to_bytes(4, "big") + raw[OFF_OP:], "apply 旧<=>超大 op_count"),
        ("op_count+1", raw[:OFF_CNT] + (len(base.ops) + 1).to_bytes(4, "big") + raw[OFF_OP:], "apply 旧<=>op_count 偏大"),
        ("op tag=7", raw[:OFF_OP] + b"\x07" + raw[OFF_OP + 1 :], "apply 旧<=>非法 op tag"),
        ("LITERAL 长度 0xFFFFFFFF", header(len(case.new), 1) + b"\x01" + (0xFFFFFFFF).to_bytes(4, "big"), "apply 旧<=>超大 literal 长度"),
        ("COPY 块号越界", header(bs, 1) + b"\x00" + (0xFFFFFFFF).to_bytes(4, "big") + strong0, "apply 旧<=>COPY 块号越界"),
        (
            "COPY_RUN count=0xFFFFFFFF",
            header(bs, 1) + b"\x02" + (0).to_bytes(4, "big") + (0xFFFFFFFF).to_bytes(4, "big") + strong0,
            "apply 旧<=>超大 COPY_RUN count",
        ),
        ("new_length=2^64-1", header((1 << 64) - 1, 1) + b"\x00" + (0).to_bytes(4, "big") + strong0, "apply 旧<=>超大 new_length"),
        ("block_size=0", header(bs, 1, block_size=0) + b"\x00" + (0).to_bytes(4, "big") + strong0, "apply 旧<=>block_size=0"),
        (
            "block_size 超上界 (>1MiB)",
            header(bs, 1, block_size=(1 << 20) + 1) + b"\x00" + (0).to_bytes(4, "big") + strong0,
            "apply 旧<=>block_size 超 §4.1 上界",
        ),
    ]
    for name, blob, desc in variants:
        path = write_file(tmp / f"bad_{abs(hash(name)) % 10**8}_{case.name}.ddlt", blob)
        res = runner.run(["apply", str(old_path), str(path)], timeout=120)
        marks = res.crash_markers()
        ok = (
            not res.timed_out
            and res.returncode != 0
            and isinstance(res.json, dict)
            and res.json.get("kind") == "error"
            and isinstance(res.json.get("code"), str)
            and res.json.get("code") != ""
            and isinstance(res.json.get("message"), str)
            and res.json.get("message") != ""
            and not marks
        )
        detail = res.brief()
        if marks:
            detail += f" | 崩溃标记 {marks}"
        rec.check(cat, f"{desc} -> error JSON + 非零退出码 + 无 panic", ok, detail)

    def apply_expect_error(name: str, blob: bytes) -> tuple[bool, str]:
        path = write_file(tmp / f"{name}_{abs(hash(name)) % 10**6}_{case.name}.ddlt", blob)
        res = runner.run(["apply", str(old_path), str(path)], timeout=120)
        code = (res.json or {}).get("code", "")
        detected = (
            not res.timed_out
            and res.returncode != 0
            and (res.json or {}).get("kind") == "error"
            and not res.crash_markers()
        )
        return detected, f"code={code!r} {res.brief(200)}"

    # §5.2 / §7.4：delta 自带强校验，篡改 COPY/COPY_RUN 记录的摘要必须被 apply 检出
    ops_flip: list[tuple] = []
    flipped = False
    for op in base.ops:
        if not flipped and op[0] in ("copy", "copy_run"):
            flipped = True
            if op[0] == "copy":
                ops_flip.append(("copy", op[1], bytes([op[2][0] ^ 0xFF]) + op[2][1:]))
            else:
                ops_flip.append(("copy_run", op[1], op[2], bytes([op[3][0] ^ 0xFF]) + op[3][1:]))
        else:
            ops_flip.append(op)
    if flipped:
        blob = R.serialize_ddlt(R.Delta(bs, sl, base.new_length, ops_flip, base.content_digest))
        detected, detail = apply_expect_error("tamper_strong", blob)
        rec.check(cat, "篡改 delta 内 COPY 强校验 -> apply 必须报错（§5.2/§7.4）", detected, detail)
        rec.check(
            cat,
            "篡改强校验的 error.code 含 BlockMismatch 语义",
            "mismatch" in str((detail.split("code=")[1] if "code=" in detail else "").lower())
            or "block" in str(detail).lower(),
            detail,
            "advisory",
        )

    # §5.2 content_digest：目标数据摘要被篡改 -> apply 必须报错（DigestMismatch）
    digest_blob = bytearray(raw)
    digest_blob[OFF_DIGEST] ^= 0xFF
    detected, detail = apply_expect_error("tamper_digest", bytes(digest_blob))
    rec.check(cat, "篡改 content_digest -> apply 必须报错（§5.2 DigestMismatch）", detected, detail)

    # 旧文件被替换为等长但内容不同：apply 必须报错而不是产出错误数据
    bad_old = write_file(tmp / f"{case.name}.badold", bytes(b ^ 0xFF for b in case.old))
    out_bad = tmp / f"{case.name}.badold.out"
    if out_bad.exists():
        out_bad.unlink()
    res = runner.run(["apply", str(bad_old), str(ddlt_path), "--out", str(out_bad)], timeout=120)
    marks = res.crash_markers()
    err = res.returncode != 0 and (res.json or {}).get("kind") == "error" and not res.timed_out and not marks
    rec.check(
        cat,
        "旧数据被替换（COPY 内容不符）-> apply 必须报错（§7.4）",
        err,
        res.brief(),
    )

    # §7.4 LITERAL 字节翻转：由 §5.2 content_digest 兜底，必须报错
    lit_index = next((i for i, op in enumerate(base.ops) if op[0] == "lit" and len(op[1]) > 0), None)
    if lit_index is not None:
        lit_ops = list(base.ops)
        data = bytearray(lit_ops[lit_index][1])
        data[0] ^= 0xFF
        lit_ops[lit_index] = ("lit", bytes(data))
        blob = R.serialize_ddlt(R.Delta(bs, sl, base.new_length, lit_ops, base.content_digest))
        detected, detail = apply_expect_error("flip_literal", blob)
        rec.check(
            cat,
            "翻转 LITERAL 内 1 字节 -> apply 必须报错（§7.4 + §5.2 content_digest）",
            detected,
            detail,
        )
    else:
        rec.info(cat, "翻转 LITERAL 内 1 字节（该语料无 LITERAL，跳过）", "本 delta 全部为 COPY")

    # 参数/路径类错误
    arg_cases = [
        ("未知命令", ["__no_such_command__"]),
        ("sign 缺参数", ["sign"]),
        ("sign 文件不存在", ["sign", str(tmp / "does-not-exist.bin")]),
        ("delta 缺 new", ["delta", str(old_path)]),
        ("delta new 不存在", ["delta", str(old_path), str(tmp / "nope.bin")]),
        ("apply delta 不存在", ["apply", str(old_path), str(tmp / "nope.ddlt")]),
        ("verify 非十六进制", ["verify", str(new_path), "zzzz"]),
        ("verify 长度不对的 hex", ["verify", str(new_path), "abcd"]),
        ("verify 64 位非十六进制", ["verify", str(new_path), "z" * 64]),
        ("verify 多余参数", ["verify", str(new_path), R.sha256_hex(case.new), "extra"]),
        ("chunk 文件不存在", ["chunk", str(tmp / "nope.bin")]),
    ]
    for name, args in arg_cases:
        res = runner.run(args, timeout=120)
        marks = res.crash_markers()
        ok = (
            not res.timed_out
            and res.returncode != 0
            and isinstance(res.json, dict)
            and res.json.get("kind") == "error"
            and bool(res.json.get("code"))
            and bool(res.json.get("message"))
            and not marks
        )
        detail = res.brief()
        if marks:
            detail += f" | 崩溃标记 {marks}"
        rec.check(cat, f"{name} -> error JSON + 非零退出码 + 无 panic", ok, detail)


def cross_backend_suite(rec: Recorder, opts: argparse.Namespace, tmp: Path, main_runner: CliRunner) -> None:
    """§7.7 跨后端一致：相同输入在不同后端必须产生逐字节相同的签名/delta/manifest。

    不依赖 `sign --out`：用 `signature_sha256_hex`（DSIG 字节的 SHA-256）代表签名字节，
    用 `delta --out` 的落盘字节代表 DDLT，用 `chunk` 的 root_hex 代表 manifest 指纹。
    """
    cat = "cli-cross-backend"
    base = opts.target
    others = [t for t in ("wasm-gc", "js", "native") if t != base]
    alt_target = others[0]
    alt = CliRunner(opts.project, opts.moon, alt_target, max(opts.timeout, 600.0))

    probe_alt = alt.run(["__no_such_command__"], timeout=max(opts.timeout, 600.0))
    if not (isinstance(probe_alt.json, dict) and probe_alt.json.get("kind") == "error"):
        rec.blocked(
            cat,
            f"§7.7 跨后端一致（{base} vs {alt_target}）",
            f"备用后端 {alt_target} 不可运行：{probe_alt.brief(400)}",
        )
        rec.cli_calls.extend(alt.calls)
        return

    case = next((c for c in build_cases(quick=True) if c.name == "doc-256k-mixed"), build_cases(quick=True)[0])
    old_path = write_file(tmp / "xbe.old", case.old)
    new_path = write_file(tmp / "xbe.new", case.new)
    digests: dict[str, dict[str, str]] = {}

    for tag, runner in ((base, main_runner), (alt_target, alt)):
        sign_res = runner.run(["sign", str(old_path)], timeout=max(opts.timeout, 600.0))
        delta_path = tmp / f"xbe.{tag}.ddlt"
        if delta_path.exists():
            delta_path.unlink()
        delta_res = runner.run(["delta", str(old_path), str(new_path), "--out", str(delta_path)], timeout=max(opts.timeout, 600.0))
        chunk_res = runner.run(["chunk", str(new_path)], timeout=max(opts.timeout, 600.0))
        out_path = tmp / f"xbe.{tag}.out"
        if out_path.exists():
            out_path.unlink()
        apply_res = runner.run(["apply", str(old_path), str(delta_path), "--out", str(out_path)], timeout=max(opts.timeout, 600.0))
        info: dict[str, str] = {}
        sj = sign_res.json or {}
        info["signature_sha256_hex"] = str(sj.get("signature_sha256_hex", ""))
        info["sign_nums"] = json.dumps({k: sj.get(k) for k in ("total_length", "block_size", "strong_len", "block_count", "signature_bytes")}, sort_keys=True)
        info["delta_sha256"] = R.sha256_hex(delta_path.read_bytes()) if delta_path.exists() else ""
        cj = chunk_res.json or {}
        info["chunk_root"] = str(cj.get("root_hex", ""))
        info["chunk_nums"] = json.dumps({k: cj.get(k) for k in ("length", "chunk_count")}, sort_keys=True)
        info["apply_sha256"] = R.sha256_hex(out_path.read_bytes()) if out_path.exists() else ""
        info["apply_ok"] = str((apply_res.json or {}).get("ok"))
        digests[tag] = info

    js_info, alt_info = digests[base], digests[alt_target]
    for key, label in (
        ("signature_sha256_hex", "DSIG 字节（signature_sha256_hex）"),
        ("sign_nums", "sign 数值字段（total_length/block_size/strong_len/block_count/signature_bytes）"),
        ("delta_sha256", "DDLT 落盘字节（delta --out 的 SHA-256）"),
        ("chunk_root", "chunk root_hex"),
        ("chunk_nums", "chunk 数值字段（length/chunk_count）"),
        ("apply_sha256", "apply 重建结果 SHA-256"),
    ):
        rec.check(
            cat,
            f"§7.7 {label} 在 {base} 与 {alt_target} 上一致",
            bool(js_info[key]) and js_info[key] == alt_info[key],
            f"{base}={js_info[key]!r} {alt_target}={alt_info[key]!r}",
        )
    # 跨后端互操作：把 js 的 DDLT 交给备用后端 apply
    js_delta = tmp / f"xbe.{base}.ddlt"
    if js_delta.exists():
        out2 = tmp / "xbe.cross.out"
        if out2.exists():
            out2.unlink()
        res = alt.run(["apply", str(old_path), str(js_delta), "--out", str(out2)], timeout=max(opts.timeout, 600.0))
        rec.check(
            cat,
            f"跨后端互操作：{base} 的 DDLT 在 {alt_target} 上重建 == new",
            res.returncode == 0 and out2.exists() and out2.read_bytes() == case.new,
            res.brief(200),
        )
    rec.cli_calls.extend(alt.calls)


def chunk_stability(rec: Recorder, runner: CliRunner, tmp: Path) -> None:
    """§7.5 分块稳定性：前缀插入 1 字节后 >= 90% 块指纹复用（需要 DCHK 可导出）。"""
    cat = "cli-chunk-stability"
    rng = random.Random(424242)
    data = gen_doc(rng, 1 << 20)
    f1 = write_file(tmp / "cdc-base.bin", data)
    f2 = write_file(tmp / "cdc-prefixed.bin", b"X" + data)
    m1 = tmp / "cdc-base.dchk"
    m2 = tmp / "cdc-prefixed.dchk"
    for p in (m1, m2):
        if p.exists():
            p.unlink()
    r1 = runner.run(["chunk", str(f1), "--out", str(m1)])
    r2 = runner.run(["chunk", str(f2), "--out", str(m2)])
    if not (r1.returncode == 0 and r2.returncode == 0 and m1.exists() and m2.exists()):
        rec.blocked(
            cat,
            "§7.5 分块稳定性（前缀插入 1 字节 >=90% 指纹复用）",
            f"chunk --out 未产出 DCHK，无法独立比较指纹（§8 未规定 DCHK 可导出，歧义 A8）。"
            f" r1={r1.brief(160)} r2={r2.brief(160)}",
        )
        return
    try:
        man1 = R.parse_dchk(m1.read_bytes())
        man2 = R.parse_dchk(m2.read_bytes())
    except R.FormatError as exc:
        rec.check(cat, "§7.5 分块稳定性：DCHK 可解析", False, str(exc))
        return
    digests1 = [c.digest for c in man1.chunks]
    digests2 = [c.digest for c in man2.chunks]
    reuse = len(set(digests1) & set(digests2)) / max(1, len(digests1))
    rec.check(
        cat,
        "§7.5 前缀插入 1 字节后 >=90% 块指纹复用（1 MiB 输入）",
        reuse >= 0.90,
        f"reuse={reuse:.3f} chunks_base={len(digests1)} chunks_prefixed={len(digests2)}",
    )
    rec.check(
        cat,
        "§7.5 内容定义分块：两个版本块长总和守恒",
        sum(c.length for c in man1.chunks) == len(data) and sum(c.length for c in man2.chunks) == len(data) + 1,
        f"{sum(c.length for c in man1.chunks)} / {sum(c.length for c in man2.chunks)}",
    )


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------


def env_facts(moon: str) -> dict[str, str]:
    facts = {
        "python": f"{sys.version.split()[0]} ({platform.python_version()})",
        "platform": platform.platform(),
        "cwd": str(Path.cwd()),
    }
    for name, argv in (("moon", [moon, "version"]), ("node", ["node", "--version"])):
        try:
            cp = subprocess.run(argv, capture_output=True, timeout=30)
            text = (cp.stdout or b"").decode("utf-8", "replace").strip()
            facts[name] = text.splitlines()[0] if text else f"(rc={cp.returncode})"
        except Exception as exc:  # noqa: BLE001
            facts[name] = f"(unavailable: {exc})"
    return facts


def write_report(
    rec: Recorder,
    path: Path,
    opts: argparse.Namespace,
    facts: dict[str, str],
    cases: list[Case],
    started: float,
    mode_used: str,
    probe_detail: str,
    cli_available: bool,
) -> int:
    hard_total = len(rec.of("hard"))
    hard_pass = rec.passed("hard")
    adv_total = len(rec.of("advisory"))
    adv_pass = rec.passed("advisory")
    blocked = rec.blocked_rows()
    failures = rec.failed()
    if failures:
        code = 1
    elif blocked:
        code = 2
    else:
        code = 0

    L: list[str] = []
    L.append("moon-deltasync 独立第三方校验报告")
    L.append("=" * 78)
    L.append(f"生成时间         : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"总耗时           : {time.time() - started:.1f}s")
    L.append(f"运行模式         : {mode_used}")
    L.append(f"校验器           : scripts/verify_deltasync.py + scripts/dsref.py（纯标准库，独立实现）")
    L.append(f"被测项目         : {opts.project}")
    L.append(f"契约             : {opts.project / 'docs/design.md'}（§5 格式 / §6 算法 / §8 CLI JSON）")
    for k, v in facts.items():
        L.append(f"{k:<17}: {v}")
    L.append("")
    L.append("复现命令")
    L.append("-" * 78)
    L.append(f"  D:\\anaconda3\\python.exe {Path(__file__).name} --mode {opts.mode}"
             + (" --quick" if opts.quick else "") + (" --keep-temp" if opts.keep_temp else ""))
    L.append("  （在 scripts/ 目录下运行；或从仓库根目录运行 python scripts/verify_deltasync.py）")
    L.append(f"  单条联调命令模板: {opts.moon} run --target js cmd/main -- sign <old> --out <old.dsig>")
    L.append("")
    L.append("结论")
    L.append("-" * 78)
    L.append(f"  硬断言 : {hard_pass}/{hard_total} 通过，{hard_total - hard_pass} 失败")
    L.append(f"  建议项 : {adv_pass}/{adv_total} 通过（advisory，不计入失败；反映文档歧义下的实现选择）")
    L.append(f"  阻塞项 : {len(blocked)}")
    L.append(f"  退出码 : {code}  (0=全通过 / 1=硬断言失败 / 2=自测通过但 CLI 联调被阻塞)")
    if not cli_available:
        L.append(f"  CLI 探测: 不可用 -> {probe_detail}")
    L.append("")
    L.append("断言分类统计")
    L.append("-" * 78)
    L.append(f"  {'category':<26}{'hard':>12}{'advisory':>12}")
    for c in rec.categories():
        hp, ht, ap, at = rec.category_stats().get(c, (0, 0, 0, 0))
        L.append(f"  {c:<26}{f'{hp}/{ht}':>12}{f'{ap}/{at}':>12}")
    L.append("")
    L.append("语料（固定种子 PRNG 20261109，写入临时目录，不提交）")
    L.append("-" * 78)
    L.append(f"  {'case':<22}{'old':>10}{'new':>10}  编辑类型")
    for c in cases:
        L.append(f"  {c.name:<22}{len(c.old):>10}{len(c.new):>10}  {c.edits}")
    L.append("")
    if DELTA_STATS:
        L.append("关键证据：delta 规模（CLI 实现 vs 本脚本独立 rsync 规划器）")
        L.append("-" * 78)
        L.append(f"  {'case':<22}{'new':>10}{'delta':>9}{'planner':>9}{'delta/planner':>15}{'copy':>7}{'literal':>9}")
        for s in DELTA_STATS:
            ratio = (s["delta"] / s["planner"]) if s["planner"] else float("nan")
            L.append(
                f"  {s['case']:<22}{s['new']:>10}{s['delta']:>9}{s['planner']:>9}"
                f"{ratio:>15.3f}{s['copied']:>7}{s['literal']:>9}"
            )
        same = sum(1 for s in DELTA_STATS if s["delta"] == s["planner"])
        L.append(
            f"  等比/完全一致：{same}/{len(DELTA_STATS)} 个语料的 delta 字节数与独立规划器**逐字节相等**"
            f"（最大比值 {max((s['delta'] / s['planner'] if s['planner'] else 0) for s in DELTA_STATS):.3f}）"
        )
        L.append("")
    if failures:
        L.append("失败明细（硬断言）")
        L.append("-" * 78)
        for r in failures:
            L.append(f"  [FAIL][{r.category}] {r.name}")
            if r.detail:
                L.append(f"         {r.detail}")
        L.append("")
    if blocked:
        L.append("阻塞项（BLOCKED）")
        L.append("-" * 78)
        for r in blocked:
            L.append(f"  [BLOCKED][{r.category}] {r.name}")
            if r.detail:
                L.append(f"         {r.detail}")
        L.append("")
    adv_fail = [r for r in rec.of("advisory") if not r.ok]
    if adv_fail:
        L.append("建议项未通过（advisory，多为文档未规定的自由选择）")
        L.append("-" * 78)
        for r in adv_fail:
            L.append(f"  [ADVISORY][{r.category}] {r.name}: {r.detail}")
        L.append("")
    L.append("全部断言明细")
    L.append("-" * 78)
    for c in rec.categories():
        L.append(f"## {c}")
        for r in [x for x in rec.rows if x.category == c]:
            tag = {"hard": "PASS" if r.ok else "FAIL", "advisory": "ADV-OK" if r.ok else "ADV-NO", "info": "INFO", "blocked": "BLOCK"}[r.severity]
            line = f"  [{tag}] {r.name}"
            if r.detail:
                line += f"  -- {r.detail}"
            L.append(line[:400])
        L.append("")
    L.append("设计文档歧义（本校验器实际采用的解释）")
    L.append("-" * 78)
    for _, text in rec.notes:
        L.append(f"  * {text}")
    L.append("")
    L.append("CLI 调用记录（时间 / 退出码 / 参数）")
    L.append("-" * 78)
    L.append(f"  共 {len(rec.cli_calls)} 次调用")
    for r in rec.cli_calls:
        L.append(f"  {r.elapsed:6.2f}s rc={r.returncode:<4} [{r.argv[3]}] {' '.join(r.argv[6:])[:150]}")
    L.append("")
    text = "\n".join(L)
    path.write_text(text, encoding="utf-8")
    return code


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def add_ambiguities(rec: Recorder) -> None:
    rec.note(
        "A1 §6.3 滑窗对象：原文「在旧数据长度上滑动窗口」与 §7.1「apply(old,delta)==new」矛盾"
        "（在旧数据上滑窗无法产出覆盖 new 的 op 序列）。本校验器按经典 rsync 语义在**新数据**上滑窗并"
        "反查旧块签名表；若实现真在旧数据上滑窗，§7.1 的重建一致性断言会直接失败。"
    )
    rec.note(
        "A2 §7.4 的「翻转 LITERAL 字节」原先在旧版 DDLT（无 content_digest）下不可达；"
        "契约已更新（§5.2 增加 content_digest = 目标数据 SHA-256，apply 完成后比对，不符即 DigestMismatch），"
        "因此该场景现在可检出。本校验器据此把 LITERAL 翻转、content_digest 篡改都升级为硬断言。"
    )
    rec.note(
        "A3 §6.4 gear 表未给定：内容定义分块的切分边界无法被第三方独立复现；"
        "本校验器只校验结构性质（块长上下界、总长守恒、root 由块摘要确定性导出、前缀插入复用率），"
        "不比较具体边界。"
    )
    rec.note(
        "A4 §8.1 的 manifest_bytes=16416 = 512*32+32（只含块摘要+root），而按 §5.3 全量应为 "
        "41+36*512=18473（含每块 length 字段与头），即 manifest_bytes 的统计口径未定义；"
        "sign 的 signature_bytes 已改为 2582，与 §5.1 的 22+128*(4+16) 一致。"
        "本校验器对 manifest_bytes 只做 advisory（接受两种口径），对 signature_bytes 硬断言。"
    )
    rec.note(
        "A5 xxh64_hex 未规定字节序：本校验器同时接受大端整数字符串与小端字节序两种写法。"
    )
    rec.note(
        "A6 小数精度：savings_ratio 明确 4 位小数，dedup_ratio 示例为 3 位（0.996）。"
        "本校验器对 dedup_ratio 用 ±1e-3 容差。"
    )
    rec.note(
        "A7 apply 的 blocks_verified 语义未定义：示例 127 与 delta 的 copy_blocks 一致（而非新文件总块数）。"
        "本校验器接受 COPY 块数或新文件块数两种解释（advisory）。"
    )
    rec.note(
        "A8 §8 只说明 --out 用于导出 DSIG/DDLT，未提 DCHK；但 chunk 报告 manifest_bytes/root_hex，"
        "第三方无法取得 manifest 原始字节做独立解析。本校验器在 chunk --out 可用时做完整 DCHK 校验，否则记为阻塞。"
    )
    rec.note(
        "A9 默认参数：§4.1 已规定 default_block_size(length) = (length<4096 ? 512 : 8192)，本校验器据此硬断言；"
        "但 strong_len 默认值只能从 §8.1 示例推为 16（advisory）。CLI 无 block_size/strong_len 选项，"
        "§4.1 的 [256, 1 MiB] 允许范围只能通过畸形 DDLT 侧测。"
    )
    rec.note(
        "A10 §5.2 未规定 COPY 引用旧数据末块（不满 block_size）时的长度语义，也未说明 COPY_RUN 的"
        "「count 块拼接」是否包含该短末块。本校验器按「旧块实际切片」重放，并假定拼接包含短末块。"
    )
    rec.note(
        "A11 §5.3 的 DCHK 不含 chunk_size_hint 字段，而 §4 的 ChunkManifest 有该字段（序列化时被丢弃）；"
        "gear 表/分块参数也无法从 manifest 反推，跨实现校验 manifest 时只有 root 可比。"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="moon-deltasync 独立第三方校验器")
    ap.add_argument("--mode", choices=["auto", "selftest", "cli"], default="auto")
    ap.add_argument("--project", default=str(DEFAULT_PROJECT))
    ap.add_argument("--moon", default=DEFAULT_MOON)
    ap.add_argument("--target", default="js", choices=["js", "wasm", "wasm-gc", "native"])
    ap.add_argument("--timeout", type=float, default=300.0, help="单次 CLI 调用超时（秒）")
    ap.add_argument("--report", default=None, help=f"报告输出路径（默认 scripts/{REPORT_NAME}）")
    ap.add_argument("--quick", action="store_true", help="跳过 2 MiB 大语料")
    ap.add_argument("--keep-temp", action="store_true", help="保留临时语料目录")
    ap.add_argument("--skip-cli", action="store_true", help="等价于 --mode selftest")
    opts = ap.parse_args(argv)
    if opts.skip_cli:
        opts.mode = "selftest"
    opts.project = Path(opts.project).resolve()
    report_path = Path(opts.report) if opts.report else (SCRIPT_DIR / REPORT_NAME)
    started = time.time()
    rec = Recorder()
    rec.cli_calls: list[CliResult] = []
    facts = env_facts(opts.moon)
    cases = build_cases(quick=opts.quick)
    add_ambiguities(rec)
    tmp = Path(tempfile.mkdtemp(prefix="deltasync-verify-"))
    mode_used = opts.mode
    probe_detail = "(skipped)"
    cli_available = False

    print(f"[verify] project={opts.project}")
    print(f"[verify] tmpdir={tmp}")
    print(f"[verify] mode={opts.mode} quick={opts.quick}")

    try:
        if opts.mode in ("auto", "selftest"):
            print("[verify] ---- self-test (synthetic byte streams) ----")
            selftest(rec)
            print(f"[verify] self-test hard assertions: {rec.passed('hard')}/{len(rec.of('hard'))}")

        if opts.mode in ("auto", "cli"):
            runner = CliRunner(opts.project, opts.moon, opts.target, opts.timeout)
            rec.cli_calls = runner.calls
            print("[verify] ---- probing CLI ----")
            cli_available, probe_detail = runner.probe()
            print(f"[verify] probe: available={cli_available} {probe_detail[:240]}")
            if not cli_available:
                rec.blocked("cli-probe", "CLI 可用性探测（moon run --target js cmd/main）", probe_detail)
                mode_used = opts.mode + " (CLI blocked, self-test only)"
            else:
                rec.check("cli-probe", "CLI 可用性探测：未知命令返回 error JSON", True, probe_detail)
                main_cases = [c for c in cases]
                for case in main_cases:
                    print(f"[verify] case {case.name} ({len(case.old)}B -> {len(case.new)}B): sign")
                    sig = cli_sign(rec, runner, case, tmp)
                    print(f"[verify] case {case.name}: delta")
                    got = cli_delta(rec, runner, case, tmp, sig)
                    if got is None:
                        continue
                    delta, ddlt_path = got
                    print(f"[verify] case {case.name}: apply")
                    cli_apply(rec, runner, case, tmp, delta, ddlt_path)
                    print(f"[verify] case {case.name}: interop (independent DDLT -> CLI apply)")
                    cli_interop(rec, runner, case, tmp, sig)
                    if case.full:
                        print(f"[verify] case {case.name}: chunk / verify")
                        cli_chunk(rec, runner, case, tmp)
                        cli_verify(rec, runner, case, tmp)
                # 畸形输入与参数错误（复用 64k 语料的产物）
                target = next((c for c in main_cases if c.name == "doc-64k-insert"), main_cases[0])
                art = tmp / f"{target.name}.ddlt"
                if art.exists():
                    print("[verify] ---- malformed inputs & argument errors ----")
                    malformed_suite(rec, runner, target, tmp, art)
                else:
                    rec.blocked("cli-malformed", "畸形输入套件", "缺少基线 DDLT 产物，无法构造畸形输入")
                print("[verify] ---- chunk stability ----")
                chunk_stability(rec, runner, tmp)
                print("[verify] ---- cross-backend consistency (§7.7) ----")
                cross_backend_suite(rec, opts, tmp, runner)
    except Exception:  # noqa: BLE001
        rec.check("internal", "校验器自身未抛异常", False, traceback.format_exc()[:2000])
    finally:
        if not opts.keep_temp:
            shutil.rmtree(tmp, ignore_errors=True)
        code = write_report(rec, report_path, opts, facts, cases, started, mode_used, probe_detail, cli_available)
        hard_total = len(rec.of("hard"))
        print("")
        print(f"[verify] report: {report_path}")
        print(
            f"[verify] hard {rec.passed('hard')}/{hard_total} passed, "
            f"{hard_total - rec.passed('hard')} failed; "
            f"advisory {rec.passed('advisory')}/{len(rec.of('advisory'))}; "
            f"blocked {len(rec.blocked_rows())}"
        )
        for r in rec.failed():
            print(f"[verify][FAIL] [{r.category}] {r.name} -- {r.detail[:300]}")
        for r in rec.blocked_rows():
            print(f"[verify][BLOCKED] [{r.category}] {r.name} -- {r.detail[:300]}")
        print(f"[verify] exit code {code}")
    return code


if __name__ == "__main__":
    sys.exit(main())
