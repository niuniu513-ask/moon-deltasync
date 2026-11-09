#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dsref -- moon-deltasync 的独立参考实现（纯 Python 3 标准库）。

本模块**只依据** `docs/design.md` 的文字语义重新实现，不读取、不翻译被测
MoonBit 源码。它的用途是给 `verify_deltasync.py` 提供第三方「语义对照物」：

  * §6.1  Adler-32 变体弱校验（模 65521）与滑动更新
  * §6.2  SHA-256（hashlib）、XXH64（标准 xxHash64，seed=0）
  * §5.1  DSIG v1 解析 / 序列化
  * §5.2  DDLT v1 解析 / 序列化 / 规范化检查
  * §5.3  DCHK v1 解析 / 序列化
  * §5.2+§7.1  delta 重放：逐块重算强校验，发现 BlockMismatch
  * §6.3  rsync 风格 delta 规划器（用于独立估算 delta 字节数）
  * §6.4  内容定义分块（gear hash）的参考实现——**仅供参考**：
          design.md 没有规定 gear 表，因此边界不保证与被测实现一致（歧义 A3）。

约定与文档对齐:
  * 所有整数大端定长；magic 为 4 字节 ASCII。
  * 弱校验 weak = (b << 16) | a，a/b 均为模 65521 的非负值。
  * 强校验 = sha256(block)[0:strong_len]，strong_len ∈ {8, 16}。
"""

from __future__ import annotations

import hashlib

MOD = 65521

# §4.1 块大小与规模上界（实现即契约）
MIN_BLOCK_SIZE = 256
MAX_BLOCK_SIZE = 1 << 20
MAX_BLOCK_COUNT = 1_000_000
MAX_TOTAL_LENGTH = 1 << 40


def default_block_size(length: int) -> int:
    """§4.1: length < 4096 -> 512，否则 8192。"""
    return 512 if length < 4096 else 8192


# ---------------------------------------------------------------------------
# §6.1 弱校验（Adler-32 变体，模 65521）
# ---------------------------------------------------------------------------


def weak_checksum(data: bytes) -> int:
    """§6.1（2026-11-09 修订）：标准 Adler-32 语义。

        a = 1 + Σ w[i]            (mod 65521)
        b = n + Σ (n - i) * w[i]  (mod 65521)
        weak = (b << 16) | a

    与 zlib.adler32 完全一致（自测里直接和 zlib 对比）。
    """
    n = len(data)
    a = 1
    b = n
    for i, byte in enumerate(data):
        a += byte
        b += (n - i) * byte
    return (((b % MOD) & 0xFFFF) << 16) | ((a % MOD) & 0xFFFF)


class RollingWeak:
    """§6.1 滑动窗口弱校验的增量更新（加入/移出字节，窗口长度不变）。

    修订后（带常数 1）：
        a' = a - out + in
        b' = b - n * out + a' - 1
    """

    __slots__ = ("n", "a", "b")

    def __init__(self, window: bytes):
        n = len(window)
        self.n = n
        a = 1
        b = n
        for i, byte in enumerate(window):
            a += byte
            b += (n - i) * byte
        self.a = a % MOD
        self.b = b % MOD

    def value(self) -> int:
        return ((self.b & 0xFFFF) << 16) | (self.a & 0xFFFF)

    def roll(self, out_byte: int, in_byte: int) -> int:
        """移出 out_byte、移入 in_byte；返回新窗口的 weak。"""
        n = self.n
        a = (self.a - out_byte + in_byte) % MOD
        b = (self.b - n * out_byte + a - 1) % MOD
        self.a = a
        self.b = b
        return self.value()


# ---------------------------------------------------------------------------
# §6.2 XXH64（标准 xxHash64，seed = 0）
# ---------------------------------------------------------------------------

_M64 = (1 << 64) - 1
_P1 = 0x9E3779B185EBCA87
_P2 = 0xC2B2AE3D27D4EB4F
_P3 = 0x165667B19E3779F9
_P4 = 0x85EBCA77C2B2AE63
_P5 = 0x27D4EB2F165667C5


def _rotl(x: int, r: int) -> int:
    return ((x << r) | (x >> (64 - r))) & _M64


def _round(acc: int, inp: int) -> int:
    acc = (acc + inp * _P2) & _M64
    acc = _rotl(acc, 31)
    return (acc * _P1) & _M64


def _merge(acc: int, val: int) -> int:
    val = _round(0, val)
    acc ^= val
    return (acc * _P1 + _P4) & _M64


def xxh64(data: bytes, seed: int = 0) -> int:
    n = len(data)
    i = 0
    if n >= 32:
        v1 = (seed + _P1 + _P2) & _M64
        v2 = (seed + _P2) & _M64
        v3 = seed & _M64
        v4 = (seed - _P1) & _M64
        while i + 32 <= n:
            v1 = _round(v1, int.from_bytes(data[i : i + 8], "little"))
            v2 = _round(v2, int.from_bytes(data[i + 8 : i + 16], "little"))
            v3 = _round(v3, int.from_bytes(data[i + 16 : i + 24], "little"))
            v4 = _round(v4, int.from_bytes(data[i + 24 : i + 32], "little"))
            i += 32
        h = (_rotl(v1, 1) + _rotl(v2, 7) + _rotl(v3, 12) + _rotl(v4, 18)) & _M64
        h = _merge(h, v1)
        h = _merge(h, v2)
        h = _merge(h, v3)
        h = _merge(h, v4)
    else:
        h = (seed + _P5) & _M64
    h = (h + n) & _M64
    while i + 8 <= n:
        k = _round(0, int.from_bytes(data[i : i + 8], "little"))
        h ^= k
        h = (_rotl(h, 27) * _P1 + _P4) & _M64
        i += 8
    if i + 4 <= n:
        h ^= (int.from_bytes(data[i : i + 4], "little") * _P1) & _M64
        h = (_rotl(h, 23) * _P2 + _P3) & _M64
        i += 4
    while i < n:
        h ^= (data[i] * _P5) & _M64
        h = (_rotl(h, 11) * _P1) & _M64
        i += 1
    h ^= h >> 33
    h = (h * _P2) & _M64
    h ^= h >> 29
    h = (h * _P3) & _M64
    h ^= h >> 32
    return h


def xxh64_hex_candidates(data: bytes, seed: int = 0) -> tuple[str, str]:
    """XXH64 的十六进制「大端整数字符串」与「小端字节序」两种候选写法。

    design.md 只写了 `xxh64_hex`，没有规定字节序（歧义 A5），因此两种都接受。
    """
    h = xxh64(data, seed)
    return (f"{h:016x}", h.to_bytes(8, "little").hex())


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------


class FormatError(Exception):
    """格式/边界错误（对应 design.md 的 FormatMismatch）。"""


class ReplayError(Exception):
    """delta 重放错误。

    code: 稳定错误标识，便于断言
      - "format"         格式层错误
      - "block-index"    COPY 块号越界
      - "block-mismatch" 逐块强校验不一致（对应 BlockMismatch(index)）
      - "length"         op 覆盖长度与 new_length 不一致
    """

    def __init__(self, code: str, message: str, block_index: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.block_index = block_index


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


class Reader:
    """带边界检查的大端读取器：任何越界都抛 FormatError，不 panic。"""

    __slots__ = ("d", "i")

    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def remaining(self) -> int:
        return len(self.d) - self.i

    def take(self, n: int) -> bytes:
        if n < 0:
            raise FormatError(f"negative read length {n}")
        if self.i + n > len(self.d):
            raise FormatError(
                f"truncated: need {n} byte(s) at offset {self.i}, "
                f"only {self.remaining()} available (total {len(self.d)})"
            )
        v = self.d[self.i : self.i + n]
        self.i += n
        return v

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "big")


def _be32(v: int) -> bytes:
    return (v & 0xFFFFFFFF).to_bytes(4, "big")


def _be64(v: int) -> bytes:
    return (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")


# ---------------------------------------------------------------------------
# §5.1 DSIG v1
# ---------------------------------------------------------------------------


class BlockSignature:
    __slots__ = ("index", "weak", "strong")

    def __init__(self, index: int, weak: int, strong: bytes):
        self.index = index
        self.weak = weak
        self.strong = strong

    def __repr__(self) -> str:  # pragma: no cover
        return f"BlockSignature(index={self.index}, weak={self.weak:#010x}, strong={self.strong.hex()})"


class FileSignature:
    __slots__ = ("block_size", "strong_len", "total_length", "blocks")

    def __init__(self, block_size: int, strong_len: int, total_length: int, blocks: list[BlockSignature]):
        self.block_size = block_size
        self.strong_len = strong_len
        self.total_length = total_length
        self.blocks = blocks

    def block_count(self) -> int:
        return len(self.blocks)


def build_signature(data: bytes, block_size: int, strong_len: int) -> FileSignature:
    """按 §5.1 的块划分方式独立计算签名。"""
    if block_size <= 0:
        raise FormatError("block_size must be positive")
    if strong_len not in (8, 16):
        raise FormatError(f"strong_len must be 8 or 16, got {strong_len}")
    n = len(data)
    count = ceil_div(n, block_size)
    blocks = []
    for i in range(count):
        chunk = data[i * block_size : (i + 1) * block_size]
        blocks.append(BlockSignature(i, weak_checksum(chunk), sha256(chunk)[:strong_len]))
    return FileSignature(block_size, strong_len, n, blocks)


def parse_dsig(data: bytes) -> FileSignature:
    r = Reader(data)
    magic = r.take(4)
    if magic != b"DSIG":
        raise FormatError(f"bad magic {magic!r}, expected b'DSIG'")
    version = r.u8()
    if version != 1:
        raise FormatError(f"unsupported DSIG version {version}")
    block_size = r.u32()
    strong_len = r.u8()
    total_length = r.u64()
    block_count = r.u32()
    if strong_len not in (8, 16):
        raise FormatError(f"strong_len must be 8 or 16, got {strong_len}")
    if block_size == 0:
        raise FormatError("block_size must be positive, got 0")
    expect = ceil_div(total_length, block_size)
    if block_count != expect:
        raise FormatError(
            f"block_count {block_count} != ceil(total_length/block_size) = {expect}"
        )
    need = block_count * (4 + strong_len)
    if r.remaining() != need:
        raise FormatError(
            f"DSIG payload size {r.remaining()} != block_count*(4+strong_len) = {need}"
        )
    blocks = []
    for i in range(block_count):
        weak = r.u32()
        strong = r.take(strong_len)
        blocks.append(BlockSignature(i, weak, strong))
    return FileSignature(block_size, strong_len, total_length, blocks)


def serialize_dsig(sig: FileSignature) -> bytes:
    out = bytearray()
    out += b"DSIG"
    out.append(1)
    out += _be32(sig.block_size)
    out.append(sig.strong_len)
    out += _be64(sig.total_length)
    out += _be32(len(sig.blocks))
    for b in sig.blocks:
        out += _be32(b.weak)
        out += b.strong
    return bytes(out)


# ---------------------------------------------------------------------------
# §5.2 DDLT v1
# ---------------------------------------------------------------------------

TAG_COPY = 0
TAG_LITERAL = 1
TAG_COPY_RUN = 2

# §5.2 DDLT 头部布局偏移（供畸形输入构造使用）
DDLT_OFF_OP_COUNT = 4 + 1 + 4 + 1 + 8 + 32  # = 50
DDLT_OFF_CONTENT_DIGEST = 4 + 1 + 4 + 1 + 8  # = 18
DDLT_OFF_FIRST_OP = DDLT_OFF_OP_COUNT + 4  # = 54
DDLT_HEADER_LEN = DDLT_OFF_FIRST_OP


class Delta:
    """DDLT v1 的内存表示（content_digest 是目标数据的 SHA-256）。

    ops 元素（§5.2，每个 COPY/COPY_RUN 自带强校验）：
      ("copy", block_index, strong)          strong = sha256(旧块)[0:strong_len]
      ("copy_run", start, count, strong)     strong = sha256(旧块拼接)[0:strong_len]
      ("lit", bytes)                         LITERAL 不携带校验，由 content_digest 兜底
    """

    __slots__ = ("block_size", "strong_len", "new_length", "content_digest", "ops")

    def __init__(
        self,
        block_size: int,
        strong_len: int,
        new_length: int,
        ops: list[tuple],
        content_digest: bytes | None = None,
    ):
        self.block_size = block_size
        self.strong_len = strong_len
        self.new_length = new_length
        self.content_digest = content_digest if content_digest is not None else bytes(32)
        self.ops = ops

    # --- 统计 -----------------------------------------------------------
    def copy_block_count(self) -> int:
        """COPY/COPY_RUN 展开后的「复制块」个数。"""
        total = 0
        for op in self.ops:
            if op[0] == "copy":
                total += 1
            elif op[0] == "copy_run":
                total += op[2]
        return total

    def literal_bytes(self) -> int:
        return sum(len(op[1]) for op in self.ops if op[0] == "lit")

    def copy_indexes(self) -> list[int]:
        out = []
        for op in self.ops:
            if op[0] == "copy":
                out.append(op[1])
            elif op[0] == "copy_run":
                out.extend(range(op[1], op[1] + op[2]))
        return out

    def __repr__(self) -> str:  # pragma: no cover
        return f"Delta(bs={self.block_size}, sl={self.strong_len}, new={self.new_length}, ops={len(self.ops)})"


def parse_ddlt(data: bytes) -> Delta:
    r = Reader(data)
    magic = r.take(4)
    if magic != b"DDLT":
        raise FormatError(f"bad magic {magic!r}, expected b'DDLT'")
    version = r.u8()
    if version != 1:
        raise FormatError(f"unsupported DDLT version {version}")
    block_size = r.u32()
    strong_len = r.u8()
    new_length = r.u64()
    content_digest = r.take(32)
    op_count = r.u32()
    if block_size == 0:
        raise FormatError("block_size must be positive, got 0")
    if strong_len not in (8, 16):
        raise FormatError(f"strong_len must be 8 or 16, got {strong_len}")
    # 每个 op 至少 1 字节（tag），用剩余字节数挡住「超大 count」导致的长时间循环。
    if op_count > r.remaining():
        raise FormatError(
            f"op_count {op_count} exceeds remaining payload {r.remaining()} byte(s)"
        )
    ops = []
    for _ in range(op_count):
        tag = r.u8()
        if tag == TAG_COPY:
            idx = r.u32()
            strong = r.take(strong_len)
            ops.append(("copy", idx, strong))
        elif tag == TAG_COPY_RUN:
            start = r.u32()
            count = r.u32()
            strong = r.take(strong_len)
            ops.append(("copy_run", start, count, strong))
        elif tag == TAG_LITERAL:
            length = r.u32()
            if length > r.remaining():
                raise FormatError(
                    f"LITERAL length {length} exceeds remaining payload {r.remaining()} byte(s)"
                )
            ops.append(("lit", r.take(length)))
        else:
            raise FormatError(f"unknown op tag {tag} at op index {len(ops)}")
    if r.remaining() != 0:
        raise FormatError(f"DDLT has {r.remaining()} trailing byte(s) after {op_count} op(s)")
    return Delta(block_size, strong_len, new_length, ops, content_digest)


def serialize_ddlt(delta: Delta) -> bytes:
    out = bytearray()
    out += b"DDLT"
    out.append(1)
    out += _be32(delta.block_size)
    out.append(delta.strong_len)
    out += _be64(delta.new_length)
    out += delta.content_digest if len(delta.content_digest) == 32 else bytes(32)
    out += _be32(len(delta.ops))
    for op in delta.ops:
        if op[0] == "copy":
            if len(op) != 3 or len(op[2]) != delta.strong_len:
                raise FormatError("COPY op must carry a strong digest of strong_len bytes")
            out.append(TAG_COPY)
            out += _be32(op[1])
            out += op[2]
        elif op[0] == "copy_run":
            if len(op) != 4 or len(op[3]) != delta.strong_len:
                raise FormatError("COPY_RUN op must carry a strong digest of strong_len bytes")
            out.append(TAG_COPY_RUN)
            out += _be32(op[1])
            out += _be32(op[2])
            out += op[3]
        elif op[0] == "lit":
            out.append(TAG_LITERAL)
            out += _be32(len(op[1]))
            out += op[1]
        else:  # pragma: no cover
            raise FormatError(f"unknown op {op[0]!r}")
    return bytes(out)


def delta_size(block_size: int, strong_len: int, new_length: int, ops: list[tuple]) -> int:
    return len(serialize_ddlt(Delta(block_size, strong_len, new_length, ops)))


def normalization_violations(ops: list[tuple]) -> list[str]:
    """§5.2 规范化要求：相邻 COPY 必须合并为 COPY_RUN，相邻 LITERAL 必须合并。"""
    problems = []
    prev = None
    for i, op in enumerate(ops):
        if op[0] == "lit":
            if len(op[1]) == 0:
                problems.append(f"op[{i}] LITERAL is empty")
            if prev is not None and prev[0] == "lit":
                problems.append(f"op[{i}] LITERAL is adjacent to previous LITERAL (must merge)")
        elif op[0] in ("copy", "copy_run"):
            if op[0] == "copy_run":
                if op[2] == 0:
                    problems.append(f"op[{i}] COPY_RUN count == 0")
                elif op[2] == 1:
                    problems.append(f"op[{i}] COPY_RUN count == 1 (should be COPY)")
            if prev is not None and prev[0] in ("copy", "copy_run"):
                problems.append(
                    f"op[{i}] {op[0].upper()} is adjacent to previous copy op (must merge into COPY_RUN)"
                )
        else:
            problems.append(f"op[{i}] unknown op kind {op[0]!r}")
        prev = op
    return problems


# ---------------------------------------------------------------------------
# §5.3 DCHK v1
# ---------------------------------------------------------------------------


class ChunkRef:
    __slots__ = ("digest", "length")

    def __init__(self, digest: bytes, length: int):
        self.digest = digest
        self.length = length

    def __repr__(self) -> str:  # pragma: no cover
        return f"ChunkRef({self.digest.hex()[:8]}..., {self.length})"


class Manifest:
    __slots__ = ("min_size", "max_size", "mask_bits", "chunks", "root")

    def __init__(self, min_size: int, max_size: int, mask_bits: int, chunks: list[ChunkRef], root: bytes):
        self.min_size = min_size
        self.max_size = max_size
        self.mask_bits = mask_bits
        self.chunks = chunks
        self.root = root

    @property
    def chunk_size_hint(self) -> int:  # 兼容旧字段名：avg = 2^mask_bits
        return 1 << self.mask_bits if self.mask_bits < 63 else 0


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    """§5.3 无符号 LEB128 varint；解析时最多 10 字节，超出即 Truncated。"""
    value = 0
    shift = 0
    consumed = 0
    while True:
        if i >= len(buf):
            raise FormatError("truncated varint")
        byte = buf[i]
        i += 1
        consumed += 1
        if consumed > 10:
            raise FormatError("varint longer than 10 bytes")
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, i
        shift += 7


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def parse_dchk(data: bytes) -> Manifest:
    """§5.3（2026-11-09 修订）：DCHK v1

        "DCHK"(4) version:u8=1 min_size:u32 max_size:u32 mask_bits:u8 chunk_count:u32
        repeat chunk_count 次: sha256:u8[32] length:varint
        root:u8[32]

    解析后重算 root 与尾部比较（§5.3 要求 BadField）。
    """
    r = Reader(data)
    magic = r.take(4)
    if magic != b"DCHK":
        raise FormatError(f"bad magic {magic!r}, expected b'DCHK'")
    version = r.u8()
    if version != 1:
        raise FormatError(f"unsupported DCHK version {version}")
    min_size = r.u32()
    max_size = r.u32()
    mask_bits = r.u8()
    chunk_count = r.u32()
    if min_size == 0 or max_size == 0 or min_size > max_size:
        raise FormatError(f"BadField: implausible chunk bounds min={min_size} max={max_size}")
    if mask_bits >= 64:
        raise FormatError(f"BadField: mask_bits {mask_bits} >= 64")
    # 每条记录至少 32 字节摘要 + 1 字节 varint
    if chunk_count * 33 > r.remaining():
        raise FormatError(
            f"Truncated: chunk_count {chunk_count} needs >= {chunk_count * 33} byte(s), "
            f"remaining {r.remaining()}"
        )
    chunks: list[ChunkRef] = []
    for _ in range(chunk_count):
        digest = r.take(32)
        length, r.i = _read_varint(data, r.i)
        chunks.append(ChunkRef(digest, length))
    root = r.take(32)
    if r.remaining() != 0:
        raise FormatError(f"BadField: DCHK has {r.remaining()} trailing byte(s)")
    if root != manifest_root(chunks):
        raise FormatError(
            f"BadField: root {root.hex()} != sha256(concat(chunk sha256)) {manifest_root(chunks).hex()}"
        )
    return Manifest(min_size, max_size, mask_bits, chunks, root)


def serialize_dchk(manifest: Manifest) -> bytes:
    out = bytearray()
    out += b"DCHK"
    out.append(1)
    out += _be32(manifest.min_size)
    out += _be32(manifest.max_size)
    out.append(manifest.mask_bits)
    out += _be32(len(manifest.chunks))
    for c in manifest.chunks:
        out += c.digest
        out += _encode_varint(c.length)
    out += manifest.root
    return bytes(out)


def manifest_root(chunks: list[ChunkRef]) -> bytes:
    return sha256(b"".join(c.digest for c in chunks))


# ---------------------------------------------------------------------------
# §6.3 rsync 风格 delta 规划器（独立实现，用于比较 delta 字节数）
# ---------------------------------------------------------------------------


def plan_delta(
    old: bytes,
    new: bytes,
    block_size: int,
    strong_len: int,
    sig: FileSignature | None = None,
) -> list[tuple]:
    """按 §6.3 生成规范化 op 列表。

    语义说明（见报告歧义 A1）：design.md §6.3 原文写「在旧数据长度上滑动窗口」，
    但要让 §7.1 `apply(old, delta) == new` 成立，滑窗必须走**新数据**并反查
    旧数据的块签名表（经典 rsync 语义）。本实现按后者执行。

    返回 op 列表，元素为：
      ("copy", old_block_index)
      ("copy_run", start, count)
      ("lit", bytes)
    """
    if block_size <= 0:
        raise FormatError("block_size must be positive")
    if sig is None:
        sig = build_signature(old, block_size, strong_len)
    if sig.block_size != block_size or sig.strong_len != strong_len:
        raise FormatError("signature parameters disagree with planner parameters")

    index: dict[int, list[BlockSignature]] = {}
    for b in sig.blocks:
        index.setdefault(b.weak, []).append(b)

    ops: list[tuple] = []
    lit = bytearray()

    def flush_lit() -> None:
        if lit:
            ops.append(("lit", bytes(lit)))
            lit.clear()

    n = len(new)
    bs = block_size
    pos = 0
    if n >= bs:
        a = 0
        bsum = 0
        for i in range(bs):
            byte = new[i]
            a += byte
            bsum += (bs - i) * byte
        a %= MOD
        bsum %= MOD
        while pos + bs <= n:
            weak = ((bsum & 0xFFFF) << 16) | (a & 0xFFFF)
            cands = index.get(weak)
            matched = None
            if cands:
                strong = sha256(new[pos : pos + bs])[:strong_len]
                for cand in cands:
                    if cand.strong == strong:
                        matched = cand
                        break
            if matched is not None:
                flush_lit()
                ops.append(("copy", matched.index))
                pos += bs
                if pos + bs <= n:
                    a = 0
                    bsum = 0
                    for i in range(bs):
                        byte = new[pos + i]
                        a += byte
                        bsum += (bs - i) * byte
                    a %= MOD
                    bsum %= MOD
                continue
            lit.append(new[pos])
            if pos + bs < n:
                out_byte = new[pos]
                in_byte = new[pos + bs]
                a = a - out_byte + in_byte
                a %= MOD
                bsum = (bsum - bs * out_byte + a) % MOD
            pos += 1

    # 尾部不足一个窗口：允许匹配旧数据最后一个不完整块（长度相等时）。
    if pos < n:
        tail = new[pos:]
        cand = None
        if sig.blocks:
            last = sig.blocks[-1]
            last_len = len(old) - last.index * bs
            if last_len < bs and last_len == len(tail):
                if last.weak == weak_checksum(tail) and last.strong == sha256(tail)[:strong_len]:
                    cand = last
        if cand is not None:
            flush_lit()
            ops.append(("copy", cand.index))
        else:
            lit.extend(tail)
    flush_lit()
    return normalize_ops(ops)


def normalize_ops(ops: list[tuple]) -> list[tuple]:
    """§5.2/§7.2 规范化：合并相邻同类 op，COPY_RUN(count=1) 退化成 COPY。"""
    merged: list[tuple] = []
    for op in ops:
        if op[0] == "lit":
            data = op[1]
            if not data:
                continue
            if merged and merged[-1][0] == "lit":
                merged[-1] = ("lit", merged[-1][1] + data)
            else:
                merged.append(("lit", data))
            continue
        # copy / copy_run
        if op[0] == "copy":
            start, count = op[1], 1
        else:
            start, count = op[1], op[2]
            if count <= 0:
                continue
        if merged and merged[-1][0] in ("copy", "copy_run"):
            prev = merged[-1]
            pstart, pcount = (prev[1], 1) if prev[0] == "copy" else (prev[1], prev[2])
            if pstart + pcount == start:
                merged[-1] = ("copy_run", pstart, pcount + count)
                continue
        merged.append(("copy", start) if count == 1 else ("copy_run", start, count))
    # 合并后可能出现 count==1 的 run？只有 pcount+count>=2，因此不会。
    return merged


def plan_delta_serialized(old: bytes, new: bytes, block_size: int, strong_len: int) -> bytes:
    return serialize_ddlt(make_delta(old, new, block_size, strong_len))


def strong_of_blocks(old: bytes, block_size: int, strong_len: int, start: int, count: int) -> bytes:
    """§5.2: COPY 的强校验 = 单块摘要；COPY_RUN = 连续 count 块拼接后的整体摘要。"""
    h = hashlib.sha256()
    for i in range(start, start + count):
        h.update(old[i * block_size : (i + 1) * block_size])
    return h.digest()[:strong_len]


def finalize_ops(old: bytes, block_size: int, strong_len: int, ops: list[tuple]) -> list[tuple]:
    """把结构 op（无校验）补成 §5.2 带强校验的 op。"""
    out: list[tuple] = []
    for op in ops:
        if op[0] == "copy":
            out.append(("copy", op[1], strong_of_blocks(old, block_size, strong_len, op[1], 1)))
        elif op[0] == "copy_run":
            out.append(
                ("copy_run", op[1], op[2], strong_of_blocks(old, block_size, strong_len, op[1], op[2]))
            )
        else:
            out.append(op)
    return out


def make_delta(
    old: bytes, new: bytes, block_size: int, strong_len: int, sig: FileSignature | None = None
) -> Delta:
    structural = plan_delta(old, new, block_size, strong_len, sig)
    return Delta(
        block_size,
        strong_len,
        len(new),
        finalize_ops(old, block_size, strong_len, structural),
        sha256(new),
    )


# ---------------------------------------------------------------------------
# §5.2 + §7.1 delta 重放（逐块强校验）
# ---------------------------------------------------------------------------


def replay(old: bytes, delta: Delta, sig: FileSignature | None = None) -> bytes:
    """把 delta 应用到 old，并按 §5.2 逐 op 重算强校验。

    §5.2（新版契约）：delta 自带校验，每个 COPY / COPY_RUN 都携带所复制内容的强校验，
    因此 `apply` 无需签名文件即可逐 op 验证。本函数据此把 op 内记录的摘要作为期望值；
    可选 sig（`sign` 的输出）用于额外交叉校验 delta 与签名是否一致。
    """
    if sig is not None:
        if sig.block_size != delta.block_size:
            raise ReplayError(
                "format",
                f"signature block_size {sig.block_size} != delta block_size {delta.block_size}",
            )
        if sig.strong_len != delta.strong_len:
            raise ReplayError(
                "format",
                f"signature strong_len {sig.strong_len} != delta strong_len {delta.strong_len}",
            )
        if sig.total_length != len(old):
            raise ReplayError(
                "format",
                f"signature total_length {sig.total_length} != len(old) {len(old)}",
            )
    bs = delta.block_size
    sl = delta.strong_len
    old_block_count = ceil_div(len(old), bs) if bs else 0
    out = bytearray()
    for op_i, op in enumerate(delta.ops):
        if op[0] == "lit":
            out += op[1]
            continue
        if op[0] == "copy":
            start, count, want = op[1], 1, op[2]
        elif op[0] == "copy_run":
            start, count, want = op[1], op[2], op[3]
            if count <= 0:
                raise ReplayError("format", f"op[{op_i}] COPY_RUN count {count} is not positive")
        else:  # pragma: no cover
            raise ReplayError("format", f"op[{op_i}] unknown op kind {op[0]!r}")
        for idx in range(start, start + count):
            if idx < 0 or idx >= old_block_count:
                raise ReplayError(
                    "block-index",
                    f"op[{op_i}] COPY block index {idx} out of range "
                    f"(old has {old_block_count} block(s) of size {bs})",
                    block_index=idx,
                )
        chunk = b"".join(old[i * bs : (i + 1) * bs] for i in range(start, start + count))
        got = sha256(chunk)[:sl]
        if got != want:
            raise ReplayError(
                "block-mismatch",
                f"op[{op_i}] COPY_RUN(start={start}, count={count}) strong mismatch: "
                f"recomputed {got.hex()}, delta records {want.hex()} (BlockMismatch({start}))",
                block_index=start,
            )
        if sig is not None:
            for idx in range(start, start + count):
                if idx >= len(sig.blocks):
                    raise ReplayError(
                        "block-index",
                        f"op[{op_i}] COPY block index {idx} has no entry in signature "
                        f"({len(sig.blocks)} block(s))",
                        block_index=idx,
                    )
                sig_strong = sig.blocks[idx].strong
                if sha256(old[idx * bs : (idx + 1) * bs])[:sl] != sig_strong:
                    raise ReplayError(
                        "sig-mismatch",
                        f"op[{op_i}] block {idx}: signature strong {sig_strong.hex()} disagrees "
                        f"with old data (sign/delta 使用的摘要不一致)",
                        block_index=idx,
                    )
        out += chunk
    if len(out) != delta.new_length:
        raise ReplayError(
            "length",
            f"replayed {len(out)} byte(s) but DDLT new_length is {delta.new_length}",
        )
    # §5.2 content_digest：目标数据 SHA-256，写完后重算比对（兜住 LITERAL/长度字段被改坏）
    if delta.content_digest and delta.content_digest != bytes(32):
        got = sha256(bytes(out))
        if got != delta.content_digest:
            raise ReplayError(
                "digest-mismatch",
                f"重建结果 SHA-256 {got.hex()} != DDLT content_digest {delta.content_digest.hex()} "
                "(DigestMismatch)",
            )
    return bytes(out)


# ---------------------------------------------------------------------------
# §6.4 内容定义分块（gear hash）—— 参考实现，边界不与被测实现保证一致（歧义 A3）
# ---------------------------------------------------------------------------

_MIN_CHUNK = 2048
_AVG_CHUNK = 8192
_MAX_CHUNK = 32768


def _gear_table(seed: int = 0x5EED_1CE5) -> list[int]:
    """design.md 未规定 gear 表；这里用固定 LCG 生成，仅用于本参考实现自洽。"""
    table = []
    x = seed & 0xFFFFFFFFFFFFFFFF
    for _ in range(256):
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        table.append(x)
    return table


GEAR_TABLE = _gear_table()


def cdc_chunks(
    data: bytes,
    min_size: int = _MIN_CHUNK,
    avg_size: int = _AVG_CHUNK,
    max_size: int = _MAX_CHUNK,
    table: list[int] | None = None,
) -> list[bytes]:
    table = GEAR_TABLE if table is None else table
    mask_bits = avg_size.bit_length() - 1
    mask = (1 << mask_bits) - 1
    chunks = []
    start = 0
    h = 0
    for i, byte in enumerate(data):
        h = ((h << 1) + table[byte]) & 0xFFFFFFFFFFFFFFFF
        length = i + 1 - start
        if length >= max_size or (length >= min_size and (h & mask) == 0):
            chunks.append(data[start : i + 1])
            start = i + 1
            h = 0
    if start < len(data):
        chunks.append(data[start:])
    return chunks


def build_manifest(data: bytes, **kwargs) -> Manifest:
    chunks = cdc_chunks(data, **kwargs)
    refs = [ChunkRef(sha256(c), len(c)) for c in chunks]
    return Manifest(_AVG_CHUNK, refs, manifest_root(refs))
