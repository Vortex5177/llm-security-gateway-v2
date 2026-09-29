"""检测器：规则引用的底层匹配实现（同步、确定性、零外部依赖）。

每个检测器实现 `find(text) -> list[RawMatch]`：
- regex：YAML 提供 pattern；
- id_card：18 位身份证 + GB 11643 校验位（排除"格式对但号码假"的误报）；
- bank_card：13-19 位数字 + Luhn 校验；
- invisible_text：Unicode Cf 类隐藏字符（零宽等）与 Tags 区块（U+E0000–E007F，
  已知 ASCII smuggling 注入手法）。
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Protocol


@dataclass
class RawMatch:
    span: tuple[int, int]
    text: str


class Detector(Protocol):
    def find(self, text: str) -> list[RawMatch]: ...


class RegexDetector:
    def __init__(self, pattern: str) -> None:
        self._regex = re.compile(pattern)

    def find(self, text: str) -> list[RawMatch]:
        return [RawMatch(m.span(), m.group(0)) for m in self._regex.finditer(text)]


_ID_CARD_RE = re.compile(r"\d{6}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]")
_ID_CARD_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CARD_CHECK = "10X98765432"


def _id_card_valid(number: str) -> bool:
    if len(number) != 18:
        return False
    total = sum(int(number[i]) * _ID_CARD_WEIGHTS[i] for i in range(17))
    return _ID_CARD_CHECK[total % 11] == number[17].upper()


class IdCardDetector:
    def find(self, text: str) -> list[RawMatch]:
        return [
            RawMatch(m.span(), m.group(0))
            for m in _ID_CARD_RE.finditer(text)
            if _id_card_valid(m.group(0))
        ]


_BANK_CARD_RE = re.compile(r"\d{13,19}")


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class BankCardDetector:
    def find(self, text: str) -> list[RawMatch]:
        return [
            RawMatch(m.span(), m.group(0))
            for m in _BANK_CARD_RE.finditer(text)
            if _luhn_valid(m.group(0))
        ]


_EXTRA_INVISIBLE = {
    0xFFFC,  # OBJECT REPLACEMENT CHARACTER（常用于隐藏载荷）
    0x034F,  # COMBINING GRAPHEME JOINER（Mn 类，零宽混淆）
}


def _is_invisible(ch: str) -> bool:
    cp = ord(ch)
    if 0xE0000 <= cp <= 0xE007F or cp in _EXTRA_INVISIBLE:
        return True
    return unicodedata.category(ch) == "Cf"


class InvisibleTextDetector:
    """连续隐藏字符归为一次命中（span 覆盖整个隐藏串）。"""

    def find(self, text: str) -> list[RawMatch]:
        matches: list[RawMatch] = []
        start: int | None = None
        for i, ch in enumerate(text):
            if _is_invisible(ch):
                if start is None:
                    start = i
            elif start is not None:
                matches.append(RawMatch((start, i), text[start:i]))
                start = None
        if start is not None:
            matches.append(RawMatch((start, len(text)), text[start:]))
        return matches


def build_detector(kind: str, pattern: str | None) -> Detector:
    if kind == "regex":
        if not pattern:
            raise ValueError("regex 检测器需要 pattern")
        return RegexDetector(pattern)
    if kind == "id_card":
        return IdCardDetector()
    if kind == "bank_card":
        return BankCardDetector()
    if kind == "invisible_text":
        return InvisibleTextDetector()
    raise ValueError(f"未知检测器类型: {kind}")
