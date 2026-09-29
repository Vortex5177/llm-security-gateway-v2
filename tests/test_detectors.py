"""检测器正反例：regex / id_card（校验位）/ bank_card（Luhn）/ invisible_text。"""

from __future__ import annotations

from app.security.detectors import (
    BankCardDetector,
    IdCardDetector,
    InvisibleTextDetector,
    RegexDetector,
    build_detector,
)

# 已知通过校验位的测试号码（非真实个人信息）
VALID_ID = "11010519491231002X"
INVALID_ID = "110105194912310021"  # 校验位错误
VALID_CARD = "4532015112830366"  # Luhn 通过
INVALID_CARD = "4532015112830367"  # Luhn 不通过
VALID_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def _hits(detector, text) -> list[str]:
    return [m.text for m in detector.find(text)]


def test_regex_detector_basic():
    d = RegexDetector(r"1[3-9]\d{9}")
    assert _hits(d, "电话13812345678，备用13900001111") == ["13812345678", "13900001111"]
    assert _hits(d, "没有任何号码 12345") == []


def test_id_card_checksum_required():
    d = IdCardDetector()
    assert _hits(d, f"身份证 {VALID_ID} 有效") == [VALID_ID]
    assert _hits(d, f"身份证 {INVALID_ID} 校验位错") == []
    # 17 位（缺一位）不报
    assert _hits(d, VALID_ID[:-1]) == []


def test_bank_card_luhn_required():
    d = BankCardDetector()
    assert _hits(d, f"卡号 {VALID_CARD}") == [VALID_CARD]
    assert _hits(d, f"卡号 {INVALID_CARD}") == []
    # 12 位以下不报
    assert _hits(d, "123456789012") == []


def test_invisible_text_zero_width_and_tags():
    d = InvisibleTextDetector()
    hits = _hits(d, "hello​world")
    assert hits == ["​"]
    # Tags 区块（ASCII smuggling）
    hits = _hits(d, "abc\U000e0001\U000e0045def")
    assert hits == ["\U000e0001\U000e0045"]
    # 普通文本不误报（空格/换行不是 Cf）
    assert _hits(d, "normal text 普通文本\t\n") == []


def test_build_detector_dispatch():
    assert build_detector("regex", "x").__class__.__name__ == "RegexDetector"
    assert build_detector("id_card", None).__class__.__name__ == "IdCardDetector"
    assert build_detector("bank_card", None).__class__.__name__ == "BankCardDetector"
    assert build_detector("invisible_text", None).__class__.__name__ == "InvisibleTextDetector"


def test_build_detector_rejects_unknown_and_missing_pattern():
    import pytest

    with pytest.raises(ValueError, match="pattern"):
        build_detector("regex", None)
    with pytest.raises(ValueError, match="未知检测器"):
        build_detector("nope", None)


def test_jwt_pattern_from_default_ruleset():
    d = RegexDetector(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
    assert _hits(d, f"token: {VALID_JWT}") == [VALID_JWT]
    assert _hits(d, "eyJshort.eyJshort.tooshort") == []
