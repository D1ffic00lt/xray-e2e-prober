"""A deliberately small, linear-time regex subset for assignment names.

Assignment filters are evaluated while inventory is compiled, often on the
event-loop thread.  Python's backtracking regex engine is therefore only used
after this module has excluded repetition and nested branching constructs.
Accepted expressions consist of flat alternatives made from literals, dots,
character classes, boundary anchors and single-character escapes.  A single
outer group and a leading ``(?i)`` flag are supported for readability.
"""

from __future__ import annotations

import re
from functools import lru_cache


MAX_SAFE_NAME_REGEX_LENGTH = 256
MAX_SAFE_NAME_REGEX_ALTERNATIVES = 32

_SINGLE_CHARACTER_ESCAPES = frozenset("AbBdDsSwWZfnrtv")
_REPETITION_OR_GROUP_META = frozenset("*+?{}()")


class UnsafeNameRegexError(ValueError):
    """Raised when an assignment regex falls outside the safe subset."""


def _is_escaped(value: str, index: int) -> bool:
    backslashes = 0
    index -= 1
    while index >= 0 and value[index] == "\\":
        backslashes += 1
        index -= 1
    return backslashes % 2 == 1


def _consume_escape(pattern: str, index: int) -> int:
    if index + 1 >= len(pattern):
        raise UnsafeNameRegexError("assignment name_regex has a trailing escape")
    escaped = pattern[index + 1]
    if escaped.isdigit():
        raise UnsafeNameRegexError("assignment name_regex backreferences are not supported")
    if escaped.isalpha() and escaped not in _SINGLE_CHARACTER_ESCAPES:
        raise UnsafeNameRegexError(
            "assignment name_regex uses an unsupported escape sequence"
        )
    return index + 2


def _consume_character_class(pattern: str, index: int) -> int:
    cursor = index + 1
    if cursor < len(pattern) and pattern[cursor] == "^":
        cursor += 1
    # A closing bracket is literal when it is the first class character.
    if cursor < len(pattern) and pattern[cursor] == "]":
        cursor += 1
    while cursor < len(pattern):
        character = pattern[cursor]
        if character == "\\":
            cursor = _consume_escape(pattern, cursor)
            continue
        if character == "[":
            raise UnsafeNameRegexError(
                "assignment name_regex nested character classes are not supported"
            )
        if character == "]":
            return cursor + 1
        cursor += 1
    raise UnsafeNameRegexError("assignment name_regex has an unterminated character class")


def _validate_flat_alternatives(expression: str) -> None:
    branch_start = 0
    alternatives = 1
    cursor = 0
    while cursor < len(expression):
        character = expression[cursor]
        if character == "\\":
            cursor = _consume_escape(expression, cursor)
            continue
        if character == "[":
            cursor = _consume_character_class(expression, cursor)
            continue
        if character == "]":
            raise UnsafeNameRegexError(
                "assignment name_regex has an unexpected closing bracket"
            )
        if character == "|":
            alternatives += 1
            if alternatives > MAX_SAFE_NAME_REGEX_ALTERNATIVES:
                raise UnsafeNameRegexError(
                    "assignment name_regex has too many alternatives"
                )
            branch_start = cursor + 1
            cursor += 1
            continue
        if character in _REPETITION_OR_GROUP_META:
            raise UnsafeNameRegexError(
                "assignment name_regex repetition and nested groups are not supported"
            )
        if character == "^" and cursor != branch_start:
            raise UnsafeNameRegexError(
                "assignment name_regex ^ anchors are only supported at branch starts"
            )
        if character == "$" and cursor + 1 < len(expression) and expression[cursor + 1] != "|":
            raise UnsafeNameRegexError(
                "assignment name_regex $ anchors are only supported at branch ends"
            )
        cursor += 1


def validate_safe_name_regex(pattern: str) -> str:
    """Validate and return a bounded expression from the safe name subset."""

    if len(pattern) > MAX_SAFE_NAME_REGEX_LENGTH:
        raise UnsafeNameRegexError(
            f"assignment name_regex exceeds {MAX_SAFE_NAME_REGEX_LENGTH} characters"
        )

    expression = pattern
    if expression.startswith("(?i)"):
        expression = expression[4:]

    # Permit anchors around the optional outer group, e.g. ``^(foo|bar)$``.
    if expression.startswith("^"):
        expression = expression[1:]
    if expression.endswith("$") and not _is_escaped(expression, len(expression) - 1):
        expression = expression[:-1]

    if expression.startswith("(?:") and expression.endswith(")"):
        expression = expression[3:-1]
    elif expression.startswith("(") and expression.endswith(")"):
        expression = expression[1:-1]

    _validate_flat_alternatives(expression)
    try:
        re.compile(pattern)
    except re.error as exc:
        raise UnsafeNameRegexError("invalid assignment name regular expression") from exc
    return pattern


@lru_cache(maxsize=256)
def compile_safe_name_regex(pattern: str) -> re.Pattern[str]:
    """Compile a validated safe name expression and cache boundedly."""

    return re.compile(validate_safe_name_regex(pattern))


def safe_name_regex_search(pattern: str, value: str) -> bool:
    """Search ``value`` with a validated expression from the safe subset."""

    return compile_safe_name_regex(pattern).search(value) is not None


__all__ = [
    "MAX_SAFE_NAME_REGEX_ALTERNATIVES",
    "MAX_SAFE_NAME_REGEX_LENGTH",
    "UnsafeNameRegexError",
    "compile_safe_name_regex",
    "safe_name_regex_search",
    "validate_safe_name_regex",
]
