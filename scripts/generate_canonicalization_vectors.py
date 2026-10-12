#!/usr/bin/env python3
"""Generate canonicalization-v1 JCS (RFC 8785) boundary vectors (CC0 public domain).

This sub-corpus pins down RFC 8785 (JCS) canonicalization at JSON numeric
boundaries. The primary case is the integer token ``-0`` as it arrives on
the wire. Each input document deliberately carries **two separate members**:

* a numeric member ``n`` (wire token ``-0`` or ``0``); and
* a string member ``s`` (wire token ``"-0"`` or ``"0"``), i.e. the *string
  form* of the signed digit.

The integer token ``-0`` and the string ``"-0"`` are carried as two separate
members to distinguish a numeric value from its string form; the numeric
member canonicalises to ``0`` while the string member is preserved verbatim::

    negzero  input.json (raw wire text)  ->  JCS canonical bytes       ->  sig
             {"n":-0,"s":"-0"}            ->  {"n":0,"s":"-0"}        ->  signature.sig (A)
    pluszero input.json (raw wire text)  ->  JCS canonical bytes       ->  sig
             {"n":0,"s":"0"}              ->  {"n":0,"s":"0"}         ->  signature.sig (B)

The two documents produce **two different canonical preimages**, because the
string member is preserved verbatim (``"-0"`` vs ``"0"``); consequently the
two ``signature.sig`` files are different bytes. (An earlier draft tried to
make the two cases converge on one preimage by carrying the string ``"0"``
in both documents; that design conflated a numeric value with its string form
and has been abandoned.)

Wrong preimages pinned as negative evidence:

* the **rejected literal** ``{"n":-0,"s":"-0"}`` — what a literal-preserving
  implementation would sign if it kept the integer ``-0`` token in its
  canonical form. Note this is byte-identical to the negzero *wire* text
  (without the trailing LF): such an implementation effectively signs the
  raw wire literal instead of the canonical bytes.
* two **numeric/string confusion** preimages:

  - ``{"n":0,"s":0}`` — the string member is coerced to a number (quotes
    dropped; a string value serialised as its numeric form);
  - ``{"n":"-0","s":-0}`` — the two members' value types are swapped.

A negative signature (``negative-signature.sig``) is published over the
rejected literal; the checker asserts the positive signature is INVALID over
the rejected literal and every confusion preimage, and that the negative
signature is VALID only over the rejected literal.

Design notes
------------
* The fixture stores the **original JSON text** in ``input.json``. The input
  is treated as raw wire bytes, never as a re-serialized Python object.
  CPython's own parser already normalizes integer ``-0`` to ``0``
  (``json.loads(b'{"n":-0,"s":"-0"}')["n"] == 0``) while leaving the string
  ``"-0"`` a distinct ``str``; feeding that parsed value to
  ``jcs.canonicalize`` yields the RFC 8785-conformant bytes. A
  literal-preserving implementation is exposed by the bidirectional
  signature evidence over exact preimage bytes.
* Signing key: the same deterministic public conformance key used by the
  rest of the repository (seed
  ``ccs-conformance-vectors/v1/independent-checker``). The seed is public
  corpus data, not a secret.
* The script is deterministic and idempotent: running it twice leaves the
  working tree unchanged. All hashes/signatures are computed, never
  hard-coded; the fixed boundary facts below are asserted against the real
  local ``jcs`` output.

Usage:
    python scripts/generate_canonicalization_vectors.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---------------------------------------------------------------------------
# Deterministic key (identical recipe to generate_vectors.py)
# ---------------------------------------------------------------------------
SEED = b"ccs-conformance-vectors/v1/independent-checker"
KEY_SEED = hashlib.sha256(SEED).digest()
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(KEY_SEED)
PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_RAW = PUBLIC_KEY.public_bytes(Encoding.Raw, PublicFormat.Raw)
PUBLIC_KEY_B64 = base64.b64encode(PUBLIC_KEY_RAW).decode("ascii")
PUBLIC_KEY_FINGERPRINT = hashlib.sha256(PUBLIC_KEY_RAW).hexdigest()[:16]

CORPUS_VERSION = "canonicalization-v1"
VECTORS_DIR = (
    Path(__file__).resolve().parent.parent / "vectors" / CORPUS_VERSION
)

# ---------------------------------------------------------------------------
# Fixed boundary facts (asserted against the local RFC 8785 implementation)
# ---------------------------------------------------------------------------
# Raw wire text (no trailing newline here; input.json on disk adds one LF).
# Integer token -0 (no decimal/exponent => not the IEEE-754 negative-zero
# float; a pure JSON integer literal with a leading minus). Each document
# carries TWO independent members:
#   "n" -> the numeric value (wire token -0 or 0; canonical token 0)
#   "s" -> the string form (wire token "-0" or "0"; preserved verbatim)
NEGZERO_RAW_TEXT = '{"n":-0,"s":"-0"}'
PLUSZERO_RAW_TEXT = '{"n":0,"s":"0"}'  # control; "+0" is not legal JSON

# RFC 8785 canonical serializations, as actually produced by jcs:
# keys in lexicographic order (n before s), negative zero emitted without a
# sign, the string kept verbatim with quotes.
NEGZERO_CANONICAL_TEXT = '{"n":0,"s":"-0"}'
NEGZERO_CANONICAL_HEX = "7b226e223a302c2273223a222d30227d"
PLUSZERO_CANONICAL_TEXT = '{"n":0,"s":"0"}'
PLUSZERO_CANONICAL_HEX = "7b226e223a302c2273223a2230227d"

# Wrong preimage A: an implementation that preserves the integer -0 literal.
# For negzero this is byte-identical to the raw wire text (without LF): the
# wrong implementation signs the wire literal as if it were canonical.
REJECTED_LITERAL_TEXT = '{"n":-0,"s":"-0"}'
REJECTED_LITERAL_HEX = "7b226e223a2d302c2273223a222d30227d"

# Wrong preimage B: string member coerced to a number (quotes dropped).
CONFUSION_STRING_AS_NUMBER_TEXT = '{"n":0,"s":0}'
CONFUSION_STRING_AS_NUMBER_HEX = "7b226e223a302c2273223a307d"

# Wrong preimage C: numeric/string value types swapped between the members.
CONFUSION_TYPES_SWAPPED_TEXT = '{"n":"-0","s":-0}'
CONFUSION_TYPES_SWAPPED_HEX = "7b226e223a222d30222c2273223a2d307d"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_hex(path.read_bytes())


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_text(path: Path, text: str) -> None:
    # Human-readable JSON text fixtures: UTF-8, no BOM, one trailing newline.
    write_bytes(path, text.encode("utf-8") + b"\n")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def jcs_canonical_of_raw_text(raw_text: str) -> bytes:
    """Return JCS canonical bytes for a raw JSON text fixture.

    The raw text is parsed here only to obtain a value for the local JCS
    library; CPython's parser already collapses integer ``-0`` to ``0``,
    which is exactly the RFC 8785-conformant result, while the string
    member (``"-0"``/``"0"``) survives as a distinct ``str``. The original
    literals are preserved on disk in input.json and pinned independently
    via the rejected-literal / confusion signature evidence.
    """
    return jcs.canonicalize(json.loads(raw_text))


def verify_sig(signature: bytes, message: bytes) -> bool:
    try:
        PUBLIC_KEY.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def assert_boundary_facts(
    neg_canonical: bytes, plus_canonical: bytes
) -> None:
    """Pin every boundary fact against the real jcs library output."""
    rejected = REJECTED_LITERAL_TEXT.encode("utf-8")
    confusion_a = CONFUSION_STRING_AS_NUMBER_TEXT.encode("utf-8")
    confusion_b = CONFUSION_TYPES_SWAPPED_TEXT.encode("utf-8")

    assert neg_canonical == NEGZERO_CANONICAL_TEXT.encode("utf-8"), neg_canonical
    assert neg_canonical.hex() == NEGZERO_CANONICAL_HEX, neg_canonical.hex()
    assert plus_canonical == PLUSZERO_CANONICAL_TEXT.encode("utf-8"), plus_canonical
    assert plus_canonical.hex() == PLUSZERO_CANONICAL_HEX, plus_canonical.hex()

    assert rejected.hex() == REJECTED_LITERAL_HEX, rejected.hex()
    assert confusion_a.hex() == CONFUSION_STRING_AS_NUMBER_HEX, confusion_a.hex()
    assert confusion_b.hex() == CONFUSION_TYPES_SWAPPED_HEX, confusion_b.hex()

    # All pinned preimages are pairwise distinct.
    preimages = [neg_canonical, plus_canonical, rejected, confusion_a, confusion_b]
    assert len({bytes(p) for p in preimages}) == 5, "preimages must be pairwise distinct"

    # CPython itself collapses the integer -0 token but preserves the string.
    parsed_neg = json.loads(NEGZERO_RAW_TEXT)
    assert isinstance(parsed_neg["n"], int) and not isinstance(parsed_neg["n"], bool)
    assert parsed_neg["n"] == 0
    assert parsed_neg["s"] == "-0" and isinstance(parsed_neg["s"], str)
    parsed_pos = json.loads(PLUSZERO_RAW_TEXT)
    assert isinstance(parsed_pos["n"], int) and parsed_pos["n"] == 0
    assert parsed_pos["s"] == "0" and isinstance(parsed_pos["s"], str)


def _members_block(*, numeric_wire_token: str, string_wire_token: str) -> dict[str, Any]:
    """Per-member wire token, JSON type, and expected canonical member."""
    return {
        "n": {
            "json_type": "number",
            "wire_token": numeric_wire_token,
            "expected_canonical_token": "0",
            "expected_canonical_member": '"n":0',
            "note": (
                "Numeric member. RFC 8785 serializes the number zero without "
                "a sign, so the canonical token is 0 with no leading minus "
                "(the integer -0 token canonicalises to 0)."
            ),
        },
        "s": {
            "json_type": "string",
            "wire_token": f'"{string_wire_token}"',
            "expected_canonical_token": f'"{string_wire_token}"',
            "expected_canonical_member": f'"s":"{string_wire_token}"',
            "note": (
                "String member carried as a separate member to distinguish a "
                "numeric value from its string form. RFC 8785 serializes JSON "
                "strings verbatim (with quotes, after the RFC 8785 string "
                "escaping rules); the content is never numerically normalized, "
                f'so "{string_wire_token}" stays a quoted string and must not '
                "become the number 0 or lose its minus sign."
            ),
        },
    }


def _rejected_block(file_ref: str) -> dict[str, Any]:
    return {
        "file": file_ref,
        "utf8": REJECTED_LITERAL_TEXT,
        "hex": REJECTED_LITERAL_HEX,
        "sha256": sha256_hex(REJECTED_LITERAL_TEXT.encode("utf-8")),
        "description": (
            "Preimage of a literal-preserving canonicalizer that keeps the "
            "integer -0 token instead of emitting 0. For the negzero case it "
            "is byte-identical to the raw wire text (input.json minus its "
            "trailing LF): the non-conformant implementation signs the wire "
            "literal as if it were the canonical form."
        ),
    }


def _confusion_entries() -> list[dict[str, Any]]:
    return [
        {
            "file": "confusion-string-as-number.json",
            "label": "string-member-coerced-to-number",
            "utf8": CONFUSION_STRING_AS_NUMBER_TEXT,
            "hex": CONFUSION_STRING_AS_NUMBER_HEX,
            "sha256": sha256_hex(CONFUSION_STRING_AS_NUMBER_TEXT.encode("utf-8")),
            "description": (
                "Preimage of a canonicalizer that treats the string member as "
                'a number: the quotes are dropped and "s" is serialised as 0. '
                "A numeric value is conflated with its string form."
            ),
        },
        {
            "file": "confusion-types-swapped.json",
            "label": "numeric-string-types-swapped",
            "utf8": CONFUSION_TYPES_SWAPPED_TEXT,
            "hex": CONFUSION_TYPES_SWAPPED_HEX,
            "sha256": sha256_hex(CONFUSION_TYPES_SWAPPED_TEXT.encode("utf-8")),
            "description": (
                "Preimage of a canonicalizer that swaps the value types of "
                'the two members: "n" carries the string "-0" and "s" carries '
                "the numeric -0 token."
            ),
        },
    ]


# ---------------------------------------------------------------------------
# Per-case generation
# ---------------------------------------------------------------------------

def _expected_common(
    *,
    case: str,
    feature: str,
    raw_text: str,
    canonical: bytes,
    signature: bytes,
) -> dict[str, Any]:
    return {
        "case": case,
        "feature": feature,
        "input_is_raw_json_text": True,
        "input_file": "input.json",
        "input_note": (
            "input.json stores the original wire JSON text as bytes "
            "(UTF-8, no BOM, single trailing LF). The trailing LF is not "
            "part of any signing preimage; only the canonical JSON bytes "
            "listed below are signed."
        ),
        "canonicalization": "JCS (RFC 8785)",
        "expected_canonical_utf8": canonical.decode("utf-8"),
        "expected_canonical_hex": canonical.hex(),
        "expected_canonical_sha256": sha256_hex(canonical),
        "signing_algorithm": "Ed25519",
        "signature_encoding": "raw 64-byte Ed25519 signature in signature.sig",
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "public_key_b64": PUBLIC_KEY_B64,
        "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
        "expect": "valid-for-rfc8785",
        "raw_input_sha256": sha256_hex(raw_text.encode("utf-8") + b"\n"),
    }


def _self_check_signature_matrix(
    *,
    canonical: bytes,
    signature: bytes,
    negative_signature: bytes | None,
) -> None:
    """Generator-side guarantee that the published signature evidence behaves."""
    rejected = REJECTED_LITERAL_TEXT.encode("utf-8")
    confusion_a = CONFUSION_STRING_AS_NUMBER_TEXT.encode("utf-8")
    confusion_b = CONFUSION_TYPES_SWAPPED_TEXT.encode("utf-8")

    assert verify_sig(signature, canonical)
    assert not verify_sig(signature, rejected)
    assert not verify_sig(signature, confusion_a)
    assert not verify_sig(signature, confusion_b)
    if negative_signature is not None:
        assert not verify_sig(negative_signature, canonical)
        assert not verify_sig(negative_signature, confusion_a)
        assert not verify_sig(negative_signature, confusion_b)
        assert verify_sig(negative_signature, rejected)


def gen_negzero(
    neg_canonical: bytes,
    plus_signature: bytes,
) -> bytes:
    """Generate the negzero case; returns its positive signature bytes."""
    case_dir = VECTORS_DIR / "negzero"

    raw_text = NEGZERO_RAW_TEXT
    canonical = neg_canonical
    rejected_literal = REJECTED_LITERAL_TEXT.encode("utf-8")
    confusion_a = CONFUSION_STRING_AS_NUMBER_TEXT.encode("utf-8")
    confusion_b = CONFUSION_TYPES_SWAPPED_TEXT.encode("utf-8")

    signature = PRIVATE_KEY.sign(canonical)
    negative_signature = PRIVATE_KEY.sign(rejected_literal)

    # The two cases must sign different preimages, hence different signatures.
    assert signature != plus_signature

    # Wire/preimage artifacts (no trailing newline on byte-preimage files).
    write_text(case_dir / "input.json", raw_text)
    write_bytes(case_dir / "canonical.jcs", canonical)
    write_bytes(case_dir / "rejected-literal.json", rejected_literal)
    write_bytes(case_dir / "confusion-string-as-number.json", confusion_a)
    write_bytes(case_dir / "confusion-types-swapped.json", confusion_b)
    write_bytes(case_dir / "signature.sig", signature)
    write_bytes(case_dir / "negative-signature.sig", negative_signature)

    _self_check_signature_matrix(
        canonical=canonical,
        signature=signature,
        negative_signature=negative_signature,
    )

    expected = _expected_common(
        case="negzero",
        feature="RFC8785 integer negative zero (-0 token on the wire) alongside its string form",
        raw_text=raw_text,
        canonical=canonical,
        signature=signature,
    )
    expected.update({
        "wire_literal": "-0",
        "members": _members_block(numeric_wire_token="-0", string_wire_token="-0"),
        "member_order_note": (
            "RFC 8785 serializes object members in lexicographic key order; "
            '"n" precedes "s".'
        ),
        "rejected_literal": _rejected_block("rejected-literal.json"),
        "confusions": _confusion_entries(),
        "negative_signature_encoding": (
            "raw 64-byte Ed25519 signature over the rejected literal bytes "
            "in negative-signature.sig"
        ),
        "negative_signature_b64": base64.b64encode(negative_signature).decode("ascii"),
        "distinct_from_case": {
            "case": "pluszero",
            "canonical_differs": True,
            "signature_differs": True,
            "note": (
                "pluszero signs {\"n\":0,\"s\":\"0\"}; its canonical preimage "
                "and signature.sig are different bytes from this case."
            ),
        },
        "conformance_rule": (
            "RFC 8785 serializes negative zero as '0', keeps JSON strings "
            "verbatim, and orders members lexicographically. A canonicalizer "
            "that preserves the integer '-0' literal and signs "
            '{"n":-0,"s":"-0"}, that coerces the string member to a number '
            'and signs {"n":0,"s":0}, or that swaps the member types and '
            'signs {"n":"-0","s":-0}, is non-conformant: signature.sig fails '
            "verification over every such preimage."
        ),
        "checker_assertions": [
            'raw wire text carries separate numeric member n (token -0) and string member s (token "-0")',
            'json.loads normalizes integer -0 to int 0 while leaving the string "-0" a str',
            f"JCS(input.json raw text) == expected_canonical_hex ({NEGZERO_CANONICAL_HEX})",
            'per-member canonical forms: "n":0 (number) and "s":"-0" (string, quoted verbatim)',
            "Ed25519 verify(pubkey, signature.sig, canonical) == VALID",
            f"Ed25519 verify(pubkey, signature.sig, rejected literal {REJECTED_LITERAL_TEXT}) == INVALID",
            f"Ed25519 verify(pubkey, signature.sig, confusion {CONFUSION_STRING_AS_NUMBER_TEXT}) == INVALID",
            f"Ed25519 verify(pubkey, signature.sig, confusion {CONFUSION_TYPES_SWAPPED_TEXT}) == INVALID",
            "Ed25519 verify(pubkey, negative-signature.sig, canonical) == INVALID",
            "Ed25519 verify(pubkey, negative-signature.sig, both confusion preimages) == INVALID",
            "Ed25519 verify(pubkey, negative-signature.sig, rejected literal) == VALID",
            "signature.sig differs from ../pluszero/signature.sig (different canonical preimages)",
        ],
    })
    write_json(case_dir / "expected.json", expected)

    readme = """# negzero — RFC 8785 integer negative zero (numeric + string members)

## What this case pins

The wire JSON text in `input.json` is exactly (UTF-8, no BOM, single LF):

```
{NRAW}
```

It carries **two separate members**:

| Key | JSON type | Wire token | Expected canonical member |
| --- | --- | --- | --- |
| `n` | number | integer `-0` (no decimal/exponent; not the IEEE-754 negative-zero float) | `"n":0` |
| `s` | string | `"-0"` (the string form of the signed digit) | `"s":"-0"` |

The integer token `-0` and the string `"-0"` are carried as two separate
members to distinguish a numeric value from its string form: the next
conflation after the `-0`/`0` one sits between a numeric value and its string
form. Under RFC 8785 (JCS) the numeric member canonicalises to `0` while the
string member is preserved verbatim with its quotes; object members are
serialized in lexicographic key order (`n` before `s`). The canonical form is
therefore:

```
{NCAN}
```

| Item | Value |
| --- | --- |
| Input (raw JSON text, on disk plus one LF) | `{NRAW}` |
| Expected canonical UTF-8 | `{NCAN}` |
| Expected canonical hex | `{NCANH}` |
| Expected canonical SHA-256 | `{CANON_SHA}` |
| Rejected literal UTF-8 | `{REJ}` |
| Rejected literal hex | `{REJH}` |
| Rejected literal SHA-256 | `{REJ_SHA}` |
| Confusion A (string coerced to number) | `{CA}` |
| Confusion A hex | `{CAH}` |
| Confusion A SHA-256 | `{CA_SHA}` |
| Confusion B (member types swapped) | `{CB}` |
| Confusion B hex | `{CBH}` |
| Confusion B SHA-256 | `{CB_SHA}` |
| Signing algorithm | Ed25519 over the canonical bytes |
| Public key (base64) | `{PUB_B64}` |
| Public key fingerprint | `{PUB_FPR}` |

## Why the input is raw JSON text

The fixture deliberately preserves the original wire bytes in `input.json`.
CPython's own JSON parser already normalizes the integer `-0` token to `0`
(`json.loads` yields `{{"n": 0, "s": "-0"}}`; the string survives as a
distinct `str`), so parsing the text into a host object and re-serializing it
erases the numeric literal before canonicalization can be observed. That is
the *correct* outcome, but it means the divergence between conformant and
literal-preserving implementations cannot be shown with parsed values alone.
The discriminator is signature evidence over the exact preimage bytes:

* `signature.sig` — Ed25519 signature over the canonical bytes `{NCAN}`
  (hex `{NCANH}`).
* `negative-signature.sig` — Ed25519 signature over the rejected literal
  bytes `{REJ}` (hex `{REJH}`). The rejected literal is byte-identical to
  the raw wire text without its trailing LF: a literal-preserving
  implementation effectively signs the wire literal instead of the
  canonical form.
* `confusion-string-as-number.json` — `{CA}`: the string member coerced to a
  number.
* `confusion-types-swapped.json` — `{CB}`: numeric/string value types
  swapped between the two members.

## Pass/fail semantics

An implementation is **valid-for-rfc8785** for this case only if:

1. It canonicalizes the raw input text to `{NCAN}` — numeric member `n`
   emitted as `0`, string member `s` emitted verbatim as `"-0"`, members
   ordered `n` then `s` — and hashes/signs those bytes;
2. `signature.sig` verifies against the public key over the canonical bytes;
3. `signature.sig` **fails** verification over `{REJ}` — an implementation
   that preserves the `-0` literal in its signing preimage cannot verify the
   correct signature and must be rejected;
4. `signature.sig` **fails** over both confusion preimages (`{CA}` and
   `{CB}`) — an implementation that coerces the string member to a number or
   swaps the numeric/string member types must likewise be rejected;
5. `negative-signature.sig` **fails** over the canonical bytes and over both
   confusion preimages, and verifies only over the rejected literal bytes;
6. this `signature.sig` is **different** from `../pluszero/signature.sig`,
   because the two cases sign different canonical preimages
   (`"-0"` vs `"0"` in the string member).

## Reproducing

```sh
python scripts/generate_canonicalization_vectors.py
python checkers/independent_checker.py vectors/canonicalization-v1/
```
""".format(
        NRAW=NEGZERO_RAW_TEXT,
        NCAN=NEGZERO_CANONICAL_TEXT,
        NCANH=NEGZERO_CANONICAL_HEX,
        REJ=REJECTED_LITERAL_TEXT,
        REJH=REJECTED_LITERAL_HEX,
        CA=CONFUSION_STRING_AS_NUMBER_TEXT,
        CAH=CONFUSION_STRING_AS_NUMBER_HEX,
        CB=CONFUSION_TYPES_SWAPPED_TEXT,
        CBH=CONFUSION_TYPES_SWAPPED_HEX,
        CANON_SHA=sha256_hex(neg_canonical),
        REJ_SHA=sha256_hex(rejected_literal),
        CA_SHA=sha256_hex(confusion_a),
        CB_SHA=sha256_hex(confusion_b),
        PUB_B64=PUBLIC_KEY_B64,
        PUB_FPR=PUBLIC_KEY_FINGERPRINT,
    )
    write_text(case_dir / "README.md", readme)
    return signature


def gen_pluszero(
    plus_canonical: bytes,
    neg_signature: bytes,
) -> bytes:
    """Generate the pluszero control case; returns its positive signature."""
    case_dir = VECTORS_DIR / "pluszero"

    raw_text = PLUSZERO_RAW_TEXT
    canonical = plus_canonical
    confusion_a = CONFUSION_STRING_AS_NUMBER_TEXT.encode("utf-8")

    signature = PRIVATE_KEY.sign(canonical)
    assert signature != neg_signature

    write_text(case_dir / "input.json", raw_text)
    write_bytes(case_dir / "canonical.jcs", canonical)
    write_bytes(case_dir / "confusion-string-as-number.json", confusion_a)
    write_bytes(case_dir / "signature.sig", signature)

    _self_check_signature_matrix(
        canonical=canonical,
        signature=signature,
        negative_signature=None,
    )

    expected = _expected_common(
        case="pluszero",
        feature=(
            "RFC8785 plain zero baseline alongside the string form, control "
            "for the negzero case (distinct canonical preimage)"
        ),
        raw_text=raw_text,
        canonical=canonical,
        signature=signature,
    )
    # The control case carries only the string-as-number confusion file of
    # its own; the swapped-types confusion and the rejected literal live in
    # ../negzero/ and are cross-checked by the checker.
    own_confusion = _confusion_entries()[0]
    expected.update({
        "members": _members_block(numeric_wire_token="0", string_wire_token="0"),
        "member_order_note": (
            "RFC 8785 serializes object members in lexicographic key order; "
            '"n" precedes "s".'
        ),
        "rejected_literal": _rejected_block("../negzero/rejected-literal.json"),
        "confusions": [own_confusion],
        "sibling_confusions_dir": "../negzero/",
        "sibling_confusions": [
            "confusion-string-as-number.json",
            "confusion-types-swapped.json",
        ],
        "distinct_from_case": {
            "case": "negzero",
            "canonical_differs": True,
            "signature_differs": True,
            "note": (
                "negzero signs {\"n\":0,\"s\":\"-0\"}; its canonical preimage "
                "and signature.sig are different bytes from this case."
            ),
        },
        "note": (
            "Control case. A leading plus sign ('+0') is not a legal JSON "
            "number token (RFC 8259 grammar), so no +0 input fixture is "
            "provided. The plain integer 0 / string \"0\" document has its "
            "own canonical preimage and its own signature.sig, which differ "
            "from the negzero case because the string member is preserved "
            'verbatim ("0" vs "-0"). The rejected-literal and '
            "types-swapped-confusion bytes live in ../negzero/ and are "
            "cross-pinned here by hex."
        ),
        "checker_assertions": [
            'raw wire text carries separate numeric member n (token 0) and string member s (token "0")',
            f"JCS(input.json raw text) == expected_canonical_hex ({PLUSZERO_CANONICAL_HEX})",
            'per-member canonical forms: "n":0 (number) and "s":"0" (string, quoted verbatim)',
            "Ed25519 verify(pubkey, signature.sig, canonical) == VALID",
            f"Ed25519 verify(pubkey, signature.sig, rejected literal {REJECTED_LITERAL_TEXT}) == INVALID",
            f"Ed25519 verify(pubkey, signature.sig, confusion {CONFUSION_STRING_AS_NUMBER_TEXT}) == INVALID",
            "Ed25519 verify(pubkey, signature.sig, ../negzero confusion types-swapped) == INVALID",
            "signature.sig differs from ../negzero/signature.sig (different canonical preimages)",
        ],
    })
    write_json(case_dir / "expected.json", expected)

    readme = """# pluszero — plain zero baseline (numeric + string members)

`input.json` is the raw JSON text `{PRAW}` (UTF-8, no BOM, single LF),
carrying the same two separate members as `negzero/`: numeric member `n`
(wire token `0`) and string member `s` (wire token `"0"`). It canonicalizes
under RFC 8785 (JCS) to:

| Item | Value |
| --- | --- |
| Input (raw JSON text, on disk plus one LF) | `{PRAW}` |
| Expected canonical UTF-8 | `{PCAN}` |
| Expected canonical hex | `{PCANH}` |
| Expected canonical SHA-256 | `{PCAN_SHA}` |
| Numeric member canonical form | `"n":0` |
| String member canonical form | `"s":"0"` (quoted; verbatim) |
| Own confusion (string coerced to number) | `{CA}` |
| Rejected literal (pinned in `../negzero/`) | `{REJ}` |
| Types-swapped confusion (pinned in `../negzero/`) | `{CB}` |
| Signing algorithm | Ed25519 over the canonical bytes |
| Public key (base64) | `{PUB_B64}` |
| Public key fingerprint | `{PUB_FPR}` |

This control case demonstrates the ordinary zero/`"0"` baseline. Its
canonical preimage `{PCAN}` is **different** from the negzero preimage
`{NCAN}` (the string member is preserved verbatim, so `"0"` and `"-0"` do
not converge), and therefore `signature.sig` here is a different signature
from `../negzero/signature.sig`. The checker also proves this control
signature is INVALID over the rejected literal `{REJ}`, over its own
string-as-number confusion `{CA}`, and over the negzero types-swapped
confusion `{CB}` (files pinned under `../negzero/`).

No `+0` fixture is included: a leading plus sign is not permitted in the
RFC 8259 JSON number grammar, so `{{"n":+0}}` is not parseable JSON and
cannot serve as a conformance input.

## Reproducing

```sh
python scripts/generate_canonicalization_vectors.py
python checkers/independent_checker.py vectors/canonicalization-v1/
```
""".format(
        PRAW=PLUSZERO_RAW_TEXT,
        PCAN=PLUSZERO_CANONICAL_TEXT,
        PCANH=PLUSZERO_CANONICAL_HEX,
        PCAN_SHA=sha256_hex(plus_canonical),
        REJ=REJECTED_LITERAL_TEXT,
        CA=CONFUSION_STRING_AS_NUMBER_TEXT,
        CB=CONFUSION_TYPES_SWAPPED_TEXT,
        NCAN=NEGZERO_CANONICAL_TEXT,
        PUB_B64=PUBLIC_KEY_B64,
        PUB_FPR=PUBLIC_KEY_FINGERPRINT,
    )
    write_text(case_dir / "README.md", readme)
    return signature


# ---------------------------------------------------------------------------
# Corpus README + manifest
# ---------------------------------------------------------------------------

def gen_corpus_readme() -> None:
    readme = """# canonicalization-v1 — JCS (RFC 8785) numeric boundary vectors

This sub-corpus pins down [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
(JSON Canonicalization Scheme, JCS) canonicalization behavior at JSON
numeric boundary conditions. It is independent of the signed-receipt
corpus in `../v1.4.0-conformance/` and has its own `manifest.json`; nothing
under that directory is touched or re-pinned here.

The case set:

| Case | Raw wire input | Expected canonical | Boundary |
| --- | --- | --- | --- |
| `negzero/` | `@NEG_RAW@` | `@NEG_CAN@` | integer token `-0` is serialized as `0`; string `"-0"` preserved verbatim |
| `pluszero/` | `@PLUS_RAW@` | `@PLUS_CAN@` | baseline: plain `0` / `"0"`; distinct preimage from negzero |

## Separate numeric and string members

Every input document carries two **independent members**: a numeric member
`n` and a string member `s` carrying the string form of the signed digit.
The integer token `-0` and the string `"-0"` are carried as two separate
members to distinguish a numeric value from its string form — the next
conflation after the `-0`/`0` one sits between a numeric value and its
string form. Under RFC 8785 the numeric member canonicalises to `0` while
JSON strings are serialized verbatim and are not numerically normalized,
so the two cases produce two **different** canonical preimages
(`@NEG_CAN@` vs `@PLUS_CAN@`) and two different signatures.

Each case's `expected.json` states the expected canonical form **per
member** (`"n":0` vs `"s":"-0"`/`"s":"0"`, the string shown with its
quotes) and at the whole-document level (UTF-8, hex, and SHA-256), so a
failing implementation can see exactly what it should have produced.

## Pinned wrong preimages

Two classes of non-conformant implementation are pinned with exact bytes:

* **rejected literal** `@REJ@` (hex `@REJH@`, file under `negzero/`) —
  the preimage of a canonicalizer that preserves the integer `-0` token.
  For the negzero case these bytes are identical to the raw wire text
  without its trailing LF, i.e. the non-conformant implementation signs
  the wire literal as if it were canonical;
* **numeric/string confusion**:
  `@CA@` (hex `@CAH@`) — the string member coerced to a number, shipped
  for both cases as `confusion-string-as-number.json`; and
  `@CB@` (hex `@CBH@`, under `negzero/`) — the numeric/string value
  types swapped between the members.

Signature evidence is bidirectional for negzero:

* `negzero/signature.sig` is VALID only over `@NEG_CAN@` and INVALID over
  the rejected literal and every confusion preimage;
* `negzero/negative-signature.sig` is VALID only over the rejected literal
  and INVALID over the canonical bytes and every confusion preimage;
* `pluszero/signature.sig` is VALID only over `@PLUS_CAN@`, INVALID over
  the rejected literal and all confusion preimages, and is a different
  signature from the negzero one (different preimages).

## Inputs are raw JSON text

Each case keeps the **original wire JSON text** in `input.json` (UTF-8, no
BOM, single trailing LF). The signed preimage is the canonical JSON bytes
listed in `expected.json`; the trailing LF in the on-disk input is never
part of a signing preimage.

This matters because host parsers may normalize numeric tokens before an
application-level canonicalizer ever sees them — CPython, for example,
parses the integer `-0` token to `0` while leaving the string `"-0"`
untouched. The fixtures therefore (1) freeze the wire text on disk and (2)
provide signature evidence that proves, against the public key alone,
whether an implementation built its preimage from the canonical bytes, from
the rejected literal, or from a numeric/string-conflated document.

## Signing material

* Algorithm: Ed25519 over the JCS canonical bytes.
* Deterministic public conformance key (same recipe as the rest of the
  repository):

  ```
  seed      = SHA-256(b"ccs-conformance-vectors/v1/independent-checker")
  public key (base64) = @PUB_B64@
  fingerprint         = @PUB_FPR@
  ```

  The seed is public corpus data for reproducibility, not a secret.
* `signature.sig` holds the raw 64-byte Ed25519 signature; base64 of the
  same bytes is recorded in `expected.json` as `signature_b64`.
* `negzero/negative-signature.sig` signs the rejected literal bytes
  `@REJ@` and exists solely to demonstrate the preimage divergence.
* The two cases sign different canonical preimages, so their
  `signature.sig` files are different bytes.

## Conformance semantics

* `expect: valid-for-rfc8785` means the raw input must canonicalize to the
  pinned canonical bytes and the positive signature must verify over them.
* An implementation that preserves the integer `-0` literal and constructs
  `@REJ@` as its signing preimage is **non-conformant**: `signature.sig`
  fails verification over that preimage. Conversely `negative-signature.sig`
  fails over the correct canonical bytes and verifies only over the
  rejected literal.
* An implementation that conflates the numeric value with its string form
  (coercing the string member to a number or swapping the member types) is
  likewise **non-conformant**: `signature.sig` fails over each confusion
  preimage.

## Reproducing

```sh
# Regenerate every file (deterministic; idempotent)
python scripts/generate_canonicalization_vectors.py

# Independently verify
python checkers/independent_checker.py vectors/canonicalization-v1/
```

All data in this directory is CC0 1.0 Universal (public domain).
"""
    replacements = {
        "@NEG_RAW@": NEGZERO_RAW_TEXT,
        "@NEG_CAN@": NEGZERO_CANONICAL_TEXT,
        "@PLUS_RAW@": PLUSZERO_RAW_TEXT,
        "@PLUS_CAN@": PLUSZERO_CANONICAL_TEXT,
        "@REJ@": REJECTED_LITERAL_TEXT,
        "@REJH@": REJECTED_LITERAL_HEX,
        "@CA@": CONFUSION_STRING_AS_NUMBER_TEXT,
        "@CAH@": CONFUSION_STRING_AS_NUMBER_HEX,
        "@CB@": CONFUSION_TYPES_SWAPPED_TEXT,
        "@CBH@": CONFUSION_TYPES_SWAPPED_HEX,
        "@PUB_B64@": PUBLIC_KEY_B64,
        "@PUB_FPR@": PUBLIC_KEY_FINGERPRINT,
    }
    for token, value in replacements.items():
        readme = readme.replace(token, value)
    write_text(VECTORS_DIR / "README.md", readme)


def gen_manifest() -> None:
    files: dict[str, str] = {}
    for root, dirs, fnames in os.walk(VECTORS_DIR):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in sorted(fnames):
            if fname == "manifest.json":
                continue
            fpath = Path(root) / fname
            rel = fpath.relative_to(VECTORS_DIR).as_posix()
            files[rel] = sha256_file(fpath)

    manifest = {
        "version": CORPUS_VERSION,
        "generated_by": "scripts/generate_canonicalization_vectors.py",
        "canonicalization": "JCS (RFC 8785)",
        "hash_algorithm": "sha256",
        "seed": SEED.decode(),
        "public_key_b64": PUBLIC_KEY_B64,
        "public_key_fingerprint": PUBLIC_KEY_FINGERPRINT,
        "signing_algorithm": "Ed25519",
        "signature_encoding": "raw 64-byte Ed25519 in signature.sig files",
        "determinism": (
            "All inputs, canonical bytes, signatures and pins are produced "
            "deterministically; re-running the generator yields identical "
            "file bytes."
        ),
        "files": dict(sorted(files.items())),
    }
    write_json(VECTORS_DIR / "manifest.json", manifest)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)

    neg_canonical = jcs_canonical_of_raw_text(NEGZERO_RAW_TEXT)
    plus_canonical = jcs_canonical_of_raw_text(PLUSZERO_RAW_TEXT)
    assert_boundary_facts(neg_canonical, plus_canonical)

    # Sign both preimages first so each generator can assert the signatures
    # are different as a built-in self-check.
    neg_signature = PRIVATE_KEY.sign(neg_canonical)
    plus_signature = PRIVATE_KEY.sign(plus_canonical)

    gen_negzero(neg_canonical, plus_signature)
    gen_pluszero(plus_canonical, neg_signature)
    gen_corpus_readme()
    gen_manifest()
    print(f"Generated {CORPUS_VERSION} vectors in {VECTORS_DIR}")


if __name__ == "__main__":
    main()
