#!/usr/bin/env python3
import argparse
import sys
import unicodedata
import re
from collections import Counter

# Common “invisible/blank” confusables used in steganography
DEFAULT_CANDIDATES = [
    "\u3164",  # Hangul Filler
    "\uFFA0",  # Halfwidth Hangul Filler
    "\u200B",  # Zero Width Space
    "\u200C",  # Zero Width Non-Joiner
    "\u200D",  # Zero Width Joiner
    "\u2060",  # Word Joiner
    "\u00A0",  # No-Break Space
    "\u3000",  # Ideographic Space
]

SUSPICIOUS_PATTERNS = [
    r"\beval\s*\(",
    r"\bFunction\s*\(",
    r"\brequire\s*\(\s*['\"]child_process['\"]\s*\)",
    r"\bexec\s*\(",
    r"\bnc\b.*\b-e\b",
    r"\bbtoa\s*\(",
    r"\batob\s*\(",
]


def normalize_text(text: str) -> str:
    # Normalize for consistent code point treatment
    return unicodedata.normalize("NFKC", text)


def read_input(path: str | None) -> str:
    if path and path != "-":
        return open(path, "r", encoding="utf-8", errors="replace").read()
    return sys.stdin.read()


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for ch in s if (32 <= ord(ch) <= 126) or ch in "\t\n\r")
    return printable / len(s)


def entropy_estimate(s: str) -> float:
    # Simple Shannon entropy estimate
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    import math

    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def suspicious_score(s: str) -> int:
    score = 0
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, s):
            score += 1
    return score


def to_bits(text: str, one: str, zero: str) -> str:
    filtered = [ch for ch in text if ch in (one, zero)]
    return "".join("1" if ch == one else "0" for ch in filtered)


def decode_bits(bits: str, reverse_bits: bool) -> str:
    out_chars = []
    for i in range(0, len(bits), 8):
        b = bits[i : i + 8]
        if len(b) != 8:
            continue
        if reverse_bits:
            b = b[::-1]
        try:
            out_chars.append(chr(int(b, 2)))
        except ValueError:
            # Skip invalid chunks
            continue
    return "".join(out_chars)


def pick_two_symbols(text: str, allowlist: list[str]) -> list[tuple[str, str]]:
    # Count candidates; return likely pairs by frequency
    counts = Counter(ch for ch in text if ch in allowlist)
    chars = [ch for ch, _ in counts.most_common()]
    pairs = []
    # Generate pairs from top-N to reduce combinatorics
    N = min(6, len(chars))
    for i in range(N):
        for j in range(i + 1, N):
            pairs.append((chars[i], chars[j]))
    return pairs


def score_candidate(s: str) -> tuple:
    # Higher printable ratio, some suspicious markers, mid entropy
    return (
        printable_ratio(s),
        suspicious_score(s),
        -abs(entropy_estimate(s) - 4.0),  # prefer mid entropy
        len(s),
    )


def decode_payload(text: str, allowlist: list[str], verbose: bool):
    # Choose pairs; try mappings and bit orientations
    pairs = pick_two_symbols(text, allowlist)
    if not pairs:
        return []

    candidates = []
    for zero, one in pairs:
        for mapping in [(one, zero), (zero, one)]:  # which char is 1 vs 0
            bits = to_bits(text, *mapping)
            for reverse in [False, True]:
                decoded = decode_bits(bits, reverse_bits=reverse)
                score = score_candidate(decoded)
                meta = {
                    "one": repr(mapping[0]),
                    "zero": repr(mapping[1]),
                    "reverse_bits": reverse,
                    "length_bits": len(bits),
                    "length_bytes": len(bits) // 8,
                    "length_decoded": len(decoded),
                    "printable_ratio": score[0],
                    "suspicious_matches": suspicious_score(decoded),
                }
                if verbose:
                    sys.stderr.write(
                        f"TRY one={meta['one']} zero={meta['zero']} "
                        f"reverse={reverse} bits={meta['length_bits']} "
                        f"bytes={meta['length_bytes']} "
                        f"printable={meta['printable_ratio']:.2f} "
                        f"suspicious={meta['suspicious_matches']}\n"
                    )
                candidates.append((score, decoded, meta))
    # Sort: best score first
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates


def main():
    ap = argparse.ArgumentParser(
        description="Decode invisible Unicode stego payloads (e.g., ㅤ/ﾠ) safely without executing."
    )
    ap.add_argument("path", nargs="?", help="Input file path (or '-' for stdin).")
    ap.add_argument("-o", "--output", help="Write best decoded text to this file.")
    ap.add_argument(
        "--list-codepoints", action="store_true", help="List unique code points found."
    )
    ap.add_argument(
        "--alphabet",
        nargs="*",
        help="Override candidate code points (e.g., '\\uFFA0' '\\u3164').",
    )
    ap.add_argument(
        "--verbose", action="store_true", help="Print decoding attempts and metrics."
    )
    ap.add_argument(
        "--show-top",
        type=int,
        default=3,
        help="Show top-N decoded candidates (default: 3)",
    )
    args = ap.parse_args()

    text = read_input(args.path)
    norm = normalize_text(text)

    # Build allowlist
    if args.alphabet:
        allowlist = []
        for token in args.alphabet:
            # Accept forms like \u3164 or raw char
            if token.startswith("\\u") and len(token) == 6:
                allowlist.append(chr(int(token[2:], 16)))
            else:
                allowlist.append(token)
    else:
        allowlist = DEFAULT_CANDIDATES

    if args.list_codepoints:
        cps = sorted(set(ord(ch) for ch in norm))
        print("Code points present:", ", ".join(f"U+{cp:04X}" for cp in cps))

    # Strip everything except selected candidates to avoid contamination
    stripped = "".join(ch for ch in norm if ch in allowlist)
    if not stripped:
        sys.stderr.write(
            "No candidate stego characters found after normalization/stripping.\n"
        )
        sys.exit(2)

    # Decode across symbol-pairs and orders
    decoded = decode_payload(stripped, allowlist, verbose=args.verbose)
    if not decoded:
        sys.stderr.write("Failed to produce any decoded candidates.\n")
        sys.exit(3)

    # Show top candidates
    topN = decoded[: args.show_top]
    for idx, (score, text_out, meta) in enumerate(topN, 1):
        print(f"--- Candidate {idx} ---")
        print(
            f"One-bit char: {meta['one']}, Zero-bit char: {meta['zero']}, Reverse bits: {meta['reverse_bits']}"
        )
        print(
            f"Bits: {meta['length_bits']}, Bytes: {meta['length_bytes']}, Decoded length: {meta['length_decoded']}"
        )
        print(
            f"Printable ratio: {meta['printable_ratio']:.2f}, Suspicious matches: {meta['suspicious_matches']}"
        )
        print("Decoded preview:")
        print(text_out)
        print()

    # Best candidate
    best_text = decoded[0][1]
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(best_text)
        print(f"Wrote best candidate to {args.output}")

    # Safety: warn on dangerous markers
    susp = suspicious_score(best_text)
    if susp > 0:
        print(
            f"Warning: decoded text contains {susp} suspicious pattern(s). Do not execute untrusted output."
        )


if __name__ == "__main__":
    main()
