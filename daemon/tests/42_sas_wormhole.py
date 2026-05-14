#!/usr/bin/env python3
# 42_sas_wormhole.py — SAS digit derivation + wordlist + wormhole-code
# normalisation.  Mirrors Android's Spake2SasTest.kt + WormholeCodeTest.kt.

import hashlib
import importlib.machinery
import importlib.util
import os
import secrets
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
loader = importlib.machinery.SourceFileLoader(
    "wgrtc", os.path.join(REPO, "wireguardrtc"))
spec = importlib.util.spec_from_loader("wgrtc", loader)
wgrtc = importlib.util.module_from_spec(spec)
loader.exec_module(wgrtc)


# ─── SAS wordlist invariants (from Spake2SasTest.kt) ────────────────

def test_wordlist_is_256_entries():
    assert len(wgrtc.SAS_WORDLIST) == 256, \
        f"wordlist length: got {len(wgrtc.SAS_WORDLIST)}, want 256"


def test_wordlist_entries_have_no_spaces():
    for i, w in enumerate(wgrtc.SAS_WORDLIST):
        assert " " not in w, f"word[{i}] = {w!r} contains a space"


def test_wordlist_entries_length_in_range():
    for i, w in enumerate(wgrtc.SAS_WORDLIST):
        assert 2 <= len(w) <= 12, \
            f"word[{i}] = {w!r} length {len(w)} out of [2, 12]"


def test_wordlist_entries_unique():
    seen = set(wgrtc.SAS_WORDLIST)
    assert len(seen) == 256, \
        f"duplicate words: {len(wgrtc.SAS_WORDLIST) - len(seen)} duplicates"


# ─── SAS derivation ──────────────────────────────────────────────────

def test_sas_digest_matches_blake2b():
    # The SAS digest is BLAKE2b(shared_key, key=LABEL_SPAKE2_SAS,
    # digest_size=word_count).  Verify deriveSas matches by computing
    # the digest independently and indexing the wordlist.
    shared_key = bytes(range(32))
    sas = wgrtc.derive_sas(shared_key, word_count=4)
    words = sas.split(" ")
    assert len(words) == 4

    expected = hashlib.blake2b(shared_key, digest_size=4,
                               key=wgrtc.SPAKE2_LABEL_SAS).digest()
    for i, byte in enumerate(expected):
        assert words[i] == wgrtc.SAS_WORDLIST[byte], \
            f"word[{i}]: got {words[i]!r}, want {wgrtc.SAS_WORDLIST[byte]!r}"


def test_sas_same_key_yields_same_sas():
    key = b"\x42" * 32
    assert wgrtc.derive_sas(key) == wgrtc.derive_sas(key)


def test_sas_different_key_yields_different_sas():
    a = wgrtc.derive_sas(b"\x42" * 32)
    b = wgrtc.derive_sas(b"\x43" * 32)
    assert a != b


def test_sas_word_count_default_is_four():
    sas = wgrtc.derive_sas(b"\x42" * 32)
    assert len(sas.split(" ")) == 4


def test_sas_word_count_zero_returns_empty():
    assert wgrtc.derive_sas(b"\x42" * 32, word_count=0) == ""


def test_sas_word_count_one_returns_one_word():
    sas = wgrtc.derive_sas(b"\x42" * 32, word_count=1)
    assert " " not in sas
    assert sas in wgrtc.SAS_WORDLIST


def test_sas_rejects_short_key():
    try:
        wgrtc.derive_sas(b"too short")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_sas_rejects_huge_word_count():
    try:
        wgrtc.derive_sas(b"\x00" * 32, word_count=33)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


# ─── SAS round-trip via SPAKE2 ──────────────────────────────────────

def test_spake2_round_trip_yields_same_sas():
    pwd = b"WORMHOLE"
    a = wgrtc.Spake2(role="alice", password=pwd)
    b = wgrtc.Spake2(role="bob", password=pwd)
    a_msg = a.start()
    b_msg = b.start()
    a_key = a.finish(b_msg)
    b_key = b.finish(a_msg)
    assert wgrtc.derive_sas(a_key) == wgrtc.derive_sas(b_key)


# ─── Wormhole code ──────────────────────────────────────────────────

def test_wormhole_alphabet_size_is_24():
    assert len(wgrtc.WORMHOLE_ALPHABET) == 24
    assert "I" not in wgrtc.WORMHOLE_ALPHABET
    assert "O" not in wgrtc.WORMHOLE_ALPHABET


def test_wormhole_generate_default_length():
    code = wgrtc.wormhole_generate()
    assert len(code) == 6
    assert all(c in wgrtc.WORMHOLE_ALPHABET for c in code)


def test_wormhole_generate_other_lengths():
    for n in (1, 4, 8, 32):
        code = wgrtc.wormhole_generate(length=n)
        assert len(code) == n


def test_wormhole_generate_rejects_bad_length():
    for bad in (0, -1, 33, 1000):
        try:
            wgrtc.wormhole_generate(length=bad)
            raise AssertionError(f"expected ValueError for length={bad}")
        except ValueError:
            pass


def test_wormhole_normalize_uppercases():
    assert wgrtc.wormhole_normalize("abcdef") == "ABCDEF"


def test_wormhole_normalize_strips_separators():
    assert wgrtc.wormhole_normalize("AB-CD EF") == "ABCDEF"
    assert wgrtc.wormhole_normalize("  ab\tcd\nef  ") == "ABCDEF"


def test_wormhole_normalize_drops_disallowed_chars():
    # I and O are not in the alphabet — get stripped.
    assert wgrtc.wormhole_normalize("ABIOCD") == "ABCD"
    # Digits, punctuation — gone.
    assert wgrtc.wormhole_normalize("AB!1CD?EF") == "ABCDEF"


def test_wormhole_is_valid_default_length():
    assert wgrtc.wormhole_is_valid("ABCDEF")
    assert wgrtc.wormhole_is_valid("ab-cd-ef")
    assert not wgrtc.wormhole_is_valid("ABCDE")     # too short
    assert not wgrtc.wormhole_is_valid("ABCDEFG")   # too long
    assert not wgrtc.wormhole_is_valid("ABCDE1")    # invalid char


def test_wormhole_to_bytes_uses_canonical_form():
    assert wgrtc.wormhole_to_bytes("ab-cd-ef") == b"ABCDEF"
    assert wgrtc.wormhole_to_bytes("ABCDEF") == b"ABCDEF"


# ─── Driver ─────────────────────────────────────────────────────────

def main():
    tests = [
        test_wordlist_is_256_entries,
        test_wordlist_entries_have_no_spaces,
        test_wordlist_entries_length_in_range,
        test_wordlist_entries_unique,
        test_sas_digest_matches_blake2b,
        test_sas_same_key_yields_same_sas,
        test_sas_different_key_yields_different_sas,
        test_sas_word_count_default_is_four,
        test_sas_word_count_zero_returns_empty,
        test_sas_word_count_one_returns_one_word,
        test_sas_rejects_short_key,
        test_sas_rejects_huge_word_count,
        test_spake2_round_trip_yields_same_sas,
        test_wormhole_alphabet_size_is_24,
        test_wormhole_generate_default_length,
        test_wormhole_generate_other_lengths,
        test_wormhole_generate_rejects_bad_length,
        test_wormhole_normalize_uppercases,
        test_wormhole_normalize_strips_separators,
        test_wormhole_normalize_drops_disallowed_chars,
        test_wormhole_is_valid_default_length,
        test_wormhole_to_bytes_uses_canonical_form,
    ]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
            failures += 1
    print()
    print(f"{len(tests) - failures}/{len(tests)} passed")
    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
