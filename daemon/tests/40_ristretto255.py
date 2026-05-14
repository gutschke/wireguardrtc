#!/usr/bin/env python3
# 40_ristretto255.py — verify the daemon's pure-Python Ristretto255
# matches libsodium byte-for-byte.
#
# Why a vendored impl: pynacl 1.5.0 exposes Ed25519 but not the
# Ristretto255 bindings, and pynacl's bundled libsodium has the
# Ristretto symbols stripped from its cffi-visible surface.  Adding a
# pypi binding adds an unmaintained transitive dep; binding to system
# libsodium via ctypes adds a Debian dep.  ~250 LoC of well-specified
# curve math, validated against the same libsodium the Android app
# links against, gives us protocol-level interop with zero new
# transitive deps.
#
# Test strategy:
#   1. Hard-coded RFC 9496 §A.1 small-multiples vectors (decode/encode
#      round-trips through repeated addition).
#   2. Hard-coded libsodium-derived "must-reject" bad encodings
#      (RFC 9496 §A.2 candidates verified against libsodium).
#   3. Hard-coded libsodium-derived hash-to-point and scalarmult_base
#      vectors for random inputs (recorded once, frozen).
#   4. Property-based cross-check: if libsodium is reachable at test
#      time via ctypes, generate 50 random scalars / hashes and assert
#      byte-for-byte equality.  This catches regressions on any
#      operation, not just the recorded vectors.

import ctypes
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


def h(s):
    return bytes.fromhex(s.replace(" ", "").replace("\n", ""))


# Try to dlopen libsodium for the property-based cross-check.  None if
# not present; tests that need it skip cleanly.
def _try_open_libsodium():
    for name in ("libsodium.so.23", "libsodium.so",
                 "/usr/lib/x86_64-linux-gnu/libsodium.so.23",
                 "/usr/lib/aarch64-linux-gnu/libsodium.so.23"):
        try:
            lib = ctypes.CDLL(name)
            lib.sodium_init()
            return lib
        except OSError:
            continue
    return None


LIBSODIUM = _try_open_libsodium()


# ─── A.1 small multiples of B ──────────────────────────────────────────
# Vectors are libsodium ground truth (which matches RFC 9496 §A.1).

SMALL_MULTIPLES = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
    "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
    "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
    "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
    "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
    "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
    "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
    "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
    "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
    "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
    "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
    "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
    "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
    "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
    "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
]


def test_encode_small_multiples_via_add():
    B = wgrtc.r255_decode(h(SMALL_MULTIPLES[1]))
    assert B is not None, "decode(B) returned None"
    # k=0
    zero_enc = wgrtc.r255_encode(wgrtc.r255_identity())
    assert zero_enc == h(SMALL_MULTIPLES[0]), \
        f"0*B: got {zero_enc.hex()}"
    # k=1..15 via repeated addition
    P = wgrtc.r255_identity()
    for k in range(1, 16):
        P = wgrtc.r255_add(P, B)
        got = wgrtc.r255_encode(P)
        want = h(SMALL_MULTIPLES[k])
        assert got == want, \
            f"k={k}: got {got.hex()}, want {want.hex()}"


def test_encode_small_multiples_via_scalarmult_base():
    for k in range(16):
        s = k.to_bytes(32, 'little')
        P = wgrtc.r255_scalarmult_base(s)
        got = wgrtc.r255_encode(P)
        want = h(SMALL_MULTIPLES[k])
        assert got == want, \
            f"k={k}: scalarmult_base got {got.hex()}, want {want.hex()}"


# ─── A.2 bad encodings that MUST be rejected ──────────────────────────
# Each verified against libsodium's is_valid_point during generation.

BAD_ENCODINGS = [
    "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "ed57ffd8c914fb78cdf59ba133b3e8a6cc65c3267cc75fa1ba6796d3271d7f80",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "26948d35ca62e643e26a8384337d88144f27dd235e5b8d5ba01a78e94a30ef6a",
    "3f732603b3d97a0cf1a9840fbf3209a41b499b9d2b118bf04d8432395de9605d",
    "a730a6225321d07b76757de880ae1602f4cb640238b4e9d09235847db17e25ad",
    "5b9cc8e987dbad868d9ec873fa13e68884fd7d310a6ecb6773650fc8478de85c",
    "edb94dc10664fa90edb3faeb8c764990f5b122c9fab5fcd25bec75cd70fa3306",
    "6224baae716b4abe21a30f5ff3cc36879f36e80496ecb84dc617fdcf8427c27c",
    "f123fb5ec0e3ef7864911fcd144cacaa9435388a03bf76d828c8d489ed7f8014",
    "c473e81c218049e30c0eba644ba118c18fbce09e30247e180e1f6ac00fe98405",
]


def test_bad_encodings_rejected():
    for i, hexstr in enumerate(BAD_ENCODINGS):
        s = h(hexstr)
        out = wgrtc.r255_decode(s)
        assert out is None, \
            f"BAD_ENCODINGS[{i}] = {hexstr} should have been rejected"
        assert not wgrtc.r255_is_valid_point(s), \
            f"BAD_ENCODINGS[{i}] = {hexstr} is_valid_point() said True"


# ─── frozen libsodium-derived random vectors ─────────────────────────
# Generated once with libsodium; baked here as regression fixtures so
# the file remains testable even on hosts without libsodium installed.

# All scalars below are < L (i.e., `scalar_random`-compatible).
# Libsodium's `ge25519_scalarmult_base` has documented undefined
# behavior when the scalar's top nibble is ≥ 8 (out-of-range): the
# comb-table lookup uses an out-of-bounds index.  SPAKE2 always
# generates scalars via `scalar_random` / `scalar_reduce` which are
# guaranteed in [0, L), so this path never bites in practice; but
# fixtures here are scrupulously in-range so we test the documented
# operating envelope rather than the UB.
SCALARMULT_BASE_VECTORS = [
    ("cc68e314085b9a54d5b4e9db4e9af7e44af15ff4e1f4a67bee157f7bd6c2f10b",
     "9e9062eb11f2e6f3b96cb7be4ca93465701ea04359932bd31ea7e2a508c56842"),
    ("52f23ca6ee83616fa247768da4f4c5c56595b5856e9806f6b05a0446958b2004",
     "9a47585d67f849d3b30d806d3cc74d2f3d403ac498314f61386958b49d00e70b"),
    ("4dd5f3a2f976bd7d303795bf810b2c23c4892ff7a64602622c589145a9604f05",
     "fa91b9505110ec26ad6acd05522f74539c3747d4ee7d1ceb3ef5c4e21015e514"),
    ("cd099d0dcb872bdc561c710eb3ca68ff7f1d133d379e9c9d6921643f26876b04",
     "96c1595fe69346a9b89e727821813f355fbe4834250756e04451a9b6a8d83e45"),
    ("230c517264e64e11c527e861890c38db7610d97db044fed883ce4d3601c2ec05",
     "305cc5459de4bba2620e7fe0f5f764cbb15baae38d6e3b9d9f0c9785497bc024"),
]

FROM_HASH_VECTORS = [
    ("7ed7e607fa5021a813e7043a33c572567fbd444b09485a7e43c4456e6bf311c8"
     "149a9122b1a9f192a7e10fdbd7f31a093d49505405163d5c7e290dcf9533690b",
     "d6ba62f7d3defc46946b79f08526b30b1a956b07ea0df045dce5814fae41a256"),
    ("f6af1083bfa03c604cd74eb561f53b7f4de5cdfe49bee101416e6283a2f55546"
     "4cafb9be586c1edf450cdfa2ea07067e35a3cab611247ea8f29668596f905829",
     "842c078b47e1c436651c9100a9aa3ad827c418030c8d260aaf91b4ba73ff910b"),
    ("bc1848a45da3bcfc39ac0a5690b78dabfaf650bfb06dfda4f7600e47937d103c"
     "e1b324b899be843ac262a107692086b5b17cb86576c38ced3b751fce811ad62a",
     "1c2dfde85be10258aa17151f2e0440427f5c5bf34c0575ea75fa7dde7292b762"),
    ("e2ad35e7314cf5a0b1fa4f998d65768f8b371ff7f6c09ea49c0f979ae3822e08"
     "4ff2e91535faf26698a8b179ad5d50df61c51b4ec2de67829823d28aa0214cfa",
     "2606a3171d8aa1790abd2550433e5c724591e4cab73407a821994d39d8c34b3a"),
    ("cb2ab616e0342b740da81f5c29d9776e0787557c82e73f1615c19f570af7eb68"
     "edf4de4ed38e04866e02f5d1b5337634a88ee9de284762a1e9ee3bb91322e7be",
     "0851d1a0b7de60fe9c9033321316ed961ce7aa264bb7f08e490e89d10a6b9642"),
]


def test_scalarmult_base_random_vectors():
    for i, (s_hex, expected_hex) in enumerate(SCALARMULT_BASE_VECTORS):
        s = h(s_hex)
        P = wgrtc.r255_scalarmult_base(s)
        got = wgrtc.r255_encode(P)
        assert got == h(expected_hex), \
            f"vec {i}: got {got.hex()}, want {expected_hex}"


def test_from_hash_random_vectors():
    for i, (h_hex, expected_hex) in enumerate(FROM_HASH_VECTORS):
        P = wgrtc.r255_from_hash(h(h_hex))
        got = wgrtc.r255_encode(P)
        assert got == h(expected_hex), \
            f"vec {i}: got {got.hex()}, want {expected_hex}"


# ─── property-based libsodium cross-check (skipped if no libsodium) ──

def _libsodium_scalarmult_base(scalar):
    inp = (ctypes.c_ubyte * 32)(*scalar)
    out = (ctypes.c_ubyte * 32)()
    LIBSODIUM.crypto_scalarmult_ristretto255_base(out, inp)
    return bytes(out)


def _libsodium_from_hash(h64):
    inp = (ctypes.c_ubyte * 64)(*h64)
    out = (ctypes.c_ubyte * 32)()
    LIBSODIUM.crypto_core_ristretto255_from_hash(out, inp)
    return bytes(out)


def _libsodium_scalarmult(scalar, point32):
    inp_s = (ctypes.c_ubyte * 32)(*scalar)
    inp_p = (ctypes.c_ubyte * 32)(*point32)
    out = (ctypes.c_ubyte * 32)()
    rc = LIBSODIUM.crypto_scalarmult_ristretto255(out, inp_s, inp_p)
    return None if rc != 0 else bytes(out)


def test_random_scalarmult_base_matches_libsodium():
    # Scalars are drawn from `r255_scalar_random`, which reduces a
    # 64-byte uniform sample mod L — i.e. always in [0, L).  Out-of-
    # range scalars trigger libsodium's documented UB in
    # `ge25519_scalarmult_base` (high-nibble overrun); SPAKE2 never
    # passes such a scalar so we don't exercise that path.
    if LIBSODIUM is None:
        print("    (libsodium not available; skipping cross-check)")
        return
    for _ in range(50):
        s = wgrtc.r255_scalar_random()
        ours = wgrtc.r255_encode(wgrtc.r255_scalarmult_base(s))
        theirs = _libsodium_scalarmult_base(s)
        assert ours == theirs, \
            f"scalarmult_base divergence on scalar {s.hex()}:\n" \
            f"  ours:   {ours.hex()}\n  libsodium: {theirs.hex()}"


def test_random_from_hash_matches_libsodium():
    if LIBSODIUM is None:
        print("    (libsodium not available; skipping cross-check)")
        return
    for _ in range(50):
        h_in = secrets.token_bytes(64)
        ours = wgrtc.r255_encode(wgrtc.r255_from_hash(h_in))
        theirs = _libsodium_from_hash(h_in)
        assert ours == theirs, \
            f"from_hash divergence on input {h_in.hex()}:\n" \
            f"  ours:   {ours.hex()}\n  libsodium: {theirs.hex()}"


def test_random_scalarmult_on_point_matches_libsodium():
    if LIBSODIUM is None:
        print("    (libsodium not available; skipping cross-check)")
        return
    # Build a known good point via from_hash, then scalarmult it.
    for _ in range(50):
        h_in = secrets.token_bytes(64)
        P_bytes = _libsodium_from_hash(h_in)
        s = wgrtc.r255_scalar_random()  # always in [0, L)
        ours = wgrtc.r255_encode(wgrtc.r255_scalarmult(s, P_bytes))
        theirs = _libsodium_scalarmult(s, P_bytes)
        assert ours == theirs, \
            f"scalarmult divergence:\n" \
            f"  scalar:    {s.hex()}\n" \
            f"  point:     {P_bytes.hex()}\n" \
            f"  ours:      {ours.hex()}\n" \
            f"  libsodium: {theirs.hex()}"


# ─── basic identities + sanity ─────────────────────────────────────

def test_identity_encode_is_zero():
    enc = wgrtc.r255_encode(wgrtc.r255_identity())
    assert enc == bytes(32), f"identity encode: got {enc.hex()}"


def test_identity_is_valid():
    assert wgrtc.r255_is_valid_point(bytes(32))


def test_decode_encode_roundtrip_on_B():
    B = wgrtc.r255_decode(h(SMALL_MULTIPLES[1]))
    assert B is not None
    enc = wgrtc.r255_encode(B)
    assert enc == h(SMALL_MULTIPLES[1])


def test_sub_is_inverse_of_add():
    B = wgrtc.r255_decode(h(SMALL_MULTIPLES[1]))
    twoB = wgrtc.r255_decode(h(SMALL_MULTIPLES[2]))
    diff = wgrtc.r255_sub(twoB, B)
    assert wgrtc.r255_encode(diff) == h(SMALL_MULTIPLES[1])


def test_scalar_reduce():
    out = wgrtc.r255_scalar_reduce(bytes(64))
    assert out == bytes(32)
    L = 2**252 + 27742317777372353535851937790883648493
    out = wgrtc.r255_scalar_reduce(L.to_bytes(64, 'little'))
    assert int.from_bytes(out, 'little') == 0


def test_scalar_random_is_in_range():
    L = 2**252 + 27742317777372353535851937790883648493
    seen = set()
    for _ in range(100):
        s = wgrtc.r255_scalar_random()
        assert len(s) == 32
        n = int.from_bytes(s, 'little')
        assert 0 < n < L, f"scalar out of range: {n}"
        seen.add(s)
    assert len(seen) == 100


# ─── Driver ─────────────────────────────────────────────────────────

def main():
    tests = [
        test_identity_encode_is_zero,
        test_identity_is_valid,
        test_decode_encode_roundtrip_on_B,
        test_encode_small_multiples_via_add,
        test_encode_small_multiples_via_scalarmult_base,
        test_bad_encodings_rejected,
        test_scalarmult_base_random_vectors,
        test_from_hash_random_vectors,
        test_sub_is_inverse_of_add,
        test_scalar_reduce,
        test_scalar_random_is_in_range,
        test_random_scalarmult_base_matches_libsodium,
        test_random_from_hash_matches_libsodium,
        test_random_scalarmult_on_point_matches_libsodium,
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
    print(f"{len(tests) - failures}/{len(tests)} passed"
          f" (libsodium {'available' if LIBSODIUM else 'NOT available'})")
    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
