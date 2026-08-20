"""RFC 8032 reference ed25519, used only to produce vectors for the Solidity.

Validated below against RFC 8032 test vector 1 before it is used for anything.
"""
import hashlib
import pathlib

p = 2**255 - 19
d = -121665 * pow(121666, p - 2, p) % p
q = 2**252 + 27742317777372353535851937790883648493

def inv(x): return pow(x, p - 2, p)

def recover_x(y, sign):
    if y >= p: return None
    x2 = (y*y - 1) * inv(d*y*y + 1) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x*x - x2) % p != 0:
        x = x * pow(2, (p - 1) // 4, p) % p
    if (x*x - x2) % p != 0: return None
    if (x & 1) != sign: x = p - x
    return x

g_y = 4 * inv(5) % p
g_x = recover_x(g_y, 0)
G = (g_x, g_y, 1, g_x * g_y % p)

def point_add(P, Q):
    A = (P[1]-P[0]) * (Q[1]-Q[0]) % p
    B = (P[1]+P[0]) * (Q[1]+Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G_, H = B-A, D-C, D+C, B+A
    return (E*F % p, G_*H % p, F*G_ % p, E*H % p)

def point_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1: Q = point_add(Q, P)
        P = point_add(P, P)
        s >>= 1
    return Q

def affine(P):
    z = inv(P[2])
    return (P[0] * z % p, P[1] * z % p)

def compress(P):
    x, y = affine(P)
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")

def secret_expand(secret):
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a

TEMPLATE = r"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {{Test, console2 as console}} from "forge-std/Test.sol";
import {{Ed25519}} from "../src/Ed25519.sol";

/// The instrument is checked before it is read.
///
/// The vectors below are the output of an RFC 8032 reference implementation
/// (`scripts/ed_reference.py`), which is itself checked against the public key
/// in the RFC's own first test vector. Two independent implementations agreeing
/// on six points is what makes the gas number beside them worth quoting.
contract Ed25519Test is Test {{
    Ed25519 ed;

    function setUp() public {{ ed = new Ed25519(); }}

    function check(uint256 s, uint256 x, uint256 y) internal view {{
        (uint256 gx, uint256 gy) = ed.mulBase(s);
        assertEq(gx, x, "x");
        assertEq(gy, y, "y");
    }}

    function test_matches_the_reference() public view {{
{checks}
    }}

    /// What one scalar multiplication costs, and what that makes a settlement
    /// cost when it is composed with the number of them a verification does.
    function test_gas() public {{
        uint256 s = {gas_scalar};
        uint256 before = gasleft();
        ed.mulBase(s);
        uint256 used = before - gasleft();

        // popcount of the scalar: how many of the 256 iterations took the
        // add branch. Reported so the number can be scaled to another scalar.
        uint256 bits = 0;
        for (uint256 t = s; t != 0; t >>= 1) {{ bits += t & 1; }}

        string memory json = string.concat(
            '{{\n  "curve": "ed25519",\n  "operation": "base-point scalar multiplication",\n',
            '  "implementation": "extended coordinates, double-and-add, no windowing",\n',
            '  "solc": "0.8.28",\n  "optimizer_runs": 200,\n',
            '  "scalar_bits_set": ', vm.toString(bits), ',\n',
            '  "gas": ', vm.toString(used), '\n}}\n'
        );
        vm.writeFile("../artifacts/evm_gas.json", json);
        console.log("gas per scalar multiplication:", used);
    }}
}}
"""


def write_test(path: str) -> None:
    """Regenerate the Solidity test from this reference.

    The vectors are not copied by hand into the test; they are printed by the
    implementation that the RFC's own vector validates, so the chain from the
    standard to the assertion has no step a person could get wrong.
    """
    scalars = [1, 2, 3, 0xdeadbeef,
               0x1f3c9a5b2e8d7460f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708 % q,
               q - 1]
    cases = [(s, *affine(point_mul(s, G))) for s in scalars]
    checks = "\n".join(f"        check({s}, {x}, {y});" for s, x, y in cases)
    gas_scalar = cases[4][0]
    pathlib.Path(path).write_text(TEMPLATE.format(checks=checks, gas_scalar=gas_scalar))


if __name__ == "__main__":
    # RFC 8032 section 7.1, test vector 1
    sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4"
                       "4449c5697b326919703bac031cae7f60")
    want = "d75a980182b10ab7d54bfed3c964073a"\
           "0ee172f3daa62325af021a68f707511a"
    got = compress(point_mul(secret_expand(sk), G)).hex()
    assert got == want, f"reference is wrong: {got} != {want}"
    print("reference validated against RFC 8032 test vector 1")
    for s in (1, 2, 3, 0xdeadbeef,
              0x1f3c9a5b2e8d7460f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708 % q):
        x, y = affine(point_mul(s, G))
        print(f"    s=0x{s:064x}\n      x=0x{x:064x}\n      y=0x{y:064x}")

    write_test("test/Ed25519.t.sol")
    print("regenerated test/Ed25519.t.sol")
