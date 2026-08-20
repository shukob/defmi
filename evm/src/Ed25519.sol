// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title A curve25519 scalar multiplication, priced on the machine that has
///        no precompile for it.
///
/// The EVM offers precompiles for BN254 and for modular exponentiation, and
/// nothing for curve25519. So an ed25519 or ristretto255 verification on an EVM
/// chain is field arithmetic interpreted one `MULMOD` at a time, and the
/// question is what that costs.
///
/// This is not a verifier. It is the *unit* a verifier is made of: one
/// variable-base-free scalar multiplication of the base point, in extended
/// twisted Edwards coordinates, double-and-add over 255 bits. A production
/// implementation would window the scalar and precompute multiples of the base,
/// which is worth roughly a factor of two --- so read the number below as an
/// upper bound of the same order, not as the last word.
///
/// The formulas are Hisil-Wong-Carter-Dawson: `add-2008-hwcd-3` and
/// `dbl-2008-hwcd`. Correctness is not argued here; the test beside this file
/// checks it against vectors from an RFC 8032 reference implementation that was
/// itself checked against the RFC's own test vector.
contract Ed25519 {
    /// 2^255 - 19
    uint256 internal constant P =
        57896044618658097711785492504343953926634992332820282019728792003956564819949;
    /// 2*d, with d = -121665/121666 mod P
    uint256 internal constant D2 =
        16295367250680780974490674513165176452449235426866156013048779062215315747161;

    /// The base point in extended coordinates (X, Y, Z, T), Z = 1.
    uint256 internal constant BX =
        15112221349535400772501151409588531511454012693041857206046113283949847762202;
    uint256 internal constant BY =
        46316835694926478169428394003475163141307993866256225615783033603165251855960;
    uint256 internal constant BT =
        46827403850823179245072216630277197565144205554125654976674165829533817101731;

    /// One scalar multiplication of the base point. Returns affine (x, y).
    function mulBase(uint256 s) external view returns (uint256, uint256) {
        // the neutral element, (0, 1, 1, 0)
        uint256 qx = 0;
        uint256 qy = 1;
        uint256 qz = 1;
        uint256 qt = 0;

        uint256 px = BX;
        uint256 py = BY;
        uint256 pz = 1;
        uint256 pt = BT;

        for (uint256 i = 0; i < 256; i++) {
            if (s & 1 == 1) {
                (qx, qy, qz, qt) = add(qx, qy, qz, qt, px, py, pz, pt);
            }
            (px, py, pz, pt) = dbl(px, py, pz, pt);
            s >>= 1;
        }
        uint256 zi = inv(qz);
        return (mulmod(qx, zi, P), mulmod(qy, zi, P));
    }

    function add(
        uint256 x1, uint256 y1, uint256 z1, uint256 t1,
        uint256 x2, uint256 y2, uint256 z2, uint256 t2
    ) internal pure returns (uint256, uint256, uint256, uint256) {
        uint256 a = mulmod(addmod(y1, P - x1, P), addmod(y2, P - x2, P), P);
        uint256 b = mulmod(addmod(y1, x1, P), addmod(y2, x2, P), P);
        uint256 c = mulmod(mulmod(t1, D2, P), t2, P);
        uint256 d = mulmod(mulmod(z1, 2, P), z2, P);
        uint256 e = addmod(b, P - a, P);
        uint256 f = addmod(d, P - c, P);
        uint256 g = addmod(d, c, P);
        uint256 h = addmod(b, a, P);
        return (mulmod(e, f, P), mulmod(g, h, P), mulmod(f, g, P), mulmod(e, h, P));
    }

    function dbl(uint256 x1, uint256 y1, uint256 z1, uint256)
        internal pure returns (uint256, uint256, uint256, uint256)
    {
        uint256 a = mulmod(x1, x1, P);
        uint256 b = mulmod(y1, y1, P);
        uint256 c = mulmod(2, mulmod(z1, z1, P), P);
        uint256 h = addmod(a, b, P);
        uint256 xy = addmod(x1, y1, P);
        uint256 e = addmod(h, P - mulmod(xy, xy, P), P);
        uint256 g = addmod(a, P - b, P);
        uint256 f = addmod(c, g, P);
        return (mulmod(e, f, P), mulmod(g, h, P), mulmod(f, g, P), mulmod(e, h, P));
    }

    /// Inversion through the modexp precompile, which is what a real
    /// implementation would do: a Fermat ladder written in Solidity costs about
    /// two hundred and fifty more multiplications.
    function inv(uint256 z) internal view returns (uint256 r) {
        assembly {
            let m := mload(0x40)
            mstore(m, 0x20)
            mstore(add(m, 0x20), 0x20)
            mstore(add(m, 0x40), 0x20)
            mstore(add(m, 0x60), z)
            mstore(add(m, 0x80), sub(P, 2))
            mstore(add(m, 0xa0), P)
            if iszero(staticcall(gas(), 0x05, m, 0xc0, m, 0x20)) { revert(0, 0) }
            r := mload(m)
        }
    }
}
