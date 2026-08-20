// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2 as console} from "forge-std/Test.sol";
import {Ed25519} from "../src/Ed25519.sol";

/// The instrument is checked before it is read.
///
/// The vectors below are the output of an RFC 8032 reference implementation
/// (`scripts/ed_reference.py`), which is itself checked against the public key
/// in the RFC's own first test vector. Two independent implementations agreeing
/// on six points is what makes the gas number beside them worth quoting.
contract Ed25519Test is Test {
    Ed25519 ed;

    function setUp() public { ed = new Ed25519(); }

    function check(uint256 s, uint256 x, uint256 y) internal view {
        (uint256 gx, uint256 gy) = ed.mulBase(s);
        assertEq(gx, x, "x");
        assertEq(gy, y, "y");
    }

    function test_matches_the_reference() public view {
        check(1, 15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960);
        check(2, 24727413235106541002554574571675588834622768167397638456726423682521233608206, 15549675580280190176352668710449542251549572066445060580507079593062643049417);
        check(3, 46896733464454938657123544595386787789046198280132665686241321779790909858396, 8324843778533443976490377120369201138301417226297555316741202210403726505172);
        check(3735928559, 35136462325802565254074472996739032021426480583520437135977070964408065107385, 312659494193657239065729020518977380645485809175095093371176396483277261482);
        check(6891768879830807808645336843538704181122430401692319619750064197510857040667, 43280750526173029619671513252686688165237902504223250564337480334974325984710, 27058096512448302635010808876967931209941086863644018597136535129323626501950);
        check(7237005577332262213973186563042994240857116359379907606001950938285454250988, 42783823269122696939284341094755422415180979639778424813682678720006717057747, 46316835694926478169428394003475163141307993866256225615783033603165251855960);
    }

    /// What one scalar multiplication costs, and what that makes a settlement
    /// cost when it is composed with the number of them a verification does.
    function test_gas() public {
        uint256 s = 6891768879830807808645336843538704181122430401692319619750064197510857040667;
        uint256 before = gasleft();
        ed.mulBase(s);
        uint256 used = before - gasleft();

        // popcount of the scalar: how many of the 256 iterations took the
        // add branch. Reported so the number can be scaled to another scalar.
        uint256 bits = 0;
        for (uint256 t = s; t != 0; t >>= 1) { bits += t & 1; }

        string memory json = string.concat(
            '{\n  "curve": "ed25519",\n  "operation": "base-point scalar multiplication",\n',
            '  "implementation": "extended coordinates, double-and-add, no windowing",\n',
            '  "solc": "0.8.28",\n  "optimizer_runs": 200,\n',
            '  "scalar_bits_set": ', vm.toString(bits), ',\n',
            '  "gas": ', vm.toString(used), '\n}\n'
        );
        vm.writeFile("../artifacts/evm_gas.json", json);
        console.log("gas per scalar multiplication:", used);
    }
}
