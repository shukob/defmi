// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2 as console} from "forge-std/Test.sol";
import {Defmi} from "../src/Defmi.sol";

/// What the in-process settlement path can claim and this can show.
contract DefmiTest is Test {
    Defmi defmi;

    bytes32 constant SEC_SELLER = keccak256("securities:seller");
    bytes32 constant SEC_BUYER = keccak256("securities:buyer");
    bytes32 constant CASH_BUYER = keccak256("cash:buyer");
    bytes32 constant CASH_SELLER = keccak256("cash:seller");
    bytes32 constant ABSENT = keccak256("nobody");

    function setUp() public {
        defmi = new Defmi();
        defmi.open(SEC_SELLER, bytes32(uint256(1)));
        defmi.open(SEC_BUYER, bytes32(uint256(2)));
        defmi.open(CASH_BUYER, bytes32(uint256(3)));
        defmi.open(CASH_SELLER, bytes32(uint256(4)));
    }

    function _moves() internal pure returns (bytes32[] memory h, bytes32[] memory c) {
        h = new bytes32[](4);
        c = new bytes32[](4);
        h[0] = SEC_SELLER; h[1] = SEC_BUYER; h[2] = CASH_BUYER; h[3] = CASH_SELLER;
        c[0] = bytes32(uint256(11));
        c[1] = bytes32(uint256(12));
        c[2] = bytes32(uint256(13));
        c[3] = bytes32(uint256(14));
    }

    function test_a_settlement_moves_every_leg() public {
        (bytes32[] memory h, bytes32[] memory c) = _moves();
        uint256 before = gasleft();
        defmi.settle(keccak256("n1"), 1000, 1, h, c);
        uint256 used = before - gasleft();
        console.log("gas to apply one settlement:", used);
        assertEq(defmi.balances(SEC_SELLER), bytes32(uint256(11)));
        assertEq(defmi.balances(CASH_SELLER), bytes32(uint256(14)));

        string memory json = string.concat(
            '{\n  "contract": "Defmi",\n',
            '  "what": "the state a settlement writes once verification has passed",\n',
            '  "legs": 4,\n  "solc": "0.8.28",\n',
            '  "gas_per_settlement": ', vm.toString(used), ',\n',
            '  "atomicity": "the chain\'s, not the caller\'s: a revert on a later leg ',
            'leaves the earlier ones untouched and the nullifier unspent, which the ',
            'in-process state model can claim and not show"\n}\n'
        );
        vm.writeFile("../artifacts/evm_state.json", json);
    }

    /// The one the state model cannot demonstrate: the second leg fails and the
    /// first is not there. No unwind is written anywhere; the chain does it.
    function test_a_failed_later_leg_leaves_the_earlier_ones_untouched() public {
        bytes32[] memory h = new bytes32[](4);
        bytes32[] memory c = new bytes32[](4);
        h[0] = SEC_SELLER; h[1] = SEC_BUYER; h[2] = ABSENT; h[3] = CASH_SELLER;
        c[0] = bytes32(uint256(11));
        c[1] = bytes32(uint256(12));
        c[2] = bytes32(uint256(13));
        c[3] = bytes32(uint256(14));

        vm.expectRevert(abi.encodeWithSelector(Defmi.UnknownAccount.selector, ABSENT));
        defmi.settle(keccak256("n2"), 1000, 1, h, c);

        assertEq(defmi.balances(SEC_SELLER), bytes32(uint256(1)),
                 "the first leg survived a failure in the third");
        assertEq(defmi.balances(SEC_BUYER), bytes32(uint256(2)));
        assertEq(defmi.nullifiers(keccak256("n2")), 0,
                 "the nullifier was spent by a settlement that did not happen");
    }

    function test_an_instruction_settles_once() public {
        (bytes32[] memory h, bytes32[] memory c) = _moves();
        defmi.settle(keccak256("n3"), 1000, 1, h, c);
        vm.expectRevert(abi.encodeWithSelector(Defmi.NullifierSeen.selector,
                                               keccak256("n3")));
        defmi.settle(keccak256("n3"), 1000, 1, h, c);
    }

    function test_an_expired_instruction_does_not_settle() public {
        (bytes32[] memory h, bytes32[] memory c) = _moves();
        vm.expectRevert(abi.encodeWithSelector(Defmi.Expired.selector, uint64(10),
                                               uint64(11)));
        defmi.settle(keccak256("n4"), 10, 11, h, c);
    }

    function test_state_is_bounded_by_activity_and_not_by_history() public {
        (bytes32[] memory h, bytes32[] memory c) = _moves();
        defmi.settle(keccak256("n5"), 10, 1, h, c);
        bytes32[] memory spent = new bytes32[](1);
        spent[0] = keccak256("n5");
        assertEq(defmi.prune(spent, 5), 0, "pruned an instruction still in time");
        assertEq(defmi.prune(spent, 11), 1);
        assertEq(defmi.nullifiers(keccak256("n5")), 0);
    }

    /// A concurrent writer, which the single-threaded model has no way to model:
    /// two settlements in one block, the second spending the first's nullifier.
    function test_two_settlements_in_one_block_do_not_interleave() public {
        (bytes32[] memory h, bytes32[] memory c) = _moves();
        defmi.settle(keccak256("a"), 1000, 1, h, c);
        c[0] = bytes32(uint256(21));
        defmi.settle(keccak256("b"), 1000, 1, h, c);
        assertEq(defmi.balances(SEC_SELLER), bytes32(uint256(21)));
        assertEq(defmi.nullifiers(keccak256("a")), 1000);
        assertEq(defmi.nullifiers(keccak256("b")), 1000);
    }
}
