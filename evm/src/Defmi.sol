// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title The settlement state, as a contract rather than as a state model.
///
/// The Rust and Python settlement paths check both legs and then write them, in
/// one process, on a model that assumes a single thread and only the failures it
/// expects. That is *agreement*: it says the two legs were consistent before
/// either was written. It is not atomicity against an exception, a concurrent
/// writer, a failed persist or a process that dies between the two writes,
/// because those are properties of a deployment and there was no deployment.
///
/// This is the deployment. Not the verifier --- a ristretto verification here
/// costs more gas than a block holds, which `Ed25519.sol` beside this file
/// prices --- but the part that has to be atomic: the state the contract keeps
/// between settlements and the transition it applies once verification has
/// passed elsewhere. The EVM gives that atomicity for nothing, and the test
/// beside this file is the demonstration: a settlement whose second leg fails
/// leaves the first leg untouched, which the in-process model can only claim.
contract Defmi {
    /// Account handle to the commitment it holds. The contract never sees a
    /// balance; a commitment goes in and a commitment comes out.
    mapping(bytes32 => bytes32) public balances;
    mapping(bytes32 => bool) public opened;

    /// An instruction settles once. The deadline is kept so the entry can be
    /// dropped afterwards --- state bounded by activity, not by history.
    mapping(bytes32 => uint64) public nullifiers;

    error HandleAlreadyOpen(bytes32 handle);
    error UnknownAccount(bytes32 handle);
    error NullifierSeen(bytes32 nullifier);
    error Expired(uint64 deadline, uint64 present);
    error LegsDisagree();

    event Settled(bytes32 indexed nullifier, uint256 legs);
    event Opened(bytes32 indexed handle);

    function open(bytes32 handle, bytes32 commitment) external {
        if (opened[handle]) revert HandleAlreadyOpen(handle);
        opened[handle] = true;
        balances[handle] = commitment;
        emit Opened(handle);
    }

    /// Apply one settled instruction: every leg or none.
    ///
    /// `handles` and `commitments` are the moves, in pairs of two per rail. The
    /// revert on any one of them undoes the ones before it, which is the whole
    /// point and is not something the caller has to arrange.
    function settle(
        bytes32 nullifier,
        uint64 deadline,
        uint64 present,
        bytes32[] calldata handles,
        bytes32[] calldata commitments
    ) external {
        if (present > deadline) revert Expired(deadline, present);
        if (nullifiers[nullifier] != 0) revert NullifierSeen(nullifier);
        if (handles.length != commitments.length || handles.length == 0) {
            revert LegsDisagree();
        }
        nullifiers[nullifier] = deadline;
        for (uint256 i = 0; i < handles.length; i++) {
            if (!opened[handles[i]]) revert UnknownAccount(handles[i]);
            balances[handles[i]] = commitments[i];
        }
        emit Settled(nullifier, handles.length);
    }

    /// Drop nullifiers whose instruction can no longer settle anyway. Safe
    /// because an expired instruction is refused on its deadline instead, so
    /// the entry stops carrying information the moment it can go.
    function prune(bytes32[] calldata spent, uint64 present) external returns (uint256) {
        uint256 dropped = 0;
        for (uint256 i = 0; i < spent.length; i++) {
            uint64 deadline = nullifiers[spent[i]];
            if (deadline != 0 && deadline < present) {
                delete nullifiers[spent[i]];
                dropped++;
            }
        }
        return dropped;
    }
}
