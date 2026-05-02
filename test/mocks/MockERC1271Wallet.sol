// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @notice Mock ERC-1271 wallet for testing. Three modes: approve, reject, revert.
contract MockERC1271Wallet is IERC1271 {
    bytes4 private constant MAGIC_VALUE = 0x1626ba7e;

    enum Mode {
        Approve,
        Reject,
        Revert
    }

    Mode public mode;
    bytes32 public approvedDigest;

    constructor(Mode _mode) {
        mode = _mode;
    }

    function setMode(Mode _mode) external {
        mode = _mode;
    }

    function setApprovedDigest(bytes32 digest) external {
        approvedDigest = digest;
    }

    function isValidSignature(bytes32 hash, bytes memory) external view override returns (bytes4) {
        if (mode == Mode.Revert) revert("MockERC1271Wallet: deliberate revert");
        if (mode == Mode.Reject) return bytes4(0xffffffff);
        if (hash == approvedDigest) return MAGIC_VALUE;
        return bytes4(0xffffffff);
    }
}
