// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

/// @title AgentCardVerifier
/// @notice Library for verifying ERC-8004 cross-chain agent registration claims via EIP-712.
///         Stateless — all functions are pure or view. Import and inline in any contract.
library AgentCardVerifier {
    // ──────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────

    bytes32 internal constant CLAIM_TYPEHASH = keccak256(
        "AgentRegistrationClaim(uint256 chainId,address registryAddress,uint256 agentId,uint256 deadline)"
    );

    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    // ──────────────────────────────────────────────
    //  Structs
    // ──────────────────────────────────────────────

    /// @notice Typed data for an agent registration claim.
    /// @param chainId The chain ID where the agent is registered.
    /// @param registryAddress The Identity Registry contract on that chain.
    /// @param agentId The ERC-721 token ID in that registry.
    /// @param deadline Unix timestamp after which the claim signature expires.
    struct AgentRegistrationClaim {
        uint256 chainId;
        address registryAddress;
        uint256 agentId;
        uint256 deadline;
    }

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────

    /// @notice The claim's deadline has passed.
    error ClaimExpired(uint256 deadline, uint256 currentTimestamp);

    /// @notice The chain ID in the claim is zero.
    error InvalidChainId();

    /// @notice The registry address in the claim is the zero address.
    error InvalidRegistryAddress();

    /// @notice The signature length is invalid.
    error InvalidSignatureLength(uint256 length);

    /// @notice ERC-1271 validation returned an unexpected value.
    error ERC1271ValidationFailed(address signer);

    /// @notice The staticcall to the ERC-1271 contract reverted.
    error ERC1271CallFailed(address signer);

    // ──────────────────────────────────────────────
    //  Internal — validation helpers
    // ──────────────────────────────────────────────

    /// @notice Reverts if the claim has invalid fields or an expired deadline.
    function _validateClaimFields(AgentRegistrationClaim memory claim) internal view {
        if (claim.chainId == 0) revert InvalidChainId();
        if (claim.registryAddress == address(0)) revert InvalidRegistryAddress();
        if (block.timestamp > claim.deadline) revert ClaimExpired(claim.deadline, block.timestamp);
        if (claim.deadline == 0) revert ClaimExpired(0, block.timestamp);
    }

    // ──────────────────────────────────────────────
    //  Internal — EIP-712 hashing
    // ──────────────────────────────────────────────

    /// @notice Returns the EIP-712 struct hash for a registration claim.
    function _hashClaim(AgentRegistrationClaim memory claim) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                CLAIM_TYPEHASH,
                claim.chainId,
                claim.registryAddress,
                claim.agentId,
                claim.deadline
            )
        );
    }

    /// @notice Returns the full EIP-712 typed data hash (domain + struct).
    /// @param domainSeparator The EIP-712 domain separator of the verifying contract.
    /// @param claim The registration claim to hash.
    function _hashTypedData(bytes32 domainSeparator, AgentRegistrationClaim memory claim)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, _hashClaim(claim)));
    }

    // ──────────────────────────────────────────────
    //  Internal — signature verification
    // ──────────────────────────────────────────────

    /// @notice Verifies a registration claim for a claimed owner.
    ///         Tries ECDSA first; if the recovered address doesn't match and claimedOwner
    ///         has contract code, falls back to ERC-1271 staticcall.
    ///         Returns false (not revert) on ERC-1271 rejection or ECDSA mismatch.
    ///         Reverts on malformed claims (expired, zero chainId, zero registry).
    /// @param domainSeparator The EIP-712 domain separator of the verifying contract.
    /// @param claim The registration claim to verify.
    /// @param claimedOwner The address that allegedly signed the claim.
    /// @param signature The EIP-712 signature bytes.
    /// @return valid True if the signature is valid for claimedOwner.
    function _verifyRegistrationClaim(
        bytes32 domainSeparator,
        AgentRegistrationClaim memory claim,
        address claimedOwner,
        bytes memory signature
    ) internal view returns (bool valid) {
        if (signature.length == 0) revert InvalidSignatureLength(0);

        _validateClaimFields(claim);

        bytes32 digest = _hashTypedData(domainSeparator, claim);

        // Attempt ECDSA recovery
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, signature);

        if (err == ECDSA.RecoverError.NoError && recovered == claimedOwner) {
            return true;
        }

        // Fall back to ERC-1271 if claimedOwner has code
        if (claimedOwner.code.length > 0) {
            (bool success, bytes memory returnData) = claimedOwner.staticcall(
                abi.encodeCall(IERC1271.isValidSignature, (digest, signature))
            );
            if (!success || returnData.length < 32) return false;
            bytes4 magicValue = abi.decode(returnData, (bytes4));
            return magicValue == ERC1271_MAGIC_VALUE;
        }

        return false;
    }

    /// @notice Recovers the signer address from a registration claim via ECDSA.
    ///         Reverts on malformed claims, invalid signatures, or recovery failures.
    /// @param domainSeparator The EIP-712 domain separator of the verifying contract.
    /// @param claim The registration claim.
    /// @param signature The EIP-712 signature bytes (65 bytes: r, s, v).
    /// @return signer The recovered signer address.
    function _recoverClaimSigner(
        bytes32 domainSeparator,
        AgentRegistrationClaim memory claim,
        bytes memory signature
    ) internal view returns (address signer) {
        if (signature.length != 65) revert InvalidSignatureLength(signature.length);

        _validateClaimFields(claim);

        bytes32 digest = _hashTypedData(domainSeparator, claim);
        return ECDSA.recover(digest, signature);
    }
}
