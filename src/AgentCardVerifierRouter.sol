// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {AgentCardVerifier} from "./AgentCardVerifier.sol";

/// @title AgentCardVerifierRouter
/// @notice Deployed stateless contract wrapping the AgentCardVerifier library as external calls.
///         Use this when you cannot link the library at compile time (already-deployed contracts,
///         different frameworks). No owner, no state beyond EIP712 immutables.
contract AgentCardVerifierRouter is EIP712 {
    using AgentCardVerifier for AgentCardVerifier.AgentRegistrationClaim;

    // ──────────────────────────────────────────────
    //  Re-export types for callers
    // ──────────────────────────────────────────────

    struct AgentRegistrationClaim {
        uint256 chainId;
        address registryAddress;
        uint256 agentId;
        uint256 deadline;
    }

    struct VerificationResult {
        AgentRegistrationClaim claim;
        bool isValid;
        address signer;
    }

    // ──────────────────────────────────────────────
    //  Re-export errors for callers
    // ──────────────────────────────────────────────

    error ClaimExpired(uint256 deadline, uint256 currentTimestamp);
    error InvalidChainId();
    error InvalidRegistryAddress();
    error InvalidSignatureLength(uint256 length);
    error ERC1271ValidationFailed(address signer);
    error ERC1271CallFailed(address signer);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    constructor() EIP712("AgentCardVerifier", "1") {}

    // ──────────────────────────────────────────────
    //  Internal conversion helpers
    // ──────────────────────────────────────────────

    function _toLibClaim(AgentRegistrationClaim calldata claim)
        internal
        pure
        returns (AgentCardVerifier.AgentRegistrationClaim memory)
    {
        return AgentCardVerifier.AgentRegistrationClaim({
            chainId: claim.chainId,
            registryAddress: claim.registryAddress,
            agentId: claim.agentId,
            deadline: claim.deadline
        });
    }

    // ──────────────────────────────────────────────
    //  Core verification
    // ──────────────────────────────────────────────

    /// @notice Verify a registration claim signature against a claimed owner.
    ///         Supports both EOA (ECDSA) and smart contract wallets (ERC-1271).
    ///         Reverts if the claim is expired or malformed.
    /// @param claim The registration claim to verify.
    /// @param claimedOwner The address that allegedly signed the claim.
    /// @param signature The EIP-712 signature bytes.
    /// @return valid True if the signature is valid for the claimedOwner.
    function verifyRegistrationClaim(
        AgentRegistrationClaim calldata claim,
        address claimedOwner,
        bytes calldata signature
    ) external view returns (bool valid) {
        return AgentCardVerifier._verifyRegistrationClaim(
            _domainSeparatorV4(), _toLibClaim(claim), claimedOwner, signature
        );
    }

    /// @notice Recover the signer address from a registration claim signature (ECDSA only).
    ///         Reverts if the claim is expired, malformed, or the signature is invalid.
    /// @param claim The registration claim.
    /// @param signature The EIP-712 signature bytes (65 bytes: r, s, v).
    /// @return signer The recovered signer address.
    function recoverClaimSigner(AgentRegistrationClaim calldata claim, bytes calldata signature)
        external
        view
        returns (address signer)
    {
        return AgentCardVerifier._recoverClaimSigner(
            _domainSeparatorV4(), _toLibClaim(claim), signature
        );
    }

    /// @notice Verify multiple registration claims in a single call.
    ///         Does not revert on individual failures — returns per-claim results.
    ///         Reverts only on mismatched array lengths.
    /// @param claims Array of registration claims.
    /// @param claimedOwners Array of claimed owner addresses (same length as claims).
    /// @param signatures Array of signatures (same length as claims).
    /// @return results Array of verification results.
    function verifyRegistrationClaimBatch(
        AgentRegistrationClaim[] calldata claims,
        address[] calldata claimedOwners,
        bytes[] calldata signatures
    ) external view returns (VerificationResult[] memory results) {
        uint256 len = claims.length;
        if (len != claimedOwners.length || len != signatures.length) {
            revert("AgentCardVerifierRouter: mismatched array lengths");
        }

        results = new VerificationResult[](len);
        bytes32 sep = _domainSeparatorV4();

        for (uint256 i = 0; i < len; i++) {
            AgentCardVerifier.AgentRegistrationClaim memory libClaim = _toLibClaim(claims[i]);
            results[i].claim = claims[i];

            try this._tryVerify(sep, libClaim, claimedOwners[i], signatures[i]) returns (
                bool isValid, address recovered
            ) {
                results[i].isValid = isValid;
                results[i].signer = recovered;
            } catch {
                results[i].isValid = false;
                results[i].signer = address(0);
            }
        }
    }

    /// @notice Internal helper for batch try/catch — do not call directly.
    /// @dev Must be external so it can be used with `try this.`.
    function _tryVerify(
        bytes32 sep,
        AgentCardVerifier.AgentRegistrationClaim calldata libClaim,
        address claimedOwner,
        bytes calldata signature
    ) external view returns (bool isValid, address recovered) {
        isValid = AgentCardVerifier._verifyRegistrationClaim(sep, libClaim, claimedOwner, signature);
        if (isValid) {
            // Only attempt recovery for ECDSA (65-byte) signatures
            if (signature.length == 65) {
                try this._tryRecover(sep, libClaim, signature) returns (address r) {
                    recovered = r;
                } catch {
                    recovered = claimedOwner;
                }
            } else {
                recovered = claimedOwner;
            }
        }
    }

    /// @notice Internal helper for ECDSA recovery — do not call directly.
    function _tryRecover(
        bytes32 sep,
        AgentCardVerifier.AgentRegistrationClaim calldata libClaim,
        bytes calldata signature
    ) external view returns (address) {
        return AgentCardVerifier._recoverClaimSigner(sep, libClaim, signature);
    }

    // ──────────────────────────────────────────────
    //  EIP-712 helpers
    // ──────────────────────────────────────────────

    /// @notice Returns the EIP-712 domain separator used by this verifier.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Returns the EIP-712 struct hash for a registration claim.
    function hashClaim(AgentRegistrationClaim calldata claim) external pure returns (bytes32) {
        return AgentCardVerifier._hashClaim(AgentCardVerifier.AgentRegistrationClaim({
            chainId: claim.chainId,
            registryAddress: claim.registryAddress,
            agentId: claim.agentId,
            deadline: claim.deadline
        }));
    }

    /// @notice Returns the full EIP-712 typed data hash (domain + struct) — the signing digest.
    function hashTypedData(AgentRegistrationClaim calldata claim) external view returns (bytes32) {
        return AgentCardVerifier._hashTypedData(_domainSeparatorV4(), AgentCardVerifier.AgentRegistrationClaim({
            chainId: claim.chainId,
            registryAddress: claim.registryAddress,
            agentId: claim.agentId,
            deadline: claim.deadline
        }));
    }
}
