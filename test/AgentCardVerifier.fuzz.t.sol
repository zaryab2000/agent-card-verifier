// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {AgentCardVerifierRouter} from "src/AgentCardVerifierRouter.sol";

/// @notice Fuzz tests verifying core invariants of the AgentCardVerifier library.
contract AgentCardVerifierFuzzTest is Test {
    AgentCardVerifierRouter internal router;

    function setUp() public {
        router = new AgentCardVerifierRouter();
    }

    // ──────────────────────────────────────────────
    //  Helpers
    // ──────────────────────────────────────────────

    function _boundKey(uint256 key) internal pure returns (uint256) {
        return bound(key, 1, SECP256K1_ORDER - 1);
    }

    function _makeClaim(
        uint256 chainId,
        address registry,
        uint256 agentId,
        uint256 deadline
    ) internal pure returns (AgentCardVerifierRouter.AgentRegistrationClaim memory) {
        return AgentCardVerifierRouter.AgentRegistrationClaim({
            chainId: chainId,
            registryAddress: registry,
            agentId: agentId,
            deadline: deadline
        });
    }

    function _signClaim(
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim,
        uint256 key
    ) internal view returns (bytes memory) {
        bytes32 digest = router.hashTypedData(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    // ──────────────────────────────────────────────
    //  Fuzz invariants
    // ──────────────────────────────────────────────

    /// @notice For any valid private key, signing a claim and verifying against the
    ///         derived address always returns true.
    function testFuzz_VerifyRegistrationClaim_RandomKey_MatchesSigner(
        uint256 privateKey,
        uint256 chainId,
        address registry,
        uint256 agentId,
        uint256 deadline
    ) public view {
        privateKey = _boundKey(privateKey);
        chainId = bound(chainId, 1, type(uint256).max);
        vm.assume(registry != address(0));
        deadline = bound(deadline, block.timestamp, type(uint256).max);

        address owner = vm.addr(privateKey);
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim =
            _makeClaim(chainId, registry, agentId, deadline);
        bytes memory sig = _signClaim(claim, privateKey);

        assertTrue(router.verifyRegistrationClaim(claim, owner, sig));
    }

    /// @notice Recovered signer always matches vm.addr(privateKey).
    function testFuzz_RecoverClaimSigner_MatchesAddress(uint256 privateKey, uint256 agentId)
        public
        view
    {
        privateKey = _boundKey(privateKey);
        address expected = vm.addr(privateKey);

        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _makeClaim(
            1,
            address(0x8004A169FB4a3325136EB29fA0ceB6D2e539a432),
            agentId,
            block.timestamp + 1 days
        );
        bytes memory sig = _signClaim(claim, privateKey);

        assertEq(router.recoverClaimSigner(claim, sig), expected);
    }

    /// @notice If agentIdA != agentIdB, typed data hashes differ.
    function testFuzz_HashTypedData_NeverCollides(uint256 agentIdA, uint256 agentIdB)
        public
        view
    {
        vm.assume(agentIdA != agentIdB);

        address registry = address(0x8004A169FB4a3325136EB29fA0ceB6D2e539a432);
        uint256 deadline = block.timestamp + 1 days;

        AgentCardVerifierRouter.AgentRegistrationClaim memory claimA =
            _makeClaim(1, registry, agentIdA, deadline);
        AgentCardVerifierRouter.AgentRegistrationClaim memory claimB =
            _makeClaim(1, registry, agentIdB, deadline);

        assertTrue(router.hashTypedData(claimA) != router.hashTypedData(claimB));
    }

    /// @notice If signerKey != claimedKey, verification always returns false.
    function testFuzz_VerifyRegistrationClaim_WrongKey_NeverPasses(
        uint256 signerKey,
        uint256 claimedKey,
        uint256 agentId
    ) public view {
        signerKey = _boundKey(signerKey);
        claimedKey = _boundKey(claimedKey);
        vm.assume(signerKey != claimedKey);

        address claimedOwner = vm.addr(claimedKey);

        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _makeClaim(
            1,
            address(0x8004A169FB4a3325136EB29fA0ceB6D2e539a432),
            agentId,
            block.timestamp + 1 days
        );
        bytes memory sig = _signClaim(claim, signerKey);

        assertFalse(router.verifyRegistrationClaim(claim, claimedOwner, sig));
    }
}
