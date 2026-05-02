// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {AgentCardVerifierRouter} from "src/AgentCardVerifierRouter.sol";

/// @notice Integration tests forking Base Sepolia to verify the Router against real chain state.
///
/// Run with:
///   forge test --match-path test/AgentCardVerifier.integration.t.sol \
///     --fork-url $BASE_SEPOLIA_RPC -vv
contract AgentCardVerifierIntegrationTest is Test {
    /// @dev ERC-8004 Identity Registry on Base Sepolia (and all testnets via CREATE2).
    address internal constant BASE_SEPOLIA_REGISTRY = 0x8004A818BFB912233c491871b3d84c89A494BD9e;

    /// @dev Base Sepolia chain ID.
    uint256 internal constant BASE_SEPOLIA_CHAIN_ID = 84532;

    AgentCardVerifierRouter internal router;
    uint256 internal signerKey = 0xA11CE;
    address internal signer;

    function setUp() public {
        // These tests require a fork — skip gracefully when no RPC is available.
        // The fork-url flag sets block.chainid to the remote chain's value.
        router = new AgentCardVerifierRouter();
        signer = vm.addr(signerKey);
    }

    /// @notice Create a claim using the real Base Sepolia Identity Registry address,
    ///         sign it with a known key, and verify it through the Router.
    function test_Integration_VerifyClaimForRealRegistry() public view {
        // Skip if not on a Base Sepolia fork
        if (block.chainid != BASE_SEPOLIA_CHAIN_ID) {
            return;
        }

        AgentCardVerifierRouter.AgentRegistrationClaim memory claim =
            AgentCardVerifierRouter.AgentRegistrationClaim({
                chainId: BASE_SEPOLIA_CHAIN_ID,
                registryAddress: BASE_SEPOLIA_REGISTRY,
                agentId: 1,
                deadline: block.timestamp + 365 days
            });

        bytes32 digest = router.hashTypedData(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        assertTrue(router.verifyRegistrationClaim(claim, signer, sig));
        assertEq(router.recoverClaimSigner(claim, sig), signer);
    }

    /// @notice Verify the Router's domain separator matches manual computation using
    ///         Base Sepolia's chain ID.
    function test_Integration_RouterDomainSeparatorMatchesChain() public view {
        // Skip if not on a Base Sepolia fork
        if (block.chainid != BASE_SEPOLIA_CHAIN_ID) {
            return;
        }

        bytes32 expected = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("AgentCardVerifier")),
                keccak256(bytes("1")),
                BASE_SEPOLIA_CHAIN_ID,
                address(router)
            )
        );

        assertEq(router.domainSeparator(), expected);
    }

    /// @notice Ensure integration tests run in isolation even without a fork,
    ///         verifying basic claim construction works on any chain.
    function test_Integration_BaselineClaimVerification() public view {
        uint256 chainId = block.chainid;
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim =
            AgentCardVerifierRouter.AgentRegistrationClaim({
                chainId: chainId,
                registryAddress: BASE_SEPOLIA_REGISTRY,
                agentId: 99,
                deadline: block.timestamp + 30 days
            });

        bytes32 digest = router.hashTypedData(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        assertTrue(router.verifyRegistrationClaim(claim, signer, sig));
    }
}
