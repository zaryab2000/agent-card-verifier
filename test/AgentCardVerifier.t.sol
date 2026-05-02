// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {AgentCardVerifierRouter} from "src/AgentCardVerifierRouter.sol";
import {AgentCardVerifier} from "src/AgentCardVerifier.sol";
import {MockERC1271Wallet} from "./mocks/MockERC1271Wallet.sol";

contract AgentCardVerifierTest is Test {
    AgentCardVerifierRouter internal router;

    // Test fixtures
    uint256 internal signerKey = 0xA11CE;
    address internal signer;
    uint256 internal constant CHAIN_ID = 1;
    address internal constant REGISTRY = 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432;
    uint256 internal constant AGENT_ID = 42;

    function setUp() public {
        router = new AgentCardVerifierRouter();
        signer = vm.addr(signerKey);
    }

    // ──────────────────────────────────────────────
    //  Helpers
    // ──────────────────────────────────────────────

    function _makeClaim(uint256 chainId, address registry, uint256 agentId, uint256 deadline)
        internal
        pure
        returns (AgentCardVerifierRouter.AgentRegistrationClaim memory)
    {
        return AgentCardVerifierRouter.AgentRegistrationClaim({
            chainId: chainId,
            registryAddress: registry,
            agentId: agentId,
            deadline: deadline
        });
    }

    function _sign(AgentCardVerifierRouter.AgentRegistrationClaim memory claim, uint256 key)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = router.hashTypedData(claim);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _defaultClaim() internal view returns (AgentCardVerifierRouter.AgentRegistrationClaim memory) {
        return _makeClaim(CHAIN_ID, REGISTRY, AGENT_ID, block.timestamp + 1 days);
    }

    // ──────────────────────────────────────────────
    //  ECDSA path
    // ──────────────────────────────────────────────

    function test_VerifyRegistrationClaim_ValidEOASignature_ReturnsTrue() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _defaultClaim();
        bytes memory sig = _sign(claim, signerKey);
        assertTrue(router.verifyRegistrationClaim(claim, signer, sig));
    }

    function test_VerifyRegistrationClaim_WrongSigner_ReturnsFalse() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _defaultClaim();
        bytes memory sig = _sign(claim, signerKey);
        address wrongOwner = vm.addr(0xBEEF);
        assertFalse(router.verifyRegistrationClaim(claim, wrongOwner, sig));
    }

    function test_VerifyRegistrationClaim_ExpiredDeadline_Reverts() public {
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim =
            _makeClaim(CHAIN_ID, REGISTRY, AGENT_ID, block.timestamp - 1);
        bytes memory sig = _sign(claim, signerKey);
        vm.expectRevert(
            abi.encodeWithSelector(
                AgentCardVerifier.ClaimExpired.selector, block.timestamp - 1, block.timestamp
            )
        );
        router.verifyRegistrationClaim(claim, signer, sig);
    }

    function test_VerifyRegistrationClaim_ZeroChainId_Reverts() public {
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim =
            _makeClaim(0, REGISTRY, AGENT_ID, block.timestamp + 1 days);
        bytes memory sig = _sign(claim, signerKey);
        vm.expectRevert(AgentCardVerifier.InvalidChainId.selector);
        router.verifyRegistrationClaim(claim, signer, sig);
    }

    function test_VerifyRegistrationClaim_ZeroRegistryAddress_Reverts() public {
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim =
            _makeClaim(CHAIN_ID, address(0), AGENT_ID, block.timestamp + 1 days);
        bytes memory sig = _sign(claim, signerKey);
        vm.expectRevert(AgentCardVerifier.InvalidRegistryAddress.selector);
        router.verifyRegistrationClaim(claim, signer, sig);
    }

    function test_VerifyRegistrationClaim_TamperedChainId_ReturnsFalse() public view {
        // Sign for chainId=1, verify with chainId=8453
        AgentCardVerifierRouter.AgentRegistrationClaim memory signedClaim =
            _makeClaim(1, REGISTRY, AGENT_ID, block.timestamp + 1 days);
        bytes memory sig = _sign(signedClaim, signerKey);

        AgentCardVerifierRouter.AgentRegistrationClaim memory tamperedClaim =
            _makeClaim(8453, REGISTRY, AGENT_ID, block.timestamp + 1 days);
        assertFalse(router.verifyRegistrationClaim(tamperedClaim, signer, sig));
    }

    function test_VerifyRegistrationClaim_TamperedAgentId_ReturnsFalse() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim memory signedClaim =
            _makeClaim(CHAIN_ID, REGISTRY, 42, block.timestamp + 1 days);
        bytes memory sig = _sign(signedClaim, signerKey);

        AgentCardVerifierRouter.AgentRegistrationClaim memory tamperedClaim =
            _makeClaim(CHAIN_ID, REGISTRY, 43, block.timestamp + 1 days);
        assertFalse(router.verifyRegistrationClaim(tamperedClaim, signer, sig));
    }

    function test_VerifyRegistrationClaim_TamperedRegistryAddress_ReturnsFalse() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim memory signedClaim =
            _makeClaim(CHAIN_ID, REGISTRY, AGENT_ID, block.timestamp + 1 days);
        bytes memory sig = _sign(signedClaim, signerKey);

        AgentCardVerifierRouter.AgentRegistrationClaim memory tamperedClaim =
            _makeClaim(CHAIN_ID, address(0xDEAD), AGENT_ID, block.timestamp + 1 days);
        assertFalse(router.verifyRegistrationClaim(tamperedClaim, signer, sig));
    }

    function test_VerifyRegistrationClaim_MalleableSignature_ReturnsFalse() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _defaultClaim();
        bytes memory sig = _sign(claim, signerKey);

        // Flip s to upper half of curve order (malleable)
        bytes32 secp256k1N =
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 s;
        assembly {
            s := mload(add(sig, 0x40))
        }
        bytes32 mallS = bytes32(uint256(secp256k1N) - uint256(s));
        assembly {
            mstore(add(sig, 0x40), mallS)
        }
        // Also flip v
        uint8 v = uint8(sig[64]);
        sig[64] = bytes1(v == 27 ? 28 : 27);

        assertFalse(router.verifyRegistrationClaim(claim, signer, sig));
    }

    function test_VerifyRegistrationClaim_EmptySignature_Reverts() public {
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _defaultClaim();
        vm.expectRevert(
            abi.encodeWithSelector(AgentCardVerifier.InvalidSignatureLength.selector, 0)
        );
        router.verifyRegistrationClaim(claim, signer, "");
    }

    function test_VerifyRegistrationClaim_DeadlineExactlyNow_ReturnsTrue() public view {
        // deadline == block.timestamp should pass (not > deadline)
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim =
            _makeClaim(CHAIN_ID, REGISTRY, AGENT_ID, block.timestamp);
        bytes memory sig = _sign(claim, signerKey);
        assertTrue(router.verifyRegistrationClaim(claim, signer, sig));
    }

    function test_VerifyRegistrationClaim_MaxAgentId_ReturnsTrue() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim =
            _makeClaim(CHAIN_ID, REGISTRY, type(uint256).max, block.timestamp + 1 days);
        bytes memory sig = _sign(claim, signerKey);
        assertTrue(router.verifyRegistrationClaim(claim, signer, sig));
    }

    // ──────────────────────────────────────────────
    //  recoverClaimSigner
    // ──────────────────────────────────────────────

    function test_RecoverClaimSigner_ValidSignature_RecoversSigner() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _defaultClaim();
        bytes memory sig = _sign(claim, signerKey);
        assertEq(router.recoverClaimSigner(claim, sig), signer);
    }

    function test_RecoverClaimSigner_InvalidSignature_Reverts() public {
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _defaultClaim();
        bytes memory badSig = new bytes(65); // all zeros — invalid sig
        vm.expectRevert();
        router.recoverClaimSigner(claim, badSig);
    }

    // ──────────────────────────────────────────────
    //  hashTypedData
    // ──────────────────────────────────────────────

    function test_HashTypedData_DeterministicOutput() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _defaultClaim();
        bytes32 h1 = router.hashTypedData(claim);
        bytes32 h2 = router.hashTypedData(claim);
        assertEq(h1, h2);
    }

    function test_HashTypedData_DifferentClaims_DifferentHashes() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim memory c1 =
            _makeClaim(CHAIN_ID, REGISTRY, 42, block.timestamp + 1 days);
        AgentCardVerifierRouter.AgentRegistrationClaim memory c2 =
            _makeClaim(CHAIN_ID, REGISTRY, 43, block.timestamp + 1 days);
        assertTrue(router.hashTypedData(c1) != router.hashTypedData(c2));
    }

    // ──────────────────────────────────────────────
    //  ERC-1271 path
    // ──────────────────────────────────────────────

    function test_VerifyRegistrationClaim_ValidERC1271Wallet_ReturnsTrue() public {
        MockERC1271Wallet wallet = new MockERC1271Wallet(MockERC1271Wallet.Mode.Approve);
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _defaultClaim();
        bytes32 digest = router.hashTypedData(claim);
        wallet.setApprovedDigest(digest);

        bytes memory sig = new bytes(65); // dummy sig — wallet ignores it
        assertTrue(router.verifyRegistrationClaim(claim, address(wallet), sig));
    }

    function test_VerifyRegistrationClaim_ERC1271WalletRejects_ReturnsFalse() public {
        MockERC1271Wallet wallet = new MockERC1271Wallet(MockERC1271Wallet.Mode.Reject);
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _defaultClaim();
        bytes memory sig = new bytes(65);
        assertFalse(router.verifyRegistrationClaim(claim, address(wallet), sig));
    }

    function test_VerifyRegistrationClaim_ERC1271WalletReverts_ReturnsFalse() public {
        MockERC1271Wallet wallet = new MockERC1271Wallet(MockERC1271Wallet.Mode.Revert);
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _defaultClaim();
        bytes memory sig = new bytes(65);
        assertFalse(router.verifyRegistrationClaim(claim, address(wallet), sig));
    }

    function test_VerifyRegistrationClaim_NonContractAsERC1271_ReturnsFalse() public view {
        // claimedOwner is an EOA that didn't sign — ECDSA fails, no code for ERC-1271
        address randomEoa = vm.addr(0xCAFE);
        AgentCardVerifierRouter.AgentRegistrationClaim memory claim = _defaultClaim();
        bytes memory sig = _sign(claim, signerKey); // signed by different key
        assertFalse(router.verifyRegistrationClaim(claim, randomEoa, sig));
    }

    // ──────────────────────────────────────────────
    //  Batch
    // ──────────────────────────────────────────────

    function test_VerifyBatch_AllValid_AllReturnTrue() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim[] memory claims =
            new AgentCardVerifierRouter.AgentRegistrationClaim[](3);
        address[] memory owners = new address[](3);
        bytes[] memory sigs = new bytes[](3);

        for (uint256 i = 0; i < 3; i++) {
            claims[i] = _makeClaim(CHAIN_ID, REGISTRY, i + 1, block.timestamp + 1 days);
            owners[i] = signer;
            sigs[i] = _sign(claims[i], signerKey);
        }

        AgentCardVerifierRouter.VerificationResult[] memory results =
            router.verifyRegistrationClaimBatch(claims, owners, sigs);

        assertEq(results.length, 3);
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(results[i].isValid);
        }
    }

    function test_VerifyBatch_MixedValidity_PartialResults() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim[] memory claims =
            new AgentCardVerifierRouter.AgentRegistrationClaim[](3);
        address[] memory owners = new address[](3);
        bytes[] memory sigs = new bytes[](3);

        // Valid claim
        claims[0] = _makeClaim(CHAIN_ID, REGISTRY, 1, block.timestamp + 1 days);
        owners[0] = signer;
        sigs[0] = _sign(claims[0], signerKey);

        // Expired claim
        claims[1] = _makeClaim(CHAIN_ID, REGISTRY, 2, block.timestamp - 1);
        owners[1] = signer;
        sigs[1] = _sign(claims[1], signerKey);

        // Wrong signer
        claims[2] = _makeClaim(CHAIN_ID, REGISTRY, 3, block.timestamp + 1 days);
        owners[2] = vm.addr(0xBEEF);
        sigs[2] = _sign(claims[2], signerKey); // signed by signerKey, not 0xBEEF

        AgentCardVerifierRouter.VerificationResult[] memory results =
            router.verifyRegistrationClaimBatch(claims, owners, sigs);

        assertEq(results.length, 3);
        assertTrue(results[0].isValid);
        assertFalse(results[1].isValid); // expired — reverts internally, caught
        assertFalse(results[2].isValid); // wrong signer
    }

    function test_VerifyBatch_EmptyArray_ReturnsEmpty() public view {
        AgentCardVerifierRouter.AgentRegistrationClaim[] memory claims =
            new AgentCardVerifierRouter.AgentRegistrationClaim[](0);
        address[] memory owners = new address[](0);
        bytes[] memory sigs = new bytes[](0);

        AgentCardVerifierRouter.VerificationResult[] memory results =
            router.verifyRegistrationClaimBatch(claims, owners, sigs);
        assertEq(results.length, 0);
    }

    function test_VerifyBatch_MismatchedLengths_Reverts() public {
        AgentCardVerifierRouter.AgentRegistrationClaim[] memory claims =
            new AgentCardVerifierRouter.AgentRegistrationClaim[](2);
        address[] memory owners = new address[](1);
        bytes[] memory sigs = new bytes[](2);

        vm.expectRevert("AgentCardVerifierRouter: mismatched array lengths");
        router.verifyRegistrationClaimBatch(claims, owners, sigs);
    }

    // ──────────────────────────────────────────────
    //  Domain separator
    // ──────────────────────────────────────────────

    function test_DomainSeparator_MatchesExpected() public view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("AgentCardVerifier")),
                keccak256(bytes("1")),
                block.chainid,
                address(router)
            )
        );
        assertEq(router.domainSeparator(), expected);
    }

    function test_DomainSeparator_DifferentRouterAddress_DifferentSeparator() public {
        AgentCardVerifierRouter router2 = new AgentCardVerifierRouter();
        assertTrue(router.domainSeparator() != router2.domainSeparator());
    }
}
