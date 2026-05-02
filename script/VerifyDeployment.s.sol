// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {AgentCardVerifierRouter} from "src/AgentCardVerifierRouter.sol";

/// @notice Read-only script for verifying a deployed AgentCardVerifierRouter.
///         Reads domain separator and sample hash — no transactions.
///
/// Usage:
///   forge script script/VerifyDeployment.s.sol \
///     --rpc-url $RPC_URL \
///     --sig "run(address)" <ROUTER_ADDRESS>
contract VerifyDeployment is Script {
    function run(address routerAddress) external view {
        require(routerAddress != address(0), "VerifyDeployment: zero address");
        require(routerAddress.code.length > 0, "VerifyDeployment: no code at address");

        AgentCardVerifierRouter router = AgentCardVerifierRouter(routerAddress);

        console2.log("=== AgentCardVerifierRouter Verification ===");
        console2.log("Router address:", routerAddress);
        console2.log("Chain ID:      ", block.chainid);

        // Verify domain separator
        bytes32 sep = router.domainSeparator();
        console2.log("Domain separator:", vm.toString(sep));

        // Manually verify it matches expected construction
        bytes32 expected = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("AgentCardVerifier")),
                keccak256(bytes("1")),
                block.chainid,
                routerAddress
            )
        );
        bool domainOk = sep == expected;
        console2.log("Domain separator matches expected:", domainOk);
        require(domainOk, "VerifyDeployment: domain separator mismatch");

        // Verify hashTypedData with a test claim
        AgentCardVerifierRouter.AgentRegistrationClaim memory testClaim =
            AgentCardVerifierRouter.AgentRegistrationClaim({
                chainId: 1,
                registryAddress: 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432,
                agentId: 42,
                deadline: 1_767_225_600
            });

        bytes32 typedHash = router.hashTypedData(testClaim);
        bytes32 structHash = router.hashClaim(testClaim);
        console2.log("Test claim struct hash:", vm.toString(structHash));
        console2.log("Test claim typed hash: ", vm.toString(typedHash));

        // Verify struct hash matches manual computation
        bytes32 typehash = keccak256(
            "AgentRegistrationClaim(uint256 chainId,address registryAddress,uint256 agentId,uint256 deadline)"
        );
        bytes32 expectedStructHash = keccak256(
            abi.encode(
                typehash,
                testClaim.chainId,
                testClaim.registryAddress,
                testClaim.agentId,
                testClaim.deadline
            )
        );
        bool structOk = structHash == expectedStructHash;
        console2.log("Struct hash matches expected:", structOk);
        require(structOk, "VerifyDeployment: struct hash mismatch");

        console2.log("=== Verification PASSED ===");
    }
}
