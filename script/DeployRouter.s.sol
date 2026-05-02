// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {AgentCardVerifierRouter} from "src/AgentCardVerifierRouter.sol";

/// @notice Deploys AgentCardVerifierRouter via CREATE2 using the Safe Singleton Factory
///         so the Router gets the same address on every EVM chain with the same salt.
///
/// Usage:
///   forge script script/DeployRouter.s.sol \
///     --rpc-url $RPC_URL \
///     --private-key $DEPLOYER_KEY \
///     --broadcast
///
/// The DEPLOYER_KEY must have ETH on the target chain to cover gas.
contract DeployRouter is Script {
    /// @dev Safe Singleton Factory — deployed at the same address on all EVM chains.
    address internal constant SAFE_SINGLETON_FACTORY = 0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7;

    /// @dev Deterministic salt. Change only to deploy a new instance.
    bytes32 internal constant SALT =
        keccak256(abi.encodePacked("AgentCardVerifier", "v1", "2025"));

    function run() external {
        bytes memory creationCode = type(AgentCardVerifierRouter).creationCode;
        bytes memory payload = abi.encodePacked(SALT, creationCode);

        // Predict the CREATE2 address before deploying
        address predicted = _computeCreate2Address(SALT, keccak256(creationCode));
        console2.log("Predicted Router address:", predicted);
        console2.log("Chain ID:", block.chainid);

        // If already deployed, skip
        if (predicted.code.length > 0) {
            console2.log("Router already deployed at:", predicted);
            _logInfo(AgentCardVerifierRouter(predicted));
            return;
        }

        vm.startBroadcast();
        (bool success, bytes memory result) = SAFE_SINGLETON_FACTORY.call(payload);
        vm.stopBroadcast();

        require(success, "DeployRouter: CREATE2 deployment failed");

        address deployed;
        assembly {
            deployed := mload(add(result, 20))
        }

        require(deployed != address(0), "DeployRouter: zero address returned");
        require(deployed == predicted, "DeployRouter: address mismatch");

        console2.log("Router deployed at:", deployed);
        _logInfo(AgentCardVerifierRouter(deployed));
    }

    function _logInfo(AgentCardVerifierRouter router) internal view {
        console2.log("Domain separator:", vm.toString(router.domainSeparator()));

        // Log a sample hashTypedData for manual verification
        AgentCardVerifierRouter.AgentRegistrationClaim memory sample =
            AgentCardVerifierRouter.AgentRegistrationClaim({
                chainId: block.chainid,
                registryAddress: 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432,
                agentId: 1,
                deadline: block.timestamp + 365 days
            });
        console2.log("Sample hashTypedData:", vm.toString(router.hashTypedData(sample)));
    }

    /// @dev Computes the CREATE2 address for the Safe Singleton Factory pattern.
    function _computeCreate2Address(bytes32 salt, bytes32 initCodeHash)
        internal
        pure
        returns (address)
    {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(bytes1(0xff), SAFE_SINGLETON_FACTORY, salt, initCodeHash)
                    )
                )
            )
        );
    }
}
