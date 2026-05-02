# Agent Card Verifier Library

A Solidity library and deployed router contract that verifies cross-chain agent registration claims from ERC-8004 Agent Registration Files. Agent owners sign EIP-712 typed data asserting ownership of `(chainId, registryAddress, agentId)` tuples; any smart contract can verify those signatures on-chain, turning the currently self-asserted `registrations[]` array into a cryptographically verifiable identity linkage. Supports both EOA (ECDSA) and smart contract wallets (ERC-1271).

See [PRD.md](PRD.md) for full specification.

---

## Architecture

```
AgentCardVerifier.sol        — stateless library (inline into any contract)
AgentCardVerifierRouter.sol  — deployed wrapper (external calls for already-deployed contracts)
```

The Router uses EIP-712 with domain `("AgentCardVerifier", "1", block.chainid, address(router))`. Each Router deployment produces a unique domain separator, binding signatures to a specific deployment.

## Quick Start

```bash
# Install
forge install

# Build
forge build

# Test (unit + fuzz + integration)
forge test -vv

# Gas report
forge test --gas-report
```

## Usage — Library (inline)

```solidity
import {AgentCardVerifier} from "src/AgentCardVerifier.sol";

contract MyContract {
    bytes32 private immutable DOMAIN_SEP;

    constructor() {
        DOMAIN_SEP = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("AgentCardVerifier"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    function checkAgent(
        AgentCardVerifier.AgentRegistrationClaim calldata claim,
        address claimedOwner,
        bytes calldata sig
    ) external view returns (bool) {
        return AgentCardVerifier._verifyRegistrationClaim(DOMAIN_SEP, claim, claimedOwner, sig);
    }
}
```

## Usage — Router (external call)

```solidity
IAgentCardVerifierRouter router = IAgentCardVerifierRouter(ROUTER_ADDRESS);

bool valid = router.verifyRegistrationClaim(
    IAgentCardVerifierRouter.AgentRegistrationClaim({
        chainId: 1,
        registryAddress: 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432,
        agentId: 42,
        deadline: block.timestamp + 365 days
    }),
    claimedOwner,
    signature
);
```

## AgentRegistrationClaim struct

```solidity
struct AgentRegistrationClaim {
    uint256 chainId;         // chain where the agent is registered
    address registryAddress; // Identity Registry on that chain
    uint256 agentId;         // ERC-721 token ID
    uint256 deadline;        // expiry timestamp (Unix)
}
```

EIP-712 typehash:
```
AgentRegistrationClaim(uint256 chainId,address registryAddress,uint256 agentId,uint256 deadline)
```

## Deployment

Uses CREATE2 via the Safe Singleton Factory (`0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7`) for a deterministic address across all EVM chains.

```bash
forge script script/DeployRouter.s.sol \
  --rpc-url $RPC_URL \
  --private-key $DEPLOYER_KEY \
  --broadcast
```

Verify a deployment:

```bash
forge script script/VerifyDeployment.s.sol \
  --rpc-url $RPC_URL \
  --sig "run(address)" <ROUTER_ADDRESS>
```

## Integration tests (fork)

```bash
forge test --match-path test/AgentCardVerifier.integration.t.sol \
  --fork-url $BASE_SEPOLIA_RPC -vv
```

## Known registries

| Network | Chain ID | Address |
|---|---|---|
| Ethereum mainnet | 1 | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` |
| Base mainnet | 8453 | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` |
| Ethereum Sepolia | 11155111 | `0x8004A818BFB912233c491871b3d84c89A494BD9e` |
| Base Sepolia | 84532 | `0x8004A818BFB912233c491871b3d84c89A494BD9e` |

## Security

- Signatures are bound to a specific Router via EIP-712 domain — no cross-Router replay
- `deadline` prevents indefinite reuse of stale signatures
- ERC-1271 checks use `staticcall` — reentrancy-safe
- ECDSA uses OZ `tryRecover` — rejects malleable signatures and zero-address recovery
- v1 is signature-only; no on-chain `ownerOf` check (by design — see PRD §3e S7)

## License

MIT
