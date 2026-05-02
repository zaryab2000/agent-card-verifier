# PRD: Agent Card Verifier Library

## 1. Project Summary

A Solidity library and companion contract that verifies cross-chain agent registration claims from ERC-8004 Agent Registration Files. An agent owner signs an EIP-712 `AgentRegistrationClaim` for each chain where they hold an `agentId`; any smart contract can then verify those signatures on-chain using the library, turning the currently self-asserted `registrations[]` array into a cryptographically verifiable identity linkage. Ships as a Foundry package with deployment scripts for Base and Ethereum mainnet.

## 2. Problem Context

ERC-8004's Identity Registry is a per-chain singleton. An agent registered as `agentId=42` on Ethereum and `agentId=17` on Base has no on-chain mechanism to prove these are the same entity. The only cross-chain hook in the spec is the `registrations[]` array inside the off-chain Agent Registration File — a self-asserted JSON list with no signature, no on-chain verification, and no way for a smart contract to validate it (Limitation (a): Identity fragmentation — P0; Limitation (e): Agent Card centralization risk — P1).

Every cross-chain identity solution in the 8004 ecosystem today (8004scan, 8k4 API, Agent Arena) aggregates this off-chain JSON via indexers. None provides on-chain verifiability. The Agent Card Verifier closes this gap: it defines a signature scheme that agent owners use to assert "I own this agentId on this chain," and a verification library that any contract can call to check those assertions without trusting an off-chain intermediary.

The IdentityRegistry's existing EIP-712 usage (`AgentWalletSet` typed data) proves wallet ownership, not registration ownership. A new typed data struct is needed for registration claims.

## 3. Technical Specification

### 3a. Architecture Overview

The system has three components:

```
┌─────────────────────────────────────────────────────────────┐
│                    Off-Chain (Agent Owner)                   │
│                                                             │
│  1. Agent owns agentId=42 on Ethereum, agentId=17 on Base   │
│  2. Signs AgentRegistrationClaim for each (chainId,         │
│     registryAddress, agentId) with EIP-712                  │
│  3. Publishes signatures in Agent Registration File:        │
│     chainRegistrations[{ chainId, registryAddress,          │
│     agentId, deadline, signature }]                         │
└─────────────────────┬───────────────────────────────────────┘
                      │ signatures passed as calldata
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                 On-Chain (Any EVM Chain)                     │
│                                                             │
│  AgentCardVerifier.sol (library, stateless)                  │
│  ├── verifyRegistrationClaim() — ECDSA verification         │
│  ├── verifyRegistrationClaimERC1271() — smart wallet verify  │
│  ├── verifyRegistrationClaim() — auto-detect EOA vs contract │
│  └── recoverClaimSigner() — recover signer from claim sig   │
│                                                             │
│  AgentCardVerifierRouter.sol (deployed contract, stateless)  │
│  └── Exposes library functions as external calls for         │
│      contracts that cannot link libraries directly           │
└─────────────────────────────────────────────────────────────┘
```

**On-chain components:**
- `AgentCardVerifier.sol` — a Solidity `library` with `internal` functions. Contracts that import it inline the verification logic (no delegatecall, no external dependency). This is the primary deliverable.
- `AgentCardVerifierRouter.sol` — a thin deployed contract that wraps the library's functions as `external view` calls. Exists for contracts that cannot link the library at compile time (e.g., already-deployed contracts, contracts using different frameworks). Stateless, no owner, no upgradeability.

**Off-chain components:**
- A proposed `chainRegistrations[]` extension to the Agent Registration File JSON schema. This is documentation only — no off-chain tooling is in scope for v1.

**External dependencies:**
- OpenZeppelin's `ECDSA` and `IERC1271` for signature handling.
- ERC-8004 Identity Registry (read-only reference — the library does not call it; the library is purely signature-based with no on-chain state reads in v1).

### 3b. Smart Contract Interfaces

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IAgentCardVerifierRouter
/// @notice Deployed contract interface for verifying ERC-8004
///         cross-chain registration claims via EIP-712 signatures.
///         Wraps the AgentCardVerifier library for external access.
interface IAgentCardVerifierRouter {

    /// @notice Typed data for an agent registration claim.
    /// @param chainId The chain ID where the agent is registered.
    /// @param registryAddress The Identity Registry contract on that chain.
    /// @param agentId The ERC-721 token ID in that registry.
    /// @param deadline Unix timestamp after which the claim signature
    ///        expires. Prevents indefinite replay of stale claims.
    struct AgentRegistrationClaim {
        uint256 chainId;
        address registryAddress;
        uint256 agentId;
        uint256 deadline;
    }

    /// @notice Result of a batch verification call.
    /// @param claim The original claim that was verified.
    /// @param isValid Whether the signature is valid for this claim.
    /// @param signer The recovered signer address (address(0) if invalid).
    struct VerificationResult {
        AgentRegistrationClaim claim;
        bool isValid;
        address signer;
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
    //  Core verification
    // ──────────────────────────────────────────────

    /// @notice Verify a registration claim signature against a claimed owner.
    ///         Supports both EOA (ECDSA) and smart contract wallets (ERC-1271).
    ///         For EOAs, recovers the signer via ECDSA and compares.
    ///         For smart wallets, calls isValidSignature on the claimedOwner.
    ///         Reverts if the claim is expired or malformed.
    /// @param claim The registration claim to verify.
    /// @param claimedOwner The address that allegedly signed the claim.
    /// @param signature The EIP-712 signature bytes.
    /// @return valid True if the signature is valid for the claimedOwner.
    function verifyRegistrationClaim(
        AgentRegistrationClaim calldata claim,
        address claimedOwner,
        bytes calldata signature
    ) external view returns (bool valid);

    /// @notice Recover the signer address from a registration claim signature.
    ///         Only works for ECDSA signatures (EOAs).
    ///         Reverts if the claim is expired, malformed, or the signature
    ///         does not recover to a valid address.
    /// @param claim The registration claim.
    /// @param signature The EIP-712 signature bytes (65 bytes: r, s, v).
    /// @return signer The recovered signer address.
    function recoverClaimSigner(
        AgentRegistrationClaim calldata claim,
        bytes calldata signature
    ) external view returns (address signer);

    /// @notice Verify multiple registration claims in a single call.
    ///         Does not revert on individual failures — returns per-claim
    ///         results. Reverts only on malformed input (mismatched array
    ///         lengths).
    /// @param claims Array of registration claims.
    /// @param claimedOwners Array of claimed owner addresses (same length).
    /// @param signatures Array of signatures (same length).
    /// @return results Array of verification results.
    function verifyRegistrationClaimBatch(
        AgentRegistrationClaim[] calldata claims,
        address[] calldata claimedOwners,
        bytes[] calldata signatures
    ) external view returns (VerificationResult[] memory results);

    // ──────────────────────────────────────────────
    //  EIP-712 helpers
    // ──────────────────────────────────────────────

    /// @notice Returns the EIP-712 domain separator used by this verifier.
    /// @return The domain separator bytes32.
    function domainSeparator() external view returns (bytes32);

    /// @notice Returns the EIP-712 hash of a registration claim struct.
    /// @param claim The claim to hash.
    /// @return The struct hash.
    function hashClaim(
        AgentRegistrationClaim calldata claim
    ) external pure returns (bytes32);

    /// @notice Returns the full EIP-712 typed data hash (domain + struct).
    ///         This is the digest that must be signed by the agent owner.
    /// @param claim The claim to hash.
    /// @return The typed data hash (the signing digest).
    function hashTypedData(
        AgentRegistrationClaim calldata claim
    ) external view returns (bytes32);
}
```

### 3c. Data Structures and Storage Layout

**The library is stateless. There are no storage variables.** All functions are `pure` or `view` (the `view` functions only read `address(this)` for domain separator construction and perform `staticcall` for ERC-1271).

**EIP-712 Domain:**

```solidity
EIP712Domain(
    string name,      // "AgentCardVerifier"
    string version,   // "1"
    uint256 chainId,  // block.chainid (chain where Router is deployed)
    address verifyingContract // address of the Router contract
)
```

Design decision: the domain uses the Router's deployed address and the deployment chain's `chainId`. The claim struct itself contains the `chainId` and `registryAddress` of the *target* chain (the chain where the agent is registered). This means:

- A signature is bound to a specific Router deployment.
- The target chain info lives in the struct, not the domain.
- To verify on a different chain, deploy another Router there — the signatures are per-Router.

This is the standard EIP-712 pattern. The alternative (domain with `verifyingContract = address(0)`, fixed `chainId = 1`) was considered but rejected because ERC-1271 smart wallets often validate against the requesting contract's domain, and `address(0)` breaks this assumption.

**Impact on cross-chain use:** An agent owner must sign separate claims per Router deployment (one for Base Router, one for Ethereum Router). This is acceptable because: (a) signing is free, (b) an agent typically signs claims for all their registrations once and includes them in their Agent Card, (c) this prevents a signature intended for one chain's verifier from being replayed on another.

**EIP-712 Typed Data:**

```solidity
bytes32 constant CLAIM_TYPEHASH = keccak256(
    "AgentRegistrationClaim(uint256 chainId,address registryAddress,uint256 agentId,uint256 deadline)"
);
```

**Struct hash construction:**

```solidity
keccak256(abi.encode(
    CLAIM_TYPEHASH,
    claim.chainId,
    claim.registryAddress,
    claim.agentId,
    claim.deadline
))
```

**Proposed Agent Registration File Extension:**

```json
{
  "type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
  "name": "myAgent",
  "chainRegistrations": [
    {
      "chainId": 1,
      "registryAddress": "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
      "agentId": 42,
      "deadline": 1767225600,
      "verifierRouter": "0x<RouterAddressOnEthereum>",
      "signature": "0x<65-byte EIP-712 signature>"
    },
    {
      "chainId": 8453,
      "registryAddress": "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
      "agentId": 17,
      "deadline": 1767225600,
      "verifierRouter": "0x<RouterAddressOnBase>",
      "signature": "0x<65-byte EIP-712 signature>"
    }
  ],
  "registrations": []
}
```

### 3d. External Dependencies

| Dependency | Address / Version | Interface Used | Trust Assumption |
|---|---|---|---|
| OpenZeppelin Contracts | v5.3.0 (latest stable, Foundry install via `forge install OpenZeppelin/openzeppelin-contracts@v5.3.0`) | `ECDSA.tryRecover()`, `IERC1271.isValidSignature()`, `EIP712` (abstract contract for domain separator) | Audited, widely used. No trust assumption beyond code correctness. |
| ERC-8004 Identity Registry (Ethereum mainnet) | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` | **Not called by the library.** Referenced only as the `registryAddress` value inside claim structs. | None — the library does not read from it. |
| ERC-8004 Identity Registry (Base mainnet) | `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` | Same as above. | None. |
| ERC-8004 Identity Registry (Ethereum Sepolia) | `0x8004A818BFB912233c491871b3d84c89A494BD9e` | Same as above. Used in tests. | None. |
| ERC-8004 Identity Registry (Base Sepolia) | `0x8004A818BFB912233c491871b3d84c89A494BD9e` | Same as above. Used in tests. | None. |

Note: the Identity Registry uses the **same address** on all mainnets (`0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`) and the same address on all testnets (`0x8004A818BFB912233c491871b3d84c89A494BD9e`), deployed via CREATE2 with vanity salts.

### 3e. Security Considerations

**S1. Signature replay across Router deployments.**
Risk: A signature created for the Base Router is replayed against the Ethereum Router.
Mitigation: The EIP-712 domain separator includes `verifyingContract` (the Router address) and `chainId` (the deployment chain). Different Router deployments produce different domain separators, making signatures non-transferable between them.

**S2. Expired claim signatures.**
Risk: An agent transfers their NFT to a new owner, but the old owner's signature is still floating in Agent Cards and cached by indexers.
Mitigation: The `deadline` field in `AgentRegistrationClaim` ensures signatures expire. The library reverts with `ClaimExpired` if `block.timestamp > deadline`. Recommended practice: agents set deadlines 6–12 months out and re-sign periodically.

**S3. ERC-1271 reentrancy via `isValidSignature`.**
Risk: A malicious smart wallet's `isValidSignature` could attempt reentrancy.
Mitigation: The library uses `staticcall` exclusively for ERC-1271 checks. `staticcall` prevents state modifications, eliminating reentrancy. The Router contract has no state to corrupt regardless.

**S4. ERC-1271 gas griefing.**
Risk: A malicious `claimedOwner` contract consumes excessive gas in `isValidSignature`, causing the verification call to run out of gas.
Mitigation: The `verifyRegistrationClaim` function forwards available gas to the `staticcall`. Callers should set appropriate gas limits. The batch function `verifyRegistrationClaimBatch` catches individual failures and returns `isValid = false` rather than reverting, preventing one bad claim from griefing the entire batch.

**S5. Signature malleability.**
Risk: ECDSA signature malleability (s-value in upper half of curve order) could allow a modified signature to pass verification.
Mitigation: OpenZeppelin's `ECDSA.tryRecover` enforces the lower-s requirement (EIP-2) and rejects malleable signatures.

**S6. Zero-address signer recovery.**
Risk: `ecrecover` returns `address(0)` for invalid signatures; comparing against a zero-address `claimedOwner` would incorrectly pass.
Mitigation: OpenZeppelin's `ECDSA.tryRecover` returns `RecoverError.InvalidSignature` when recovery yields `address(0)`. The library checks the error code before comparing addresses.

**S7. No on-chain ownership verification in v1.**
Risk: The library verifies that a signature was made by `claimedOwner`, but does not check whether `claimedOwner` currently owns `agentId` on the target chain. An agent owner could sign a claim, then transfer the NFT — the signature remains valid until `deadline`.
Mitigation: This is a deliberate v1 design choice (signature-only verification, no cross-chain reads). The `deadline` bounds the exposure window. Consumers that require real-time ownership checks should additionally call `ownerOf(agentId)` on the local chain's Identity Registry if the claimed registration is on the same chain. Cross-chain ownership checks require a bridge and are out of scope for v1.

### 3f. Gas Analysis

All gas estimates are for the Router contract's `external` functions (which include calldata decoding overhead). Library users who inline the `internal` functions will see ~2,000–3,000 gas less per call.

| Operation | Estimated Gas | Comparable Operation |
|---|---|---|
| `verifyRegistrationClaim` (ECDSA, EOA) | ~28,000–32,000 | Similar to `ECDSA.recover` (~26,000) + EIP-712 hash computation (~3,000) + calldata decoding (~2,000) |
| `verifyRegistrationClaim` (ERC-1271, smart wallet) | ~35,000–60,000 | Depends on the target contract's `isValidSignature` implementation. Gnosis Safe: ~45,000. Simple 1271: ~35,000. |
| `recoverClaimSigner` (ECDSA only) | ~27,000–30,000 | `ECDSA.recover` + hash computation |
| `verifyRegistrationClaimBatch` (N claims, ECDSA) | ~25,000 + N × 28,000 | Linear scaling. 5 claims ≈ 165,000 gas. |
| `hashTypedData` | ~3,000–4,000 | Two `keccak256` calls + `abi.encode` |
| `hashClaim` | ~1,500–2,000 | One `keccak256` + `abi.encode` |

**Economic viability:** Signature verification is a one-time or infrequent operation (called when a contract first encounters an agent's cross-chain claim, not on every interaction). At current Base gas prices (~0.01 gwei L2 fee + L1 data posting), a single `verifyRegistrationClaim` call costs < $0.01 on Base. On Ethereum mainnet at 30 gwei, the same call costs ~$0.03–0.05. These costs are negligible compared to the value of the identity verification they provide.

## 4. Implementation Guide

### Step 1: Initialize Foundry project

Create the Foundry project structure and install dependencies.

**Files to create:**
- `foundry.toml`
- `src/` directory
- `test/` directory
- `script/` directory

**Commands:**
```bash
cd ai-on-chain-projects/agent-card-verifier
forge init --no-git --no-commit .
forge install OpenZeppelin/openzeppelin-contracts@v5.3.0 --no-git --no-commit
```

**Configure `foundry.toml`:**
```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.28"
optimizer = true
optimizer_runs = 10000
via_ir = false
evm_version = "cancun"

remappings = [
    "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
]

[profile.default.fuzz]
runs = 1000
max_test_rejects = 100000

[fmt]
line_length = 100
tab_width = 4
bracket_spacing = false
int_types = "long"
multiline_func_header = "params_first"
quote_style = "double"
number_underscore = "thousands"
```

**Verification:** `forge build` succeeds with no warnings.

### Step 2: Implement the AgentCardVerifier library

**File:** `src/AgentCardVerifier.sol`

Implement the core library with:
- `CLAIM_TYPEHASH` constant
- `AgentRegistrationClaim` struct definition
- `_validateClaimFields()` internal pure — reverts on zero chainId, zero registryAddress, or expired deadline
- `_hashClaim()` internal pure — returns the EIP-712 struct hash
- `_hashTypedData()` internal view — takes domain separator, returns the full digest
- `_verifyRegistrationClaim()` internal view — validates fields, hashes the claim, attempts ECDSA recovery first, falls back to ERC-1271 `staticcall` if ECDSA fails or doesn't match
- `_recoverClaimSigner()` internal view — validates fields, hashes, recovers via ECDSA only, reverts on failure

All custom errors defined in the library.

**Verification:** `forge build` succeeds. No tests yet.

### Step 3: Implement the AgentCardVerifierRouter contract

**File:** `src/AgentCardVerifierRouter.sol`

Implement the deployed contract that:
- Inherits OpenZeppelin's `EIP712` for domain separator management (constructor args: `"AgentCardVerifier"`, `"1"`)
- Exposes all library functions as `external view` / `external pure`
- Implements `verifyRegistrationClaimBatch` with try/catch per claim (no revert on individual failure)
- Exposes `domainSeparator()`, `hashClaim()`, `hashTypedData()`
- No owner, no upgradeability, no state variables beyond EIP712's immutables

**Verification:** `forge build` succeeds.

### Step 4: Implement unit tests for the library

**File:** `test/AgentCardVerifier.t.sol`

Test the library through the Router contract (deploy Router in `setUp()`).

**Test cases (ECDSA path):**

| Test Function | Scenario |
|---|---|
| `test_VerifyRegistrationClaim_ValidEOASignature_ReturnsTrue` | Happy path: sign claim with EOA, verify succeeds |
| `test_VerifyRegistrationClaim_WrongSigner_ReturnsFalse` | Sign with key A, claim owner is key B |
| `test_VerifyRegistrationClaim_ExpiredDeadline_Reverts` | `deadline` is in the past |
| `test_VerifyRegistrationClaim_ZeroChainId_Reverts` | `chainId = 0` |
| `test_VerifyRegistrationClaim_ZeroRegistryAddress_Reverts` | `registryAddress = address(0)` |
| `test_VerifyRegistrationClaim_TamperedChainId_ReturnsFalse` | Sign for chainId=1, verify with chainId=8453 |
| `test_VerifyRegistrationClaim_TamperedAgentId_ReturnsFalse` | Sign for agentId=42, verify with agentId=43 |
| `test_VerifyRegistrationClaim_TamperedRegistryAddress_ReturnsFalse` | Change registry address after signing |
| `test_VerifyRegistrationClaim_MalleableSignature_ReturnsFalse` | Flip s-value to upper half of curve order |
| `test_VerifyRegistrationClaim_EmptySignature_Reverts` | Zero-length signature bytes |
| `test_VerifyRegistrationClaim_DeadlineExactlyNow_ReturnsTrue` | `deadline == block.timestamp` (boundary) |
| `test_VerifyRegistrationClaim_MaxAgentId_ReturnsTrue` | `agentId = type(uint256).max` |
| `test_RecoverClaimSigner_ValidSignature_RecoversSigner` | Recover and check address matches |
| `test_RecoverClaimSigner_InvalidSignature_Reverts` | Random bytes as signature |
| `test_HashTypedData_DeterministicOutput` | Same claim produces same hash across calls |
| `test_HashTypedData_DifferentClaims_DifferentHashes` | Two claims with different agentId produce different hashes |

**Test cases (ERC-1271 path):**

Deploy a mock `MockERC1271Wallet` that implements `isValidSignature`:
- Returns `0x1626ba7e` for a pre-approved digest, `0xffffffff` otherwise.

| Test Function | Scenario |
|---|---|
| `test_VerifyRegistrationClaim_ValidERC1271Wallet_ReturnsTrue` | Smart wallet approves the digest |
| `test_VerifyRegistrationClaim_ERC1271WalletRejects_ReturnsFalse` | Smart wallet returns wrong magic value |
| `test_VerifyRegistrationClaim_ERC1271WalletReverts_ReturnsFalse` | Smart wallet reverts on isValidSignature |
| `test_VerifyRegistrationClaim_NonContractAsERC1271_ReturnsFalse` | claimedOwner is an EOA but ECDSA doesn't match, ERC-1271 fallback fails because no code |

**Test cases (Batch):**

| Test Function | Scenario |
|---|---|
| `test_VerifyBatch_AllValid_AllReturnTrue` | 3 valid claims, all pass |
| `test_VerifyBatch_MixedValidity_PartialResults` | 3 claims: valid, expired, wrong signer |
| `test_VerifyBatch_EmptyArray_ReturnsEmpty` | Zero-length arrays |
| `test_VerifyBatch_MismatchedLengths_Reverts` | claims.length != signatures.length |

**Test cases (Domain separator):**

| Test Function | Scenario |
|---|---|
| `test_DomainSeparator_MatchesExpected` | Manually compute and compare |
| `test_DomainSeparator_DifferentRouterAddress_DifferentSeparator` | Deploy two Routers, compare separators |

**Verification:** `forge test -vv` — all tests pass. `forge test --gas-report` — `verifyRegistrationClaim` < 35,000 gas for ECDSA path.

### Step 5: Implement fuzz tests

**File:** `test/AgentCardVerifier.fuzz.t.sol`

| Test Function | Invariant |
|---|---|
| `testFuzz_VerifyRegistrationClaim_RandomKey_MatchesSigner(uint256 privateKey, uint256 chainId, address registry, uint256 agentId, uint256 deadline)` | For any valid private key, signing a claim and verifying against the derived address always returns true. Bound: `privateKey` between 1 and `secp256k1 order - 1`, `chainId > 0`, `registry != address(0)`, `deadline >= block.timestamp`. |
| `testFuzz_RecoverClaimSigner_MatchesAddress(uint256 privateKey, uint256 agentId)` | Recovered address always matches `vm.addr(privateKey)`. |
| `testFuzz_HashTypedData_NeverCollides(uint256 agentIdA, uint256 agentIdB)` | If `agentIdA != agentIdB`, typed data hashes differ (same chainId, registry, deadline). |
| `testFuzz_VerifyRegistrationClaim_WrongKey_NeverPasses(uint256 signerKey, uint256 claimedKey, uint256 agentId)` | If `signerKey != claimedKey`, verification returns false. Bound: both keys valid, distinct. |

**Verification:** `forge test --match-path test/AgentCardVerifier.fuzz.t.sol -vv` — 1,000 fuzz runs pass for each function.

### Step 6: Implement deployment script

**File:** `script/DeployRouter.s.sol`

A Forge script that:
1. Deploys `AgentCardVerifierRouter` using `CREATE2` via the Safe Singleton Factory (`0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7`) with a deterministic salt, so the Router gets the same address on every chain.
2. Logs the deployed address and domain separator.
3. Verifies the deployment by calling `domainSeparator()` on the deployed contract.

**File:** `script/VerifyDeployment.s.sol`

A read-only script that:
1. Calls `domainSeparator()` on the Router at a given address.
2. Calls `hashTypedData()` with a test claim.
3. Logs results for manual verification.

**Verification:** `forge script script/DeployRouter.s.sol --rpc-url $BASE_SEPOLIA_RPC --private-key $DEPLOYER_KEY --broadcast` deploys successfully on Base Sepolia. Do **not** deploy to mainnet without explicit operator confirmation.

### Step 7: Integration test against forked chain state

**File:** `test/AgentCardVerifier.integration.t.sol`

Fork Base Sepolia (`forge test --fork-url $BASE_SEPOLIA_RPC`).

| Test Function | Scenario |
|---|---|
| `test_Integration_VerifyClaimForRealRegistry` | Create a claim with `registryAddress = 0x8004A818BFB912233c491871b3d84c89A494BD9e` (Base Sepolia Identity Registry), a known `agentId` from the fork state, sign it, and verify it through the Router. |
| `test_Integration_RouterDomainSeparatorMatchesChain` | Verify the Router's domain separator matches manual computation using Base Sepolia's chain ID. |

**Verification:** `forge test --match-path test/AgentCardVerifier.integration.t.sol --fork-url $BASE_SEPOLIA_RPC -vv` — all tests pass.

## 5. Testing Plan

### Unit Tests

**File:** `test/AgentCardVerifier.t.sol`
**Mock dependencies:** `MockERC1271Wallet.sol` (approve/reject/revert modes).
**Convention:** `test_FunctionName_Condition_ExpectedResult`
**Coverage target:** Every `external` function in the Router. Every error path (all 6 custom errors must be triggered by at least one test). Every branch in the ECDSA/ERC-1271 fallback logic.

28 test cases specified in Step 4 above.

### Integration Tests

**File:** `test/AgentCardVerifier.integration.t.sol`
**Fork:** Base Sepolia via `--fork-url`.
**Scenarios:** 2 test cases specified in Step 7 above.

### Fuzz Tests

**File:** `test/AgentCardVerifier.fuzz.t.sol`
**Runs:** 1,000 per function (configured in `foundry.toml`).
**Invariants:**
1. A valid signature from key K always verifies against `vm.addr(K)`.
2. A valid signature from key K never verifies against `vm.addr(K')` where `K != K'`.
3. Different claims produce different typed data hashes.

4 fuzz test functions specified in Step 5 above.

## 6. Reference Materials

- **ERC-8004 spec text** — `8004-contracts/erc-8004-contracts/ERC8004SPEC.md` in this repo. Defines Identity Registry interface, Agent Registration File schema, and `registrations[]` array.
- **ERC-8004 Identity Registry implementation** — `8004-contracts/erc-8004-contracts/contracts/IdentityRegistryUpgradeable.sol`. Reference for EIP-712 domain (`"ERC8004IdentityRegistry"`, `"1"`) and `AgentWalletSet` typehash pattern.
- **ERC-8004 deployed addresses** — `8004-contracts/erc-8004-contracts/scripts/addresses.ts`. Mainnet: `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`. Testnet: `0x8004A818BFB912233c491871b3d84c89A494BD9e`.
- **EIP-712 spec** — https://eips.ethereum.org/EIPS/eip-712. Typed structured data hashing and signing standard.
- **ERC-1271 spec** — https://eips.ethereum.org/EIPS/eip-1271. Standard signature validation for contracts. Magic value: `0x1626ba7e`.
- **OpenZeppelin Contracts v5.x** — https://docs.openzeppelin.com/contracts/5.x/. `ECDSA`, `EIP712`, `IERC1271` implementations.
- **Safe Singleton Factory** — deployed at `0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7` on all EVM chains. Used for deterministic CREATE2 deployment of the Router.
