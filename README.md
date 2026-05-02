# Agent Card Verifier Library

A Solidity library and deployed router contract that verifies cross-chain agent registration claims from ERC-8004 Agent Registration Files. Agent owners sign EIP-712 typed data asserting ownership of `(chainId, registryAddress, agentId)` tuples; any smart contract can verify those signatures on-chain, turning the currently self-asserted `registrations[]` array into a cryptographically verifiable identity linkage. Supports both EOA (ECDSA) and smart contract wallets (ERC-1271).

**Status:** Not Started

See [PRD.md](PRD.md) for full specification.
