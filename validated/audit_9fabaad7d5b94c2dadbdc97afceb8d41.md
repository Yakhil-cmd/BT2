### Title
Cross-Network COA Ownership Proof Signature Replay via Hardcoded Domain Separation Tag - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` uses a hardcoded, network-agnostic domain separation tag `"FLOW-V0.0-user"` when verifying Cadence account signatures over caller-supplied `signedData`. Because the tag does not encode any chain-specific identifier, a valid COA ownership proof signature produced on one Flow network (e.g., mainnet) is cryptographically indistinguishable from one on any other Flow network (e.g., testnet), enabling cross-network signature replay.

---

### Finding Description

`validateCOAOwnershipProof` is a public Cadence function that verifies a set of Flow account signatures over arbitrary caller-supplied bytes (`signedData`) to prove that a Flow account controls a COA (Cadence Owned Account) in the EVM layer.

The signature verification call at line 1082–1086 is:

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

The `domainSeparationTag` `"FLOW-V0.0-user"` is a static string constant. It contains no chain ID, no network identifier, and no epoch/spork information. The `signedData` parameter is entirely caller-supplied (`[UInt8]`) with no protocol-level enforcement that it encodes any chain-specific context. [1](#0-0) 

The function is reachable via three distinct unprivileged paths:

1. **Direct Cadence script/transaction**: `EVM.validateCOAOwnershipProof(...)` is `access(all)` and callable by any script or transaction.
2. **EVM precompile**: The Cadence Arch precompile `verifyCOAOwnershipProof(address,bytes32,bytes)` is callable from any EVM transaction or contract, which internally invokes `validateCOAOwnershipProof` via `coaOwnershipProofValidator`.
3. **ERC-1271 `isValidSignature`**: The COA Solidity contract's `isValidSignature` calls the precompile, making any EVM contract that uses ERC-1271 on a COA a replay surface. [2](#0-1) [3](#0-2) 

The existing code comment at lines 1003–1009 acknowledges a *cross-address* replay risk within the same network but explicitly does not address cross-network replay:

> "Callers building off-chain authentication flows on top of this function should ensure `signedData` encodes `evmAddress` to prevent cross-address replay." [4](#0-3) 

Flow has multiple live networks with distinct chain IDs (`flow-mainnet`, `flow-testnet`, `flow-previewnet`, etc.) defined in `model/flow/chain.go`. [5](#0-4) 

---

### Impact Explanation

An attacker who observes a valid COA ownership proof signature on one Flow network can replay it on any other Flow network where the same account address and key exist. Specifically:

- A signature over `signedData = X` with tag `"FLOW-V0.0-user"` on mainnet is byte-for-byte identical to a valid signature on testnet for the same `signedData = X`.
- Any EVM contract on testnet that uses `isValidSignature` (ERC-1271) or `verifyCOAOwnershipProof` for access control (e.g., multisig wallets, token approvals, bridge authorization) can be bypassed by replaying a mainnet-produced proof.
- The `signedData` field is fully attacker-controlled at the call site — there is no protocol-level binding to a chain.

This is a cross-VM asset loss / transaction authorization bypass: an attacker can impersonate a Flow account's COA ownership on a network where the victim never intended to authorize anything.

---

### Likelihood Explanation

- The `domainSeparationTag` is hardcoded and identical across all Flow networks — there is no per-network variation.
- The `signedData` has no enforced structure; wallets and dApps routinely sign short challenge bytes that contain no chain context.
- Flow mainnet and testnet share the same address space derivation for accounts created at the same index, making account address collisions across networks common for developers and power users.
- The function is `access(all)` and reachable from any unprivileged Cadence script or EVM transaction — no special role or capability is required.
- The ERC-1271 path (`isValidSignature` on COA) is a standard interface that EVM DeFi protocols call automatically, making exploitation transparent to the victim.

---

### Recommendation

Bind the domain separation tag to the current Flow chain ID so that signatures are network-scoped. The tag should be constructed dynamically at verification time to include the chain identifier:

```cadence
// Instead of the hardcoded tag:
domainSeparationTag: "FLOW-V0.0-user"

// Use a chain-scoped tag, e.g.:
domainSeparationTag: "FLOW-V0.0-user-".concat(getCurrentChainID())
```

Alternatively, mandate that `signedData` encodes the chain ID as a protocol-level requirement (not merely a documentation suggestion), and validate this within `validateCOAOwnershipProof` before accepting the proof.

---

### Proof of Concept

**Setup**: Alice has the same Flow account address on both mainnet and testnet (common for developers). She signs `signedData = [0xde, 0xad, 0xbe, 0xef]` on mainnet to prove COA ownership to a mainnet EVM contract.

**Attack**:
1. Attacker observes Alice's `COAOwnershipProof` (public on-chain data: `KeyIndices`, `Address`, `CapabilityPath`, `Signatures`) and the `signedData`.
2. Attacker calls `EVM.validateCOAOwnershipProof` on **testnet** with the identical proof and `signedData`.
3. The Cadence runtime on testnet calls `keyList.verify(..., domainSeparationTag: "FLOW-V0.0-user")` — the tag is identical to mainnet.
4. Alice's key exists on testnet at the same index with the same public key.
5. The proof validates as `isValid: true` on testnet.
6. Any testnet EVM contract using `isValidSignature` (ERC-1271) on Alice's COA now accepts the replayed proof, granting the attacker unauthorized authorization as Alice's COA on testnet. [1](#0-0) [6](#0-5)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1001-1009)
```text
    /// validateCOAOwnershipProof validates a COA ownership proof.
    ///
    /// Note: this function does not enforce that `signedData` includes `evmAddress`.
    /// In principle, a signature produced for one purpose could be replayed here against
    /// a different COA owned by the same Cadence account. In practice this is low-risk:
    /// the EVM-side precompile (verifyCOAOwnershipProof) always passes the calling COA's
    /// address as the evmAddress argument, and Flow wallets historically create at most one
    /// COA per account. Callers building off-chain authentication flows on top of this
    /// function should ensure `signedData` encodes `evmAddress` to prevent cross-address replay.
```

**File:** fvm/evm/stdlib/contract.cdc (L1082-1086)
```text
        let isValid = keyList.verify(
            signatureSet: signatureSet,
            signedData: signedData,
            domainSeparationTag: "FLOW-V0.0-user"
        )
```

**File:** fvm/evm/handler/precompiles.go (L115-133)
```go
func coaOwnershipProofValidator(contractAddress flow.Address, backend backends.Backend) func(proof *types.COAOwnershipProofInContext) (bool, error) {
	return func(proof *types.COAOwnershipProofInContext) (bool, error) {
		value, err := backend.Invoke(
			environment.ContractFunctionSpec{
				AddressFromChain: func(_ flow.Chain) flow.Address {
					return contractAddress
				},
				LocationName: "EVM",
				FunctionName: "validateCOAOwnershipProof",
				ArgumentTypes: []sema.Type{
					types.FlowAddressSemaType,
					types.PublicPathSemaType,
					types.SignedDataSemaType,
					types.KeyIndicesSemaType,
					types.SignaturesSemaType,
					types.AddressBytesSemaType,
				},
			},
			proof.ToCadenceValues(),
```

**File:** fvm/evm/handler/coa/coa.sol (L113-125)
```text
    // ERC1271 requirement 
    function isValidSignature(
        bytes32 _hash,
        bytes memory _sig
    ) external view virtual returns (bytes4){
        (bool ok, bytes memory data) = cadenceArch.staticcall(abi.encodeWithSignature("verifyCOAOwnershipProof(address,bytes32,bytes)", address(this), _hash, _sig));
        require(ok);
        bool output = abi.decode(data, (bool));
        if (output) {
            return ValidERC1271Signature;
        }
        return InvalidERC1271Signature;
    }
```

**File:** model/flow/chain.go (L11-43)
```go
// A ChainID is a unique identifier for a specific Flow network instance.
//
// Chain IDs are used to prevent replay attacks and to support network-specific address generation.
type ChainID string
type ChainIDList []ChainID

const (
	// Mainnet is the chain ID for the mainnet chain.
	Mainnet ChainID = "flow-mainnet"

	// Long-lived test networks

	// Testnet is the chain ID for the testnet chain.
	Testnet ChainID = "flow-testnet"
	// Sandboxnet is the chain ID for internal sandboxnet chain.
	Sandboxnet ChainID = "flow-sandboxnet"
	// Previewet is the chain ID for an external preview chain.
	Previewnet ChainID = "flow-previewnet"

	// Transient test networks

	// Benchnet is the chain ID for the transient benchmarking chain.
	Benchnet ChainID = "flow-benchnet"
	// Localnet is the chain ID for the local development chain.
	Localnet ChainID = "flow-localnet"
	// Emulator is the chain ID for the emulated chain.
	Emulator ChainID = "flow-emulator"
	// BftTestnet is the chain ID for testing attack vector scenarios.
	BftTestnet ChainID = "flow-bft-test-net"

	// MonotonicEmulator is the chain ID for the emulated node chain with monotonic address generation.
	MonotonicEmulator ChainID = "flow-emulator-monotonic"
)
```
