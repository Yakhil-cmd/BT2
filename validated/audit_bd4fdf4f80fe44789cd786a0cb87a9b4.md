### Title
Hardcoded `"FLOW-V0.0-user"` Domain Separation Tag in `validateCOAOwnershipProof` Enables Cross-Network Signature Replay - (File: fvm/evm/stdlib/contract.cdc)

---

### Summary

`validateCOAOwnershipProof` in the EVM Cadence contract verifies COA ownership signatures using the hardcoded, network-agnostic domain separation tag `"FLOW-V0.0-user"`. Because no chain ID or network identifier is bound into the signing domain, a valid COA ownership proof produced on one Flow network (e.g., testnet) is cryptographically valid on any other Flow network (e.g., mainnet) where the same Flow account and keys exist. This is the direct analog of the EIP712 DOMAIN_SEPARATOR-as-immutable vulnerability: the signing domain is fixed at compile time and never reflects the actual network.

---

### Finding Description

`validateCOAOwnershipProof` is a Cadence function exposed both as a public EVM contract function and as the backing implementation of the `verifyCOAOwnershipProof` EVM precompile (Cadence Arch). It is the canonical on-chain mechanism for EVM contracts to verify that a Flow account controls a given COA.

The signature verification call at the core of the function is:

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,
    domainSeparationTag: "FLOW-V0.0-user"   // ← hardcoded, no chain ID
)
``` [1](#0-0) 

The tag `"FLOW-V0.0-user"` is a static string constant. It does not incorporate:
- The Flow chain ID (`flow-mainnet`, `flow-testnet`, `flow-previewnet`, …)
- The EVM chain ID (747, 545, 646)
- Any other network-specific discriminator

The `COAOwnershipProof` struct itself carries no chain ID field:

```go
type COAOwnershipProof struct {
    KeyIndices     KeyIndices
    Address        FlowAddress
    CapabilityPath PublicPath
    Signatures     Signatures
}
``` [2](#0-1) 

The `SignedData` field is arbitrary caller-supplied bytes with no enforced chain ID binding:

```go
type COAOwnershipProofInContext struct {
    COAOwnershipProof
    SignedData SignedData
    EVMAddress Address
}
``` [3](#0-2) 

The code's own comment acknowledges partial replay risk (cross-COA replay within the same network) but explicitly does **not** address cross-network replay:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [4](#0-3) 

The `verifyCOAOwnershipProof` EVM precompile routes directly to this function via `coaOwnershipProofValidator` → `backend.Invoke("validateCOAOwnershipProof", ...)`: [5](#0-4) 

---

### Impact Explanation

An unprivileged attacker who has observed (or induced) a COA ownership proof on one Flow network can replay it on any other Flow network where the same Flow account exists with the same keys. Concretely:

1. A user signs `signedData = H` on testnet to authenticate with an EVM dApp. The resulting `COAOwnershipProof` (Flow address + capability path + key indices + signatures) is valid on mainnet for the same `H` because the domain separation tag is identical on both networks.
2. Any EVM contract on mainnet that calls `verifyCOAOwnershipProof(evmAddress, H, proof)` will accept the testnet-produced proof as valid, granting the attacker the authentication outcome the contract enforces (e.g., access to bridged assets, governance votes, or permissioned contract calls).
3. The same applies across any pair of Flow networks (mainnet ↔ testnet ↔ previewnet) and across hard-fork scenarios where the Flow chain ID string remains unchanged but the network has diverged.

The impact class is **unauthorized transaction authorization / entitlement bypass** in EVM contracts that rely on `verifyCOAOwnershipProof` for access control.

---

### Likelihood Explanation

- Flow accounts are commonly created with the same keys on both testnet and mainnet (standard wallet onboarding).
- The `verifyCOAOwnershipProof` precompile is the documented mechanism for EVM contracts to authenticate Flow account ownership; its use is expected to grow as the COA bridge ecosystem matures.
- The attacker only needs to observe a single valid proof from the victim on any Flow network — no privileged access, no key compromise, no node control required.
- The `signedData` is caller-controlled in the EVM transaction, so the attacker can supply the exact bytes the victim previously signed.

Likelihood is **medium**: it requires the victim to have the same keys on multiple networks and an EVM contract that does not independently bind `signedData` to a chain ID, but neither condition is unusual.

---

### Recommendation

Bind the signing domain to the network by including the Flow chain ID in the domain separation tag used for COA ownership proof verification. Following the same pattern as OpenZeppelin's EIP712 (which dynamically reads `block.chainid`), the tag should be constructed at runtime from the chain ID rather than hardcoded:

```cadence
// Instead of:
domainSeparationTag: "FLOW-V0.0-user"

// Use a network-scoped tag, e.g.:
domainSeparationTag: "FLOW-V0.0-user-".concat(self.chainID)
```

where `self.chainID` is the Flow chain ID string injected into the EVM contract at deployment or read from a system contract. Alternatively, mandate that `signedData` must include the chain ID and enforce this in `validateCOAOwnershipProof` itself, rejecting proofs whose `signedData` does not encode the expected network.

---

### Proof of Concept

**Setup**: Alice has a Flow account with the same ECDSA key on both `flow-testnet` and `flow-mainnet`. She has a COA at `/public/coa` on both networks.

**Step 1 – Obtain proof on testnet**: An EVM dApp on testnet asks Alice to sign `signedData = keccak256("authenticate:dapp.testnet:nonce=1")`. Alice signs with her Flow key using `domainSeparationTag: "FLOW-V0.0-user"` and submits the `COAOwnershipProof`.

**Step 2 – Replay on mainnet**: The attacker submits an EVM transaction on mainnet calling:
```solidity
verifyCOAOwnershipProof(
    aliceEVMAddressOnMainnet,
    keccak256("authenticate:dapp.testnet:nonce=1"),  // same signedData
    aliceProofFromTestnet                             // same proof bytes
)
```

**Step 3 – Verification passes**: `validateCOAOwnershipProof` on mainnet fetches Alice's mainnet account keys, verifies the signatures against `signedData` using `domainSeparationTag: "FLOW-V0.0-user"` — the same tag used on testnet — and returns `ValidationResult(isValid: true)`. The mainnet EVM contract grants the attacker Alice's authenticated access.

The root cause is that `"FLOW-V0.0-user"` at line 1085 of `fvm/evm/stdlib/contract.cdc` is identical on every Flow network, providing no cryptographic binding to the network on which the proof is intended to be used. [1](#0-0)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1002-1009)
```text
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

**File:** fvm/evm/types/proof.go (L102-106)
```go
type COAOwnershipProofInContext struct {
	COAOwnershipProof
	SignedData SignedData
	EVMAddress Address
}
```

**File:** fvm/evm/types/proof.go (L139-144)
```go
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
}
```

**File:** fvm/evm/handler/precompiles.go (L115-152)
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
		)
		if err != nil {
			if types.IsAFatalError(err) {
				panic(err)
			}
			return false, err
		}
		data, ok := value.(cadence.Struct)
		if !ok {
			return false, fmt.Errorf("invalid output data received from validateCOAOwnershipProof")
		}

		isValidValue := cadence.SearchFieldByName(data, ValidationResultTypeIsValidFieldName)
		if isValidValue == nil {
			return false, fmt.Errorf("invalid output data received from validateCOAOwnershipProof")
		}

		return bool(isValidValue.(cadence.Bool)), nil
	}
```
