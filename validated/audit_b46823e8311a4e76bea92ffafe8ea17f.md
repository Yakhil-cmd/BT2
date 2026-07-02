### Title
Cross-COA Signature Replay via Missing `evmAddress` Binding in `validateCOAOwnershipProof` - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary

`EVM.validateCOAOwnershipProof` does not enforce that `signedData` encodes the target `evmAddress`. A Cadence account that owns multiple COAs (at different storage paths) can have a signature produced for one COA replayed to impersonate a different COA. Via the ERC-1271 `isValidSignature` path in `coa.sol`, this allows an attacker who observes any valid COA ownership proof from a victim to forge ERC-1271 authorization for any other COA the victim owns, enabling unauthorized asset transfers or access grants in EVM contracts.

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` performs two independent checks:

1. Verifies that the provided `signatures` are valid over `signedData` using the Cadence account's keys.
2. Verifies that the COA resource at the given `path` has an EVM address matching `evmAddress`. [1](#0-0) 

These two checks are never bound together: `signedData` is never required to include `evmAddress` or `CapabilityPath`. The code itself acknowledges this gap: [2](#0-1) 

The `COAOwnershipProof` struct is RLP-encoded and contains a mutable `CapabilityPath` field: [3](#0-2) 

An attacker who obtains a valid proof `{Address: alice, CapabilityPath: "coa", Signatures: sig_over_hash}` can trivially construct a new proof `{Address: alice, CapabilityPath: "coa2", Signatures: sig_over_hash}` with the same signatures but pointing to a different COA. Because `signedData` (i.e., `hash`) does not encode which COA it was intended for, the signature remains valid under the new proof.

The ERC-1271 entry point in `coa.sol` passes `address(this)` as the EVM address: [4](#0-3) 

So when `COA-B.isValidSignature(hash, crafted_proof)` is called, the precompile invokes `validateCOAOwnershipProof(alice_addr, /public/coa2, hash_bytes, key_indices, sigs, COA-B_address)`. The signature check passes (Alice signed `hash`), and the COA address check passes (COA-B is at `/public/coa2`), so the function returns `isValid: true` — even though Alice only signed `hash` in the context of COA-A.

The precompile wiring that routes EVM calls to the Cadence function: [5](#0-4) 

### Impact Explanation

**Impact: High.** Any EVM contract that uses ERC-1271 (`isValidSignature`) to authorize actions on behalf of a COA — such as DEX order execution, permit-style token approvals, NFT marketplace listings, or governance votes — can be tricked into accepting authorization from COA-B when Alice only signed for COA-A. This leads to unauthorized asset transfers or state changes from COA-B without Alice's consent for that specific COA.

### Likelihood Explanation

**Likelihood: Medium.** The attack requires:
1. The victim to own at least two COAs under the same Cadence account (allowed by the protocol; no enforcement of the "one COA per account" assumption the comment relies on).
2. The attacker to observe a valid COA ownership proof from the victim (e.g., from an on-chain transaction or off-chain API call).
3. An EVM contract that uses ERC-1271 against the victim's second COA.

All three conditions are realistic as the Flow EVM ecosystem grows and multi-COA patterns emerge.

### Recommendation

Enforce that `signedData` encodes `evmAddress` inside `validateCOAOwnershipProof`, or add a protocol-level check that binds the signature to the target COA address:

```cadence
// Require that signedData includes evmAddress as its last 20 bytes,
// or prepend evmAddress to signedData before verification:
let boundData = evmAddress.toBytes().concat(signedData)
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: boundData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

This mirrors the fix recommended in the external report: include the binding context (contract address / EVM address) in the signed hash to prevent cross-context replay.

### Proof of Concept

**Setup:** Alice's Cadence account has two COAs:
- COA-A stored at `/storage/coa`, published at `/public/coa`, EVM address `0xAAAA`
- COA-B stored at `/storage/coa2`, published at `/public/coa2`, EVM address `0xBBBB`

**Step 1 — Legitimate action:** Alice signs `hash` for COA-A and submits a proof to an EVM contract:
```
proof_A = RLP{KeyIndices:[0], Address:alice, CapabilityPath:"coa", Signatures:[sig]}
COA-A.isValidSignature(hash, proof_A) → true  ✓ (legitimate)
```

**Step 2 — Attacker crafts replay proof:** The attacker copies `proof_A` and changes only `CapabilityPath`:
```
proof_B = RLP{KeyIndices:[0], Address:alice, CapabilityPath:"coa2", Signatures:[sig]}
```
The `Signatures` field is identical — no new signing required.

**Step 3 — Replay against COA-B:**
```
COA-B.isValidSignature(hash, proof_B)
  → verifyCOAOwnershipProof(0xBBBB, hash, proof_B)
  → validateCOAOwnershipProof(alice, /public/coa2, hash_bytes, [0], [sig], 0xBBBB)
     ✓ sig is valid over hash_bytes with alice's key
     ✓ COA at /public/coa2 has address 0xBBBB
  → isValid: true  ← UNAUTHORIZED
```

**Step 4 — Impact:** Any EVM contract that called `COA-B.isValidSignature(hash, proof_B)` now believes COA-B authorized `hash`, enabling the attacker to execute actions (token transfers, approvals, votes) from COA-B without Alice's consent for that COA.

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1003-1009)
```text
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

**File:** fvm/evm/types/proof.go (L139-144)
```go
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
}
```

**File:** fvm/evm/handler/coa/coa.sol (L114-125)
```text
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

**File:** fvm/evm/handler/precompiles.go (L115-134)
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
```
