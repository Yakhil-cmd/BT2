### Title
Cross-Address COA Ownership Proof Replay via Unbound `signedData` in `validateCOAOwnershipProof` - (File: fvm/evm/stdlib/contract.cdc)

### Summary

`EVM.validateCOAOwnershipProof` is a public (`access(all)`) Cadence function that verifies a Cadence account's ownership of a COA (Cadence-Owned Account) by checking cryptographic signatures over caller-supplied `signedData`. The function does not enforce that `signedData` encodes the target `evmAddress`, so a valid signature produced to prove ownership of one COA can be replayed by an attacker to forge a passing proof for a different COA belonging to the same Cadence account. The code comment at lines 1003–1009 explicitly acknowledges this gap but marks it "low-risk in practice," leaving the vulnerability unmitigated in the protocol.

### Finding Description

`validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` (lines 1011–1116) accepts six parameters: `address`, `path`, `signedData`, `keyIndices`, `signatures`, and `evmAddress`. The function:

1. Verifies the supplied `signatures` over `signedData` using the account's keys (line 1082–1086).
2. Borrows the COA capability at `path` and checks that its EVM address matches `evmAddress` (lines 1095–1105).

Critically, **there is no check that `signedData` encodes `evmAddress`**. The signature validity check (step 1) and the address-match check (step 2) are completely independent. An attacker who observes a valid `(signedData, signatures)` pair produced by a victim for COA-A can supply those same bytes with `path = /public/coaB` and `evmAddress = COA-B-address` to obtain a `ValidationResult{isValid: true}` for COA-B — a COA the victim never authorized.

The function is `access(all)`, meaning any unprivileged Cadence script or transaction can invoke it with fully attacker-controlled arguments. The EVM precompile path (`verifyCOAOwnershipProof` in `fvm/evm/precompiles/arch.go`) is safe because it always passes `address(this)` as `evmAddress`, but the Cadence-side function is independently reachable and carries no such enforcement.

### Impact Explanation

Any Cadence contract that calls `EVM.validateCOAOwnershipProof(...)` to gate a privileged action (e.g., a bridge withdrawal, an asset transfer, or an authorization check) is vulnerable to a cross-address replay attack. An attacker who has observed a single valid COA ownership signature from a victim — which is submitted on-chain and therefore public — can forge a passing proof for any other COA the victim controls, without possessing the victim's private key. This constitutes unauthorized account mutation / authorization bypass: the attacker can impersonate the victim's COA ownership to any relying Cadence contract.

### Likelihood Explanation

The attack requires the victim to control more than one COA under the same Cadence account and to have previously produced a signature over `signedData` that does not encode the target COA's EVM address. While the code comment notes that "Flow wallets historically create at most one COA per account," the protocol places no on-chain restriction on creating multiple COAs, and the public API actively supports multi-COA accounts. As the Flow EVM ecosystem grows and more complex wallet patterns emerge, multi-COA accounts will become more common. Signatures are submitted on-chain and are permanently observable, so the attacker has no time constraint.

### Recommendation

Enforce inside `validateCOAOwnershipProof` that `signedData` commits to `evmAddress`. The simplest fix is to hash `evmAddress` into the data that is actually verified:

```cadence
// Derive the effective signed payload that must include the EVM address
let boundData: [UInt8] = signedData.concat(evmAddress.toVariableSized())
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: boundData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

Alternatively, document a mandatory encoding convention and enforce it with a pre-condition check. The EVM precompile (`verifyCOAOwnershipProof`) should be updated in parallel to pass `signedData` that already encodes `address(this)` so that existing callers remain compatible.

### Proof of Concept

**Setup**: Alice's Cadence account (`0xAlice`) holds two COAs:
- COA-A stored at `/storage/coaA`, published at `/public/coaA`, EVM address `0xAAAA…`
- COA-B stored at `/storage/coaB`, published at `/public/coaB`, EVM address `0xBBBB…`

**Step 1 – Victim produces a signature**: Alice signs `signedData = "authorize_action"` (without encoding any EVM address) to prove ownership of COA-A. The resulting `(keyIndices, signatures)` are submitted on-chain and are publicly visible.

**Step 2 – Attacker replays against COA-B**: The attacker submits a Cadence script:

```cadence
import EVM from 0x…

access(all) fun main(): EVM.ValidationResult {
    return EVM.validateCOAOwnershipProof(
        address: 0xAlice,
        path: /public/coaB,          // ← COA-B, not COA-A
        signedData: "authorize_action".utf8,
        keyIndices: [0],             // ← Alice's key index from the observed tx
        signatures: [<observed_sig>],// ← Alice's signature from the observed tx
        evmAddress: <COA-B bytes>    // ← COA-B's EVM address
    )
}
```

**Step 3 – Result**: The function verifies the signature over `"authorize_action"` (valid, because Alice signed exactly that), then checks that COA-B's address matches `0xBBBB…` (true, because the attacker supplied the correct COA-B address). It returns `ValidationResult{isValid: true}` — a forged proof of Alice's ownership of COA-B.

**Relevant code locations**:

- Signature verification with no `evmAddress` binding: [1](#0-0) 
- EVM address check that is independent of the signed payload: [2](#0-1) 
- Acknowledged gap in the code comment: [3](#0-2) 
- Public function signature (attacker entry point): [4](#0-3) 
- EVM precompile safe path (passes `address(this)`, not attacker-controlled): [5](#0-4) 
- Go-side precompile dispatcher that calls `validateCOAOwnershipProof`: [6](#0-5)

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

**File:** fvm/evm/stdlib/contract.cdc (L1010-1018)
```text
    access(all)
    fun validateCOAOwnershipProof(
        address: Address,
        path: PublicPath,
        signedData: [UInt8],
        keyIndices: [UInt64],
        signatures: [[UInt8]],
        evmAddress: [UInt8; 20]
    ): ValidationResult {
```

**File:** fvm/evm/stdlib/contract.cdc (L1082-1086)
```text
        let isValid = keyList.verify(
            signatureSet: signatureSet,
            signedData: signedData,
            domainSeparationTag: "FLOW-V0.0-user"
        )
```

**File:** fvm/evm/stdlib/contract.cdc (L1095-1105)
```text
        if let coaRef = acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(path) {
            // verify evm address matching — capture bytes once to avoid redundant borrow
            let coaAddressBytes = coaRef.address().bytes
            for index, item in coaAddressBytes {
                if item != evmAddress[index] {
                    return ValidationResult(
                        isValid: false,
                        problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership. The provided evm address does not match the account's COA address."
                    )
                }
            }
```

**File:** fvm/evm/handler/coa/coa.sol (L118-118)
```text
        (bool ok, bytes memory data) = cadenceArch.staticcall(abi.encodeWithSignature("verifyCOAOwnershipProof(address,bytes32,bytes)", address(this), _hash, _sig));
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
