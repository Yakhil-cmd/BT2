### Title
Signature Replay in `validateCOAOwnershipProof` Allows Proving Ownership of Unintended COA — (`fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` verifies Cadence account key signatures over caller-supplied `signedData` bytes, but does **not** enforce that `signedData` encodes the `evmAddress` being proven. Because the signed payload is decoupled from the EVM address, any valid signature a Flow account holder has ever produced under the `"FLOW-V0.0-user"` domain tag — for any purpose — can be replayed by an attacker to pass the ownership check for that account's COA. EVM contracts that gate privileged actions on a successful `verifyCOAOwnershipProof` call are therefore bypassable without the victim's participation.

---

### Finding Description

`validateCOAOwnershipProof` (lines 1011–1116 of `fvm/evm/stdlib/contract.cdc`) accepts six arguments:

```cadence
fun validateCOAOwnershipProof(
    address: Address,
    path: PublicPath,
    signedData: [UInt8],      // ← arbitrary bytes; NOT required to contain evmAddress
    keyIndices: [UInt64],
    signatures: [[UInt8]],
    evmAddress: [UInt8; 20]   // ← checked against the COA resource, but NOT signed over
): ValidationResult
```

The function:
1. Verifies that `signatures` are valid over `signedData` using the account's keys at `keyIndices` with domain tag `"FLOW-V0.0-user"`.
2. Borrows the COA resource at `path` and checks that its `.address()` equals `evmAddress`.

**Neither step binds `signedData` to `evmAddress`.** The code itself acknowledges this at lines 1003–1009:

> *"this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."* [1](#0-0) 

The EVM-side entry point is the `verifyCOAOwnershipProof(address, bytes32, bytes)` precompile, whose `Run` method decodes the ABI-encoded arguments and delegates to the same Cadence function via `coaOwnershipProofValidator`: [2](#0-1) [3](#0-2) 

The `COAOwnershipProofInContext` struct confirms that `SignedData` and `EVMAddress` are independent fields — the proof encoding never commits one to the other: [4](#0-3) 

**Attack scenario — cross-context replay:**

1. Victim signs 32 bytes of data `D` under `"FLOW-V0.0-user"` for any legitimate purpose (e.g., an off-chain dApp login, a prior COA proof for a different contract).
2. Attacker constructs a `COAOwnershipProof` with the victim's Flow `Address`, their public `CapabilityPath`, the observed `Signatures`, and the matching `KeyIndices`.
3. Attacker submits an EVM transaction calling `verifyCOAOwnershipProof(victimCOAAddress, D, encodedProof)`.
4. `validateCOAOwnershipProof` verifies `sig(D)` against the victim's keys — **passes** — then checks the COA resource address — **passes** — and returns `isValid: true`.
5. The EVM contract grants the attacker the privileges it associates with the victim's COA.

**Cross-COA replay (same account, multiple COAs):**

If a single Cadence account holds COA-A (at `/public/coaA`) and COA-B (at `/public/coaB`), a signature produced to prove ownership of COA-A can be replayed with `path = /public/coaB` to prove ownership of COA-B, because the signed data never encodes which COA it is for.

---

### Impact Explanation

Any EVM smart contract that uses `verifyCOAOwnershipProof` as an authorization gate — granting token withdrawals, role assignments, or other privileged actions to the proven COA owner — can be bypassed. An attacker who observes a single valid `"FLOW-V0.0-user"` signature from the victim (e.g., from a prior on-chain proof submission or an off-chain authentication flow) can impersonate the victim as COA owner in any such contract, leading to unauthorized asset movement or privilege escalation. This is a direct analog to the TimelockTokenPool H-05 finding: a signature lacking context binding (nonce / address commitment) can be replayed to authorize actions the signer never intended.

---

### Likelihood Explanation

- `validateCOAOwnershipProof` is `access(all)` and callable by any Cadence script or transaction; the EVM precompile is reachable by any EVM transaction — no privileged access is required.
- The `"FLOW-V0.0-user"` domain tag is generic; any user-facing signature (off-chain dApp auth, prior COA proofs) qualifies.
- Prior proof submissions are permanently visible on-chain, giving attackers a ready supply of replayable signatures.
- EVM contracts using `verifyCOAOwnershipProof` for access control are the intended production use case (FLIP 223), making exploitation realistic wherever such contracts exist.

---

### Recommendation

Enforce inside `validateCOAOwnershipProof` that `signedData` encodes `evmAddress` — for example, require the first 20 bytes of `signedData` to equal `evmAddress`, or hash `evmAddress` into a mandatory prefix. Alternatively, add a per-proof nonce stored on-chain and include it in `signedData`, invalidating any replayed signature. The EVM precompile wrapper should pass the calling contract's own COA address as a mandatory component of the signed payload, not merely as a post-verification check.

---

### Proof of Concept

```cadence
// Step 1 – Victim previously signed 32 bytes D for any "FLOW-V0.0-user" purpose.
// The signature `victimSig` and the victim's Flow address are publicly observable.

// Step 2 – Attacker constructs a replay proof (off-chain):
let replayProof = COAOwnershipProof(
    keyIndices:     [0],                  // victim's key index
    address:        victimFlowAddress,    // victim's Flow address
    capabilityPath: "coa",               // victim's published COA path
    signatures:     [victimSig]           // signature over D, produced for a different purpose
)
let encodedProof = replayProof.encode()

// Step 3 – Attacker submits an EVM transaction calling the precompile:
//   verifyCOAOwnershipProof(victimCOAAddress, D, encodedProof)
// The precompile calls validateCOAOwnershipProof which:
//   (a) verifies victimSig over D with "FLOW-V0.0-user" → PASSES (valid sig)
//   (b) checks COA resource at "coa" path has address victimCOAAddress → PASSES
//   returns isValid: true

// Step 4 – The EVM contract grants the attacker privileges intended for the victim.
```

The root cause is at `fvm/evm/stdlib/contract.cdc` lines 1082–1086, where `keyList.verify` is called over `signedData` with no enforcement that `evmAddress` is committed inside it: [5](#0-4)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1001-1018)
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

**File:** fvm/evm/precompiles/arch.go (L143-155)
```go
func (f *proofVerifier) Run(input []byte) ([]byte, error) {
	proof, err := DecodeABIEncodedProof(input)
	if err != nil {
		return nil, err
	}
	verified, err := f.proofVerifier(proof)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, EncodedBoolSize)
	return buffer, EncodeBool(verified, buffer, 0)
}
```

**File:** fvm/evm/handler/precompiles.go (L115-153)
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
}
```

**File:** fvm/evm/types/proof.go (L102-118)
```go
type COAOwnershipProofInContext struct {
	COAOwnershipProof
	SignedData SignedData
	EVMAddress Address
}

func NewCOAOwnershipProofInContext(sd []byte, addr Address, encodedProof []byte) (*COAOwnershipProofInContext, error) {
	proof, err := COAOwnershipProofFromEncoded(encodedProof)
	if err != nil {
		return nil, err
	}
	return &COAOwnershipProofInContext{
		COAOwnershipProof: *proof,
		SignedData:        sd,
		EVMAddress:        addr,
	}, nil
}
```
