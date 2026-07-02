### Title
COA Ownership Proof Signatures Replay Across Sibling COAs Due to Missing EVM Address Binding in `signedData` - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` verifies Cadence account key signatures over caller-supplied `signedData` without enforcing that `signedData` encodes the target `evmAddress`. A signature produced to prove ownership of one COA (Cadence-Owned Account) can be replayed verbatim against any other COA owned by the same Cadence account, because the signed preimage is not bound to the specific EVM address being claimed.

---

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` is declared `access(all)` and is directly callable from any unprivileged Cadence script or transaction. Its validation logic has two independent steps:

**Step 1 — Signature verification** (lines 1082–1086): verifies that the provided `signatures` are valid over `signedData` using the account keys at `keyIndices`. [1](#0-0) 

**Step 2 — EVM address check** (lines 1095–1105): borrows the COA resource at `path` and checks that its `.address()` matches the caller-supplied `evmAddress`. [2](#0-1) 

Critically, the function **never checks that `signedData` encodes `evmAddress`**. The two steps are entirely decoupled: the signature covers `signedData` (arbitrary bytes chosen by whoever requested the proof), and the EVM address check is performed against a separately supplied `evmAddress` and `path`. The code itself acknowledges this gap: [3](#0-2) 

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."

The comment argues this is "low-risk" because the EVM-side precompile (`verifyCOAOwnershipProof` in `coa.sol`) always passes `address(this)` as the `evmAddress` argument: [4](#0-3) 

However, `validateCOAOwnershipProof` is `access(all)` and is independently callable from Cadence. Any off-chain authentication flow or on-chain Cadence contract that calls it directly — without enforcing that `signedData` encodes `evmAddress` — is fully exposed to cross-COA replay. The precompile path's safety does not protect the Cadence-level entry point.

The Go-level `coaOwnershipProofValidator` in `fvm/evm/handler/precompiles.go` delegates directly to `validateCOAOwnershipProof` via `backend.Invoke`, passing the proof's `EVMAddress` as a separate argument with no enforcement that it appears in `SignedData`: [5](#0-4) 

The `COAOwnershipProofInContext` struct separates `SignedData` and `EVMAddress` as independent fields with no structural coupling: [6](#0-5) 

---

### Impact Explanation

Any Cadence contract or off-chain authentication system that calls `EVM.validateCOAOwnershipProof` directly to gate access to a specific COA is vulnerable. An attacker who intercepts a valid proof for COA_A (owned by account `0xVICTIM`) can replay the identical `signedData` and `signatures` with `path=/public/coaB` and `evmAddress=evmAddress_B` to obtain a passing `ValidationResult` for COA_B — a different COA owned by the same account. This constitutes unauthorized proof of ownership of an EVM address the signer never authorized, enabling cross-COA asset access, ERC-1271 signature forgery, or bypass of any Cadence-level access control that relies on this proof.

---

### Likelihood Explanation

The function is `access(all)` and reachable by any unprivileged Cadence script or transaction sender. No special privileges, staked nodes, or compromised keys are required. The attacker only needs to observe a valid proof for one COA (e.g., from a public authentication flow) and submit a transaction replaying it against a sibling COA. The precondition — a Cadence account owning more than one COA — is explicitly anticipated by the protocol (the `path` parameter exists precisely to support multiple COAs per account). The risk is not theoretical: the code comment itself identifies the attack vector and warns callers.

---

### Recommendation

Enforce the binding inside `validateCOAOwnershipProof` itself rather than relying on callers. Before verifying signatures, prepend or hash `evmAddress` into the effective signed message:

```cadence
// Enforce that signedData encodes evmAddress to prevent cross-COA replay
let boundData = evmAddress.concat(signedData)
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: boundData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

Update the EVM precompile, `coa.sol`'s `isValidSignature`, and all SDK tooling to prepend the COA's EVM address to `signedData` before signing, matching the new binding. Add test coverage for cross-COA replay attempts.

---

### Proof of Concept

**Setup**: Cadence account `0xVICTIM` owns two COAs:
- COA_A stored at `/storage/coaA`, capability published at `/public/coaA`, EVM address `evmAddress_A`
- COA_B stored at `/storage/coaB`, capability published at `/public/coaB`, EVM address `evmAddress_B`

**Step 1 — Legitimate proof for COA_A**: Victim signs `signedData = someBytes` with account key 0 to prove ownership of COA_A for some authentication flow. The resulting proof `(signedData, [0], [sig], evmAddress_A)` is observed by the attacker (e.g., from a public transaction or API call).

**Step 2 — Replay against COA_B**: Attacker submits a Cadence script:

```cadence
import EVM from 0xEVMContract

access(all) fun main(): EVM.ValidationResult {
    return EVM.validateCOAOwnershipProof(
        address: 0xVICTIM,
        path: /public/coaB,      // ← different COA
        signedData: someBytes,    // ← same signedData, never signed for COA_B
        keyIndices: [0],          // ← same key indices
        signatures: [sig],        // ← same signatures
        evmAddress: evmAddress_B  // ← COA_B's address
    )
}
```

**Result**: `validateCOAOwnershipProof` verifies `sig` over `someBytes` (passes, same key/data), then checks that the COA at `/public/coaB` has address `evmAddress_B` (passes, it does). Returns `ValidationResult(isValid: true, problem: nil)` — a valid ownership proof for COA_B — even though the victim only ever signed for COA_A. [7](#0-6) [1](#0-0) [8](#0-7)

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

**File:** fvm/evm/stdlib/contract.cdc (L1011-1018)
```text
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

**File:** fvm/evm/stdlib/contract.cdc (L1095-1110)
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
            return ValidationResult(
                isValid: true,
                problem: nil
            )
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
