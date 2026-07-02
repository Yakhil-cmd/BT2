### Title
Cross-COA Signature Replay in `validateCOAOwnershipProof` Due to Missing `evmAddress` Binding in Signed Data - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` verifies cryptographic signatures over a caller-supplied `signedData` blob and then separately checks that the COA at the given `path` matches the supplied `evmAddress`. Because `evmAddress` is never required to be part of `signedData`, a valid proof produced for one COA owned by a Cadence account can be replayed verbatim to prove ownership of any other COA owned by the same account. The function is `access(all)` and callable by any unprivileged Cadence script or transaction, making the replay path fully externally reachable.

---

### Finding Description

`validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` performs two structurally independent checks:

**Step 1 — Cryptographic verification** (lines 1082–1086): signatures are verified over `signedData` using the account's keys. `evmAddress` plays no role here.

**Step 2 — COA address check** (lines 1095–1110): the COA resource at `path` is borrowed and its `.address().bytes` is compared byte-by-byte against the caller-supplied `evmAddress`. [1](#0-0) [2](#0-1) 

Because `evmAddress` is never bound into the signed payload, a proof `(signedData, signatures)` that is valid for COA_A is equally valid for COA_B if both are owned by the same Cadence account — the attacker simply substitutes COA_B's `evmAddress` and `path` while keeping `signedData` and `signatures` unchanged.

The code itself acknowledges this gap at lines 1003–1009 but dismisses it as "low-risk" on the behavioral assumption that wallets create at most one COA per account: [3](#0-2) 

However, `createCadenceOwnedAccount()` is `access(all)` with no per-account limit, so a single Cadence account can own arbitrarily many COAs stored at different public paths. [4](#0-3) 

The function is `access(all)`, so any unprivileged Cadence script or transaction can invoke it with attacker-chosen arguments. The EVM-side precompile path (`verifyCOAOwnershipProof` in `coa.sol`) is not affected because it always passes `address(this)` as `evmAddress`, binding it to the calling contract. The vulnerability is specific to the direct Cadence-callable surface. [5](#0-4) [6](#0-5) 

---

### Impact Explanation

Any protocol or application that calls `EVM.validateCOAOwnershipProof` directly from Cadence to make access-control decisions (e.g., off-chain authentication flows, bridge authorization checks, or on-chain gating logic) can be bypassed. An attacker who obtains a valid proof for COA_A — which is possible simply by observing a legitimate proof submission — can replay it to impersonate the owner of COA_B, a different EVM address controlled by the same Cadence account. This constitutes unauthorized identity assertion / authorization bypass at the COA ownership proof layer.

---

### Likelihood Explanation

- `validateCOAOwnershipProof` is `access(all)` — no privilege required to call it.
- `createCadenceOwnedAccount()` is `access(all)` — any account can create multiple COAs.
- A valid proof for any COA of the target account is sufficient; the attacker does not need to forge a signature.
- The only precondition is that the victim account owns more than one COA, which is a supported and unrestricted protocol state.
- Likelihood is **medium**: the multi-COA precondition is not the common case today, but it is fully reachable without any privileged access.

---

### Recommendation

Enforce inside `validateCOAOwnershipProof` that `signedData` encodes `evmAddress` before performing signature verification — do not rely on callers to do so. A concrete fix is to prepend or hash `evmAddress` into the data that is passed to `keyList.verify(...)`, replacing the current:

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

with a version that binds `evmAddress` into the verified payload, e.g.:

```cadence
let boundData = evmAddress.toBytes().concat(signedData)
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: boundData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

This mirrors the recommendation in the external report: include the identifier (nonce / `evmAddress`) in the signature so that a proof is cryptographically scoped to exactly one target.

---

### Proof of Concept

1. Cadence account `Alice` calls `EVM.createCadenceOwnedAccount()` twice, storing COA_1 at `/storage/coa1` (published at `/public/coa1`) and COA_2 at `/storage/coa2` (published at `/public/coa2`). COA_1 has EVM address `0xAAAA…`, COA_2 has EVM address `0xBBBB…`.

2. A legitimate verifier requests a COA ownership proof for COA_1. Alice signs `signedData = <some application bytes that do NOT include 0xAAAA…>` with her key. The resulting proof `(signedData, keyIndices, signatures)` is published or observed on-chain.

3. An attacker constructs a Cadence script:
   ```cadence
   import EVM from <address>
   access(all) fun main(): EVM.ValidationResult {
       return EVM.validateCOAOwnershipProof(
           address: <Alice's Cadence address>,
           path: /public/coa2,          // COA_2's path
           signedData: <same signedData>,
           keyIndices: <same keyIndices>,
           signatures: <same signatures>,
           evmAddress: <0xBBBB…>        // COA_2's EVM address
       )
   }
   ```

4. The script returns `ValidationResult(isValid: true, problem: nil)` for COA_2, even though Alice's signature was produced for COA_1. The attacker has successfully replayed the proof across COA addresses. [1](#0-0) [7](#0-6) [8](#0-7)

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

**File:** fvm/evm/stdlib/contract.cdc (L1095-1116)
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

        return ValidationResult(
            isValid: false,
            problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership. Could not borrow the COA resource for account \(address)."
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
