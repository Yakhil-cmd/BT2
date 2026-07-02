### Title
Cross-COA Ownership Proof Replay via Missing `evmAddress` Binding in `EVM.validateCOAOwnershipProof` - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` is an `access(all)` Cadence function that verifies a COA ownership proof by checking signatures over `signedData` and separately checking that the COA at the given `path` matches `evmAddress`. Because `signedData` is not required to encode `evmAddress`, a proof produced to authenticate ownership of one COA (`COA_A`) can be replayed by an unprivileged attacker to authenticate ownership of a different COA (`COA_B`) belonging to the same Cadence account. The code itself acknowledges this gap in a comment but dismisses it as low-risk based on a non-enforced assumption.

---

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` performs two independent checks:

1. **Signature check** (lines 1082–1086): Verifies that the provided `signatures` are valid over `signedData` using the Cadence account's keys.
2. **COA address check** (lines 1095–1110): Borrows the COA resource at the given `path` and compares its EVM address to the caller-supplied `evmAddress`.

The critical gap is that these two checks are **not bound together**: `signedData` is never required to include `evmAddress`. The signature only commits to `signedData`; the `evmAddress` is a separate, caller-controlled parameter that is checked independently after signature verification passes.

The function is declared `access(all)` and is callable by any Cadence script or transaction without restriction. The code comment at lines 1003–1009 explicitly acknowledges this:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."

The comment dismisses this as "low-risk" because the EVM-side precompile (`verifyCOAOwnershipProof`) always passes `address(this)` as `evmAddress`. However, `validateCOAOwnershipProof` is a public Cadence API that any protocol or DApp can call directly — and the protocol does not prevent a Cadence account from owning multiple COAs at different storage paths. [1](#0-0) 

The signature verification step: [2](#0-1) 

The separate, unbound `evmAddress` check: [3](#0-2) 

The `COAOwnershipProof` struct (RLP-encoded in the proof bytes) contains `KeyIndices`, `Address`, `CapabilityPath`, and `Signatures` — but **not** `EVMAddress`. The `EVMAddress` is passed as a separate argument and is never part of the signed message: [4](#0-3) 

The `COAOwnershipProofInContext` struct shows `EVMAddress` is external to the proof: [5](#0-4) 

---

### Impact Explanation

An attacker who observes a valid COA ownership proof (e.g., from an on-chain transaction or off-chain authentication flow) can replay it against a different COA owned by the same Cadence account. Any Cadence transaction or protocol that calls `validateCOAOwnershipProof` directly to gate access to COA-controlled assets or privileged actions is vulnerable to unauthorized authentication. The attacker does not need any keys or privileged access — only the publicly observable `signedData`, `keyIndices`, and `signatures` from a prior valid proof.

The EVM precompile path (`verifyCOAOwnershipProof` in `coa.sol`) is safe because it always passes `address(this)` as `evmAddress`: [6](#0-5) 

But the direct Cadence API path is not protected.

---

### Likelihood Explanation

Requires: (1) the victim Cadence account owns multiple COAs at different storage paths; (2) a valid proof for one COA is observable; (3) a protocol uses `validateCOAOwnershipProof` directly to gate privileged actions. As Flow EVM adoption grows and multi-COA patterns become more common (the protocol does not prevent them), this risk increases. The function is `access(all)` and publicly documented as a callable API, making it a realistic integration target.

---

### Recommendation

Enforce within `validateCOAOwnershipProof` itself that `signedData` encodes `evmAddress` — for example, by verifying that the 20-byte `evmAddress` is a suffix or prefix of `signedData` before returning `isValid: true`. This removes the reliance on callers to enforce domain separation and closes the replay path regardless of how many COAs an account owns.

---

### Proof of Concept

1. Cadence account `A` owns two COAs: `COA_A` at `/public/coa` (EVM address `0xAAAA...`) and `COA_B` at `/public/coa2` (EVM address `0xBBBB...`).
2. A DApp asks account `A` to prove ownership of `COA_A` by signing `signedData = "challenge-xyz"` (without encoding `0xAAAA...`). Account `A` submits the proof on-chain.
3. Attacker observes `signedData`, `keyIndices`, and `signatures` from the on-chain transaction.
4. Attacker submits a Cadence transaction calling:
   ```cadence
   EVM.validateCOAOwnershipProof(
     address: A,
     path: /public/coa2,       // COA_B's path
     signedData: "challenge-xyz",
     keyIndices: [...],         // same as original
     signatures: [...],         // same as original
     evmAddress: [0xBB, 0xBB, ...]  // COA_B's address
   )
   ```
5. Step 1 (signature check) passes — the signatures are valid over `"challenge-xyz"` for account `A`'s keys.
6. Step 2 (COA address check) passes — the COA at `/public/coa2` has address `0xBBBB...`, which matches the attacker-supplied `evmAddress`.
7. The function returns `isValid: true` for `COA_B`, even though account `A` never signed anything related to `COA_B`.
8. Any protocol action gated on this result is now accessible to the attacker for `COA_B`.

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
