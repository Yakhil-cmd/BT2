### Title
Signature Replay Across COA Addresses in `validateCOAOwnershipProof` Due to Missing `evmAddress` Binding in `signedData` - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary

`EVM.validateCOAOwnershipProof` is an `access(all)` Cadence function that verifies Flow account key signatures over an arbitrary `signedData` blob, then separately checks that the COA at the given `path` matches the supplied `evmAddress`. Because the function does not enforce that `signedData` encodes `evmAddress`, any valid signature produced by a Flow account key — regardless of its original purpose — can be replayed to "prove" ownership of any COA controlled by that same Cadence account. The code comment explicitly acknowledges this gap but dismisses it as low-risk. The function is callable directly by any unprivileged Cadence script or transaction, making the replay reachable without any privileged access.

### Finding Description

`EVM.validateCOAOwnershipProof` accepts six parameters: `address`, `path`, `signedData`, `keyIndices`, `signatures`, and `evmAddress`. The signature verification step checks only that the provided signatures are valid over `signedData` using the account's keys: [1](#0-0) 

The `evmAddress` is then checked against the COA resource stored at `path`: [2](#0-1) 

These two checks are entirely independent. The signature does not commit to `evmAddress`. The code comment at lines 1003–1009 explicitly acknowledges this:

> "this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [3](#0-2) 

The function is declared `access(all)`: [4](#0-3) 

This means any Cadence script or transaction can call it directly, bypassing the EVM precompile path (`verifyCOAOwnershipProof`) which always pins `evmAddress` to `address(this)`. [5](#0-4) 

### Impact Explanation

An attacker who observes any valid signature produced by a victim's Flow account key (over any `signedData`) can replay it to obtain a `ValidationResult{isValid: true}` for any COA owned by that same Cadence account, by calling `EVM.validateCOAOwnershipProof` directly with:
- `address` = victim's Cadence address
- `path` = path to a different COA (e.g., `/public/coaB`)
- `signedData` = the observed signed bytes (not necessarily related to `coaB`)
- `evmAddress` = the EVM address of `coaB`

Any on-chain Cadence protocol that calls `EVM.validateCOAOwnershipProof` directly to gate privileged actions (asset transfers, authorization decisions) is vulnerable to this cross-address replay. The `COAOwnershipProof` struct does not include `evmAddress` in its encoded form, so the proof carries no binding to a specific COA: [6](#0-5) 

### Likelihood Explanation

The preconditions are:
1. A Cadence account controls more than one COA (at different capability paths).
2. The attacker observes a valid signature from that account over any data (e.g., from a prior off-chain authentication flow or a public on-chain event).
3. A Cadence contract or transaction uses `EVM.validateCOAOwnershipProof` directly to gate a privileged action.

Condition 1 is possible since the EVM contract imposes no limit on the number of COAs per account. Condition 2 is realistic for any account that participates in off-chain signing flows. Condition 3 is the realistic deployment scenario for any Cadence-native protocol that integrates COA ownership proofs for authorization.

### Recommendation

Enforce that `signedData` encodes `evmAddress` inside `validateCOAOwnershipProof` itself, rather than relying on callers to do so. Concretely, before verifying signatures, the function should assert that `signedData` contains the bytes of `evmAddress` (or reconstruct the expected signed payload from `evmAddress` and verify against that). This mirrors the fix recommended in the PhiFactory report: the validation function itself must bind the signature to the context it is authorizing.

### Proof of Concept

```cadence
import EVM from <EVM_contract_address>

// Attacker transaction:
// - victim has two COAs: coaA at /public/coaA, coaB at /public/coaB
// - attacker observed a signature `sig` from victim over arbitrary `data`
//   (e.g., from a prior off-chain authentication for coaA)
// - attacker replays it to prove ownership of coaB

access(all)
fun main(
    victimAddress: Address,
    data: [UInt8],           // arbitrary data victim signed
    sig: [UInt8],            // victim's signature over `data`
    coaBAddress: [UInt8; 20] // EVM address of victim's second COA
): EVM.ValidationResult {
    return EVM.validateCOAOwnershipProof(
        address: victimAddress,
        path: /public/coaB,   // different COA than what was signed for
        signedData: data,
        keyIndices: [0],
        signatures: [sig],
        evmAddress: coaBAddress
    )
    // Returns isValid: true — signature replay succeeds
}
```

The function verifies the signature over `data` (valid, since victim signed it) and separately confirms that the COA at `/public/coaB` has address `coaBAddress` (also valid). Because `data` is never required to encode `coaBAddress`, the two checks pass independently and the replay succeeds. [7](#0-6) [8](#0-7)

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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1093)
```text
        let isValid = keyList.verify(
            signatureSet: signatureSet,
            signedData: signedData,
            domainSeparationTag: "FLOW-V0.0-user"
        )

        if !isValid{
            return ValidationResult(
                isValid: false,
                problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership for Cadence account \(address). The given signatures are not valid or provide enough weight."
            )
        }
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

**File:** fvm/evm/types/proof.go (L139-144)
```go
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
}
```
