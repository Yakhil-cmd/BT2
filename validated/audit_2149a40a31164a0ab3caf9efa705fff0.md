### Title
COA Ownership Proof Signature Not Bound to EVM Address Enables Cross-COA Replay - (File: fvm/evm/stdlib/contract.cdc)

### Summary
`EVM.validateCOAOwnershipProof` does not enforce that `signedData` encodes the target `evmAddress`. A signature produced by a Cadence account for one COA can be replayed verbatim to obtain a valid ownership proof for any other COA owned by the same Cadence account, bypassing access controls in Cadence contracts that gate on-chain assets behind COA ownership verification.

### Finding Description
`validateCOAOwnershipProof` is an `access(all)` Cadence function that accepts caller-supplied `signedData`, `keyIndices`, `signatures`, and `evmAddress`. It verifies that the signatures over `signedData` are valid for the Cadence account at `address`, then checks that the COA resource at `path` has the EVM address `evmAddress`. The function never checks that `signedData` encodes `evmAddress`.

The code itself acknowledges this:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [1](#0-0) 

Because `validateCOAOwnershipProof` is `access(all)`, any unprivileged Cadence script or transaction can call it directly with an arbitrary `evmAddress` argument. The function signature: [2](#0-1) 

The verification logic checks the signature against `signedData` and separately checks that the COA at `path` matches `evmAddress`, but never binds the two together: [3](#0-2) [4](#0-3) 

### Impact Explanation
If a Cadence account owns two COAs (COA-1 at EVM address E1, COA-2 at EVM address E2), and a valid signature over arbitrary `signedData` from that account is observable on-chain (e.g., from a prior legitimate call to `verifyCOAOwnershipProof` in an EVM transaction), an attacker can:

1. Take the observed `signedData` and `signatures`.
2. Call `EVM.validateCOAOwnershipProof(address: A, path: /public/coa2, signedData: D, keyIndices: [...], signatures: [...], evmAddress: E2)`.
3. Receive `isValid: true` — a forged proof for COA-2 — even though the account holder only signed for COA-1.

Any Cadence contract that uses `validateCOAOwnershipProof` to gate access to on-chain assets (vaults, NFTs, bridge escrow) based on COA ownership is vulnerable to this bypass. The authorization token (the signature) is not bound to the specific EVM address it is intended to authorize, directly analogous to the reported pattern of nonces not being tracked per-address.

### Likelihood Explanation
The preconditions are:
- A Cadence account owns more than one COA (possible; no protocol restriction prevents it).
- A Cadence contract uses `validateCOAOwnershipProof` to gate access to on-chain assets.
- A prior valid signature from the target account is observable on-chain.

As the Flow EVM ecosystem grows and off-chain authentication flows or Cadence-level access control based on COA ownership become more common, all three conditions become increasingly likely to co-occur. The entry path requires no special privileges — any unprivileged transaction sender can call the `access(all)` function.

### Recommendation
Enforce that `signedData` encodes `evmAddress` inside `validateCOAOwnershipProof` before verifying signatures, or document and enforce this requirement at the call site. Concretely, the function should verify that the first 20 bytes of `signedData` match `evmAddress` (or use a structured encoding), rejecting proofs where the signed payload does not commit to the target EVM address. This mirrors the fix described in the external report: binding the authorization token to the specific address it is intended to authorize.

### Proof of Concept
```
// Attacker script (no special privileges required)
import EVM from 0x<EVMContractAddress>

access(all)
fun main() {
    // signedData and signatures observed on-chain from Alice's prior
    // legitimate use of verifyCOAOwnershipProof for COA-1 (E1).
    let signedData: [UInt8] = <observed_signed_data>
    let keyIndices: [UInt64] = [0]
    let signatures: [[UInt8]] = [<observed_signature>]

    // Alice's Cadence account also owns COA-2 at E2, stored at /public/coa2.
    let result = EVM.validateCOAOwnershipProof(
        address: <alice_cadence_address>,
        path: /public/coa2,
        signedData: signedData,
        keyIndices: keyIndices,
        signatures: signatures,
        evmAddress: <E2_bytes>   // COA-2's address, not COA-1's
    )
    // result.isValid == true — forged proof for COA-2
    assert(result.isValid, message: "cross-COA replay succeeded")
}
```

The signature check passes because Alice's key signed `signedData` (valid for her account). The COA address check passes because COA-2 is legitimately at `/public/coa2` with address E2. The function never verifies that `signedData` commits to E2, so the proof is accepted. [5](#0-4)

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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1116)
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
