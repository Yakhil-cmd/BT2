### Title
Cross-COA Signature Replay in `validateCOAOwnershipProof` Allows Impersonating a Different COA Owned by the Same Cadence Account - (File: fvm/evm/stdlib/contract.cdc)

### Summary

`EVM.validateCOAOwnershipProof` verifies that a set of Cadence account key signatures cover `signedData`, then separately checks that the COA resource at the caller-supplied `path` matches the caller-supplied `evmAddress`. Neither `evmAddress` nor `CapabilityPath` is required to be included in `signedData`. Because the `COAOwnershipProof` struct's `CapabilityPath` field is not covered by the signatures, an attacker who observes a valid proof for COA_A can freely substitute the `CapabilityPath` to point to COA_B (another COA owned by the same Cadence account) and replay the original signatures to make COA_B appear to have signed data it never signed.

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` accepts six parameters: `address`, `path`, `signedData`, `keyIndices`, `signatures`, and `evmAddress`. The cryptographic check at line 1082–1086 verifies only that the provided `signatures` are valid over `signedData` using the account's keys:

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

After that, the function checks that the COA resource at the caller-supplied `path` has an EVM address matching the caller-supplied `evmAddress` (lines 1095–1105). Neither `path` nor `evmAddress` is part of `signedData`. The code itself acknowledges the `evmAddress` omission in a comment at lines 1003–1009, but does not acknowledge that `CapabilityPath` is equally uncovered.

The `COAOwnershipProof` struct (in `fvm/evm/types/proof.go`) encodes `CapabilityPath` as a plain RLP field alongside `KeyIndices`, `Address`, and `Signatures`. The signatures cover only the external `signedData` blob, not the proof struct fields. An attacker can therefore take a valid proof `{KeyIndices, Address, CapabilityPath="/public/coa1", Signatures}` and produce a new proof `{KeyIndices, Address, CapabilityPath="/public/coa2", Signatures}` with the same signatures, pointing to a different COA owned by the same Cadence account.

The `isValidSignature` function in `fvm/evm/handler/coa/coa.sol` (line 118) calls the `verifyCOAOwnershipProof` precompile with `address(this)` as the EVM address and the caller-supplied `_sig` as the encoded proof. An attacker who calls `isValidSignature` on COA_B with a proof whose `CapabilityPath` points to `/public/coa2` and whose signatures were originally produced for COA_A will pass both checks: the signatures are cryptographically valid over `signedData`, and the COA at `/public/coa2` does match COA_B's EVM address.

### Impact Explanation

Any EVM contract that uses ERC-1271 (`isValidSignature`) to authenticate a COA — including DEX order books, NFT marketplaces, governance contracts, and token permit systems — will accept the replayed proof as a valid signature from COA_B. This allows an attacker to:

- Impersonate the owner of COA_B in any ERC-1271 authentication flow.
- Authorize token transfers, NFT listings, or governance votes on behalf of COA_B without the account owner's consent.
- Bypass access controls in any EVM smart contract that relies on `isValidSignature` for COA authentication.

The impact is unauthorized authentication / authorization bypass leading to potential asset loss.

### Likelihood Explanation

The attack requires a Cadence account that has published two or more COA capabilities at different public paths. While the comment notes this is historically uncommon, the protocol does not enforce a one-COA-per-account limit. As the Flow EVM ecosystem grows and multi-COA patterns emerge (e.g., separating a "hot" COA from a "cold" COA on the same Cadence account), this becomes increasingly realistic. The attacker only needs to observe one valid proof for any COA on the target account — a proof that is routinely broadcast on-chain whenever `isValidSignature` is called.

### Recommendation

1. **Bind `evmAddress` into `signedData`**: Require that `signedData` encodes the target `evmAddress`. The function should verify this binding before accepting the proof.
2. **Bind `CapabilityPath` into `signedData`**: Similarly, require that `signedData` encodes the `CapabilityPath` so that a proof for one COA cannot be redirected to another.
3. **Alternatively, include `evmAddress` and `CapabilityPath` in the signed message at the protocol level**: Construct the message to be signed as `hash(evmAddress || capabilityPath || signedData)` inside `validateCOAOwnershipProof`, so that the caller-supplied parameters are always covered by the signature regardless of what the off-chain signer included.

### Proof of Concept

**Setup**: Cadence account `A` owns two COAs:
- COA_1 at `/storage/coa1`, published at `/public/coa1`
- COA_2 at `/storage/coa2`, published at `/public/coa2`

**Step 1**: A legitimate party calls `COA_1.isValidSignature(hash, proof1)` where `proof1 = {KeyIndices:[0], Address:A, CapabilityPath:"coa1", Signatures:[sig]}` and `sig = sign(hash)` with account A's key. This succeeds.

**Step 2**: An attacker observes `proof1` and `hash` on-chain. The attacker constructs `proof2 = {KeyIndices:[0], Address:A, CapabilityPath:"coa2", Signatures:[sig]}` — identical except `CapabilityPath` is changed to `"coa2"`. The `sig` bytes are unchanged.

**Step 3**: The attacker calls `COA_2.isValidSignature(hash, proof2)`. Inside `isValidSignature`, `verifyCOAOwnershipProof(address(COA_2), hash, proof2)` is called. `validateCOAOwnershipProof` runs:
- Verifies `sig` over `hash` using account A's key → **passes** (same key, same data).
- Borrows the COA at `/public/coa2` and checks its EVM address equals `address(COA_2)` → **passes** (correct path, correct address).
- Returns `ValidationResult(isValid: true)`.

**Result**: `COA_2.isValidSignature` returns `0x1626ba7e` (valid), even though account A never signed anything for COA_2. Any ERC-1271-gated action on COA_2 is now accessible to the attacker.

---

**Root cause lines**: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
