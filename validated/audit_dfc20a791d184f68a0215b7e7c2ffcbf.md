### Title
Cross-COA Ownership Proof Replay: Signature for One COA Accepted as Proof of Ownership for Another COA on the Same Cadence Account - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary

`EVM.validateCOAOwnershipProof` verifies that the provided signatures are cryptographically valid over `signedData` using the Cadence account's keys, and separately checks that the COA resource at the given `path` matches the claimed `evmAddress`. However, it does not enforce that `signedData` encodes `evmAddress`. Because the `CapabilityPath` field inside the `COAOwnershipProof` struct is attacker-controlled and is not covered by the signatures, an attacker can take a valid proof produced by Alice for COA1 and replay it — with only the `CapabilityPath` changed to point to COA2 — to pass ownership verification for COA2. This is the direct Flow analog of the reported session-key impersonation bug: the validator checks "does the signer own a key on this account?" but not "did the signer sign for *this specific* COA?"

### Finding Description

**Root cause — `validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc`:**

The function performs two independent checks:

1. Verify that the supplied `signatures` are cryptographically valid over `signedData` using the Cadence account's keys.
2. Borrow the `CadenceOwnedAccount` capability from `path` and confirm its `.address()` equals `evmAddress`.

The code comment at lines 1001–1009 explicitly acknowledges the gap:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."

The `COAOwnershipProof` struct (in `fvm/evm/types/proof.go`) contains:

```go
type COAOwnershipProof struct {
    KeyIndices     KeyIndices
    Address        FlowAddress
    CapabilityPath PublicPath   // ← attacker-controlled, NOT covered by signatures
    Signatures     Signatures   // ← over SignedData only
}
```

The `Signatures` are over `SignedData` (the `_hash` in ERC-1271 context), **not** over `CapabilityPath` or `evmAddress`. An attacker can freely substitute a different `CapabilityPath` in the proof without invalidating the signatures.

**Attacker-controlled entry path:**

The `isValidSignature` function in `fvm/evm/handler/coa/coa.sol` is the ERC-1271 entry point:

```solidity
function isValidSignature(bytes32 _hash, bytes memory _sig) external view virtual returns (bytes4) {
    (bool ok, bytes memory data) = cadenceArch.staticcall(
        abi.encodeWithSignature("verifyCOAOwnershipProof(address,bytes32,bytes)", address(this), _hash, _sig)
    );
    ...
}
```

`_sig` is the RLP-encoded `COAOwnershipProof` — fully attacker-supplied. `address(this)` is the calling COA's EVM address (COA2 in the attack). `_hash` is the message hash being verified.

`DecodeABIEncodedProof` in `fvm/evm/precompiles/arch.go` extracts `caller` (= COA2's EVM address), `hash` (= `_hash`), and `encodedProof` (= attacker-modified proof with `CapabilityPath` pointing to COA2), then calls `validateCOAOwnershipProof` with `evmAddress = COA2`.

**Exploit flow:**

1. Alice has two COAs on the same Cadence account: COA1 at `/public/coa1` and COA2 at `/public/coa2`.
2. Alice legitimately signs `_hash` for COA1, producing a `COAOwnershipProof` with `CapabilityPath = "coa1"`.
3. The attacker obtains this proof (from on-chain data or off-chain communication).
4. The attacker constructs a modified proof: same `Address`, same `KeyIndices`, same `Signatures`, but `CapabilityPath = "coa2"`.
5. The attacker calls `COA2.isValidSignature(_hash, modified_proof)` via an EVM transaction.
6. `validateCOAOwnershipProof` is invoked with `evmAddress = COA2_address`:
   - Signature check: Alice's signatures over `_hash` are valid for her account keys → **passes**.
   - COA address check: COA at `/public/coa2` has address `COA2_address` → **passes**.
   - Returns `isValid: true`.
7. The EVM contract accepts the proof as valid authorization from Alice for COA2 — but Alice never signed for COA2.

### Impact Explanation

Any EVM contract that uses ERC-1271 (`isValidSignature`) to gate privileged actions on COA2 — token approvals, NFT transfers, DeFi protocol interactions, multisig participation — will accept a proof that Alice never intended for COA2. This constitutes unauthorized authorization of EVM actions on behalf of COA2, directly analogous to the reported bug where SK2 consumes SK1's session without SK1 signing. The impact is unauthorized movement of on-chain assets controlled by COA2.

### Likelihood Explanation

The attack requires Alice to have two COAs on the same Cadence account. The code comment acknowledges this is currently rare ("Flow wallets historically create at most one COA per account"), but the protocol explicitly permits multiple COAs, and the attack surface grows as the EVM-on-Flow ecosystem matures and more sophisticated users or contracts create multiple COAs per account. The attacker needs only Alice's valid proof for COA1, which is obtainable from on-chain transaction data once Alice has used COA1's `isValidSignature` in any prior transaction. No privileged access is required.

### Recommendation

Enforce that `signedData` commits to `evmAddress`. The simplest fix is to require that `signedData` is a hash that includes the target EVM address (e.g., `keccak256(abi.encode(evmAddress, applicationHash))`). Alternatively, `validateCOAOwnershipProof` itself should verify that `signedData` encodes `evmAddress` before accepting the proof, rather than leaving this as a caller responsibility documented only in a comment.

### Proof of Concept

**Setup:** Alice's Cadence account has two COAs:
- COA1 stored at `/storage/coa1`, capability published at `/public/coa1`, EVM address `0xCOA1`
- COA2 stored at `/storage/coa2`, capability published at `/public/coa2`, EVM address `0xCOA2`

**Step 1 — Alice legitimately signs for COA1:**
```
signedData = _hash  (some application message hash)
proof1 = COAOwnershipProof{
    Address:        Alice_cadence_address,
    CapabilityPath: "coa1",
    KeyIndices:     [0],
    Signatures:     [sign(Alice_key0, _hash)],
}
```

**Step 2 — Attacker constructs modified proof for COA2:**
```
proof2 = COAOwnershipProof{
    Address:        Alice_cadence_address,
    CapabilityPath: "coa2",   // ← changed, NOT covered by signatures
    KeyIndices:     [0],
    Signatures:     [sign(Alice_key0, _hash)],  // ← same signatures, still valid
}
```

**Step 3 — Attacker calls `COA2.isValidSignature(_hash, RLP_encode(proof2))`:**

Inside `validateCOAOwnershipProof`:
- `keyList.verify(signatureSet, signedData=_hash, ...)` → `true` (Alice's key signed `_hash`)
- `acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(/public/coa2)` → COA2 resource
- `coaRef.address().bytes == evmAddress (0xCOA2)` → `true`
- Returns `ValidationResult(isValid: true)`

**Result:** The EVM contract believes Alice authorized the action for COA2. Alice only ever signed for COA1. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1110)
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

**File:** fvm/evm/precompiles/arch.go (L219-243)
```go
func DecodeABIEncodedProof(input []byte) (*types.COAOwnershipProofInContext, error) {
	index := 0
	caller, err := ReadAddress(input, index)
	index += FixedSizeUnitDataReadSize
	if err != nil {
		return nil, err
	}

	hash, err := ReadBytes32(input, index)
	index += Bytes32DataReadSize
	if err != nil {
		return nil, err
	}

	encodedProof, err := ReadBytes(input, index)
	if err != nil {
		return nil, err
	}

	return types.NewCOAOwnershipProofInContext(
		hash,
		types.Address(caller),
		encodedProof,
	)
}
```

**File:** fvm/evm/handler/coa/coa.sol (L113-125)
```text
    // ERC1271 requirement 
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
