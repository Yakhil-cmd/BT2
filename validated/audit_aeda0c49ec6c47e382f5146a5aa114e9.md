### Title
Cross-COA Signature Replay in `validateCOAOwnershipProof` Bypasses ERC-1271 Authentication — (`fvm/evm/stdlib/contract.cdc`)

---

### Summary

`validateCOAOwnershipProof` verifies that a set of Cadence account key signatures are valid over `signedData`, then checks that the COA at the supplied `path` has an address matching `evmAddress`. It never checks that `signedData` encodes `evmAddress`. A signature produced for COA-A is therefore valid proof of ownership for COA-B (owned by the same Cadence account) if the attacker supplies a proof whose `CapabilityPath` points to COA-B. The code itself documents this gap.

---

### Finding Description

**Root cause — `fvm/evm/stdlib/contract.cdc` lines 1082–1109**

The function performs two independent checks:

1. Signature validity over `signedData` with domain tag `"FLOW-V0.0-user"`: [1](#0-0) 

2. COA address match at the caller-supplied `path`: [2](#0-1) 

There is no step that binds `signedData` to `evmAddress`. The code's own comment at lines 1002–1009 explicitly acknowledges this:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [3](#0-2) 

**How the precompile exposes this**

`DecodeABIEncodedProof` in `fvm/evm/precompiles/arch.go` reads three independent fields from the ABI-encoded call: `caller` (the EVM address asserted), `hash` (the `signedData`), and `encodedProof` (the RLP-encoded `COAOwnershipProof` containing `CapabilityPath` and `Signatures`): [4](#0-3) 

The `COAOwnershipProof` struct carries `CapabilityPath` as an attacker-controlled field: [5](#0-4) 

Because `CapabilityPath` is part of the caller-supplied `encodedProof` bytes, an attacker can freely substitute the path from COA-A to COA-B while keeping the same `Signatures` and `signedData`.

**`isValidSignature` on COA-B is the concrete impact surface**

`coa.sol`'s `isValidSignature` hardcodes `address(this)` as the EVM address argument: [6](#0-5) 

When an attacker calls `isValidSignature` on COA-B and supplies a `_sig` whose embedded `CapabilityPath` points to COA-B (but whose `Signatures` were produced over `_hash` for COA-A), the precompile:
- verifies the signatures over `_hash` → **passes** (same key, same data)
- checks the COA at the COA-B path has address COA-B → **passes**
- returns `ValidERC1271Signature`

---

### Impact Explanation

Any EVM contract that relies on `isValidSignature` on COA-B to authenticate the Cadence account owner (e.g., a multisig, a vault, a bridge authorization gate) will accept the replayed proof as a valid authorization from the COA-B owner. The attacker never held the account's private key and never produced a signature intended for COA-B. This constitutes impersonation of a COA the attacker does not own, bypassing ERC-1271 authentication — matching the stated Critical scope of "unauthorized access to sandboxed host capabilities."

---

### Likelihood Explanation

Two preconditions must hold:

1. **Victim account has two COAs.** The protocol does not prevent this; `createCadenceOwnedAccount()` can be called multiple times and stored at different public paths. It is unusual today but is a valid, supported configuration.

2. **Attacker possesses a valid Cadence key signature over the target `_hash`.** This is obtained by observing a prior on-chain `isValidSignature` call on COA-A (all parameters, including the RLP-encoded proof with raw signatures, are visible in transaction/call data). No private key theft or social engineering is required — passive on-chain observation suffices.

Both conditions are realistic for any account that operates two COAs and has previously used COA-A for ERC-1271 authentication.

---

### Recommendation

Bind `signedData` to `evmAddress` inside `validateCOAOwnershipProof` before verifying signatures. The simplest fix is to require that `signedData` is (or commits to) the ABI/RLP encoding of `evmAddress`, or to construct the message that is verified as `hash(evmAddress || callerSuppliedData)` inside the function itself, so that a signature over COA-A's address cannot satisfy the check for COA-B. The comment at lines 1002–1009 already identifies the correct mitigation ("Callers building off-chain authentication flows on top of this function should ensure `signedData` encodes `evmAddress`"); the fix is to enforce this invariant inside the function rather than leaving it as a caller responsibility.

---

### Proof of Concept

```
Setup (emulator):
  1. Create Cadence account A.
  2. Call createCadenceOwnedAccount() twice; store COA-A at /public/coaA, COA-B at /public/coaB.
  3. Record COA-A's EVM address (addrA) and COA-B's EVM address (addrB).

Capture signature:
  4. Sign bytes32 H with account A's key (domain tag "FLOW-V0.0-user").
  5. Build proof_A = RLP{KeyIndices:[0], Address:A, CapabilityPath:"coaA", Signatures:[sig]}.
  6. Call isValidSignature(H, proof_A) on COA-A → expect ValidERC1271Signature (baseline).

Replay against COA-B:
  7. Build proof_B = RLP{KeyIndices:[0], Address:A, CapabilityPath:"coaB", Signatures:[sig]}.
     (identical signatures, only CapabilityPath changed)
  8. Call isValidSignature(H, proof_B) on COA-B.

Expected (secure): InvalidERC1271Signature
Actual (vulnerable): ValidERC1271Signature
```

The proof_B construction requires no private key — only the publicly observable `sig` bytes from step 5 and knowledge of the COA-B path.

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1002-1009)
```text
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

**File:** fvm/evm/stdlib/contract.cdc (L1095-1109)
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
```

**File:** fvm/evm/precompiles/arch.go (L219-242)
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

**File:** fvm/evm/handler/coa/coa.sol (L118-120)
```text
        (bool ok, bytes memory data) = cadenceArch.staticcall(abi.encodeWithSignature("verifyCOAOwnershipProof(address,bytes32,bytes)", address(this), _hash, _sig));
        require(ok);
        bool output = abi.decode(data, (bool));
```
