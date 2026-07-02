### Title
`evmAddress` Not Committed in `signedData` Enables Cross-COA Replay in `EVM.validateCOAOwnershipProof` - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` verifies account key signatures over `signedData` but does not enforce that `signedData` encodes the `evmAddress` being proven. Because the `CapabilityPath` inside the RLP-encoded proof blob is also not covered by the signatures, an attacker who obtains a valid COA ownership proof for one COA (COA1) owned by a Cadence account can replay it against a different COA (COA2) owned by the same account by substituting the `CapabilityPath` field in the proof. The signatures remain valid because they commit only to `signedData`, which contains neither the COA EVM address nor the capability path.

---

### Finding Description

`EVM.validateCOAOwnershipProof` (`access(all)`) performs two independent checks:

1. **Signature check** — verifies that the provided signatures are valid over `signedData` using the account's keys.
2. **Address check** — verifies that the COA resource stored at `path` has an EVM address matching `evmAddress`. [1](#0-0) 

Neither `evmAddress` nor `path` is required to appear inside `signedData`. The code itself acknowledges this: [2](#0-1) 

The `COAOwnershipProof` struct that is RLP-encoded and passed as the `_sig` bytes contains `CapabilityPath` as a plain field: [3](#0-2) 

The signatures inside the proof cover only `signedData` (the `bytes32 _hash`), not the `CapabilityPath`. Therefore, an attacker can freely mutate `CapabilityPath` in the encoded proof without invalidating the signatures.

The EVM-side entry point is the COA contract's `isValidSignature`, which calls the Cadence Arch precompile with `address(this)` as the `evmAddress`: [4](#0-3) 

The precompile's `DecodeABIEncodedProof` reads the caller address from the ABI-encoded input (fixed to `address(this)`) and the encoded proof blob separately: [5](#0-4) 

Because `address(this)` is fixed by the calling contract, the attacker's lever is the `CapabilityPath` inside the mutable `_sig` bytes. By changing `CapabilityPath` from `/public/coa1` to `/public/coa2`, the attacker redirects the address check to COA2 while the signature check still passes (signatures are over `_hash`, which does not include either path).

---

### Impact Explanation

Any EVM contract that uses `isValidSignature` (ERC-1271) for authorization — for example, to authorize token transfers, governance votes, or access-gated operations — can be bypassed if the legitimate account owner has previously signed any hash `H` for COA1 without binding `H` to COA1's address. An attacker replays that proof against COA2 (owned by the same Cadence account), causing the EVM contract at COA2's address to accept the proof as valid and authorize the operation on behalf of COA2's owner.

The impact is **unauthorized authorization** of on-chain operations (e.g., fund transfers) at a COA address the account owner never intended to authorize.

---

### Likelihood Explanation

- The attack requires the same Cadence account to hold **two or more COAs** at distinct capability paths. The code comment notes this is historically uncommon ("Flow wallets historically create at most one COA per account"), but it is not prevented by the protocol.
- The attacker must obtain a valid proof (signatures over some hash `H`) for COA1. This is realistic: any prior ERC-1271 interaction at COA1 produces such a proof, and the proof bytes are observable on-chain.
- No privileged access, staked node control, or key compromise is required. The attack is executable by any unprivileged transaction sender who can call `isValidSignature` on an EVM contract or call `EVM.validateCOAOwnershipProof` directly from a Cadence script/transaction.

Likelihood is **low-to-medium**: the precondition of multiple COAs per account is uncommon today but is not architecturally prevented, and the attack path is straightforward once the precondition is met.

---

### Recommendation

Enforce that `signedData` commits to `evmAddress`. The simplest fix is to require the verifier to check that `signedData` contains the 20-byte `evmAddress` (e.g., as a suffix or via a structured encoding), and reject proofs where it does not. Alternatively, the protocol can internally construct the message to be verified as `hash(signedData || evmAddress)` before calling `keyList.verify`, so that a signature produced for one COA address cannot be replayed for another. [1](#0-0) 

---

### Proof of Concept

**Setup:**
- Cadence account `A` owns COA1 (published at `/public/coa1`, EVM address `0xCOA1`) and COA2 (published at `/public/coa2`, EVM address `0xCOA2`).
- Account `A` previously signed hash `H` for COA1 (e.g., via an ERC-1271 call to COA1's contract). The resulting proof is:
  ```
  proof1 = { Address: A, CapabilityPath: "coa1", KeyIndices: [0], Signatures: [sig(H)] }
  ```

**Attack:**
1. Attacker constructs a modified proof by RLP-re-encoding with `CapabilityPath` changed to `"coa2"`:
   ```
   proof2 = { Address: A, CapabilityPath: "coa2", KeyIndices: [0], Signatures: [sig(H)] }
   ```
   The `Signatures` field is unchanged — `sig(H)` is still a valid signature over `H` by account `A`'s key.

2. Attacker calls `isValidSignature(H, proof2)` on COA2's EVM contract.

3. COA2's contract calls `verifyCOAOwnershipProof(0xCOA2, H, proof2)` on the Cadence Arch precompile.

4. The precompile calls `EVM.validateCOAOwnershipProof(address: A, path: /public/coa2, signedData: H, keyIndices: [0], signatures: [sig(H)], evmAddress: 0xCOA2)`.

5. **Signature check passes**: `sig(H)` is valid over `H` for account `A`'s key.

6. **Address check passes**: the COA at `/public/coa2` has EVM address `0xCOA2`, which matches the `evmAddress` argument.

7. `validateCOAOwnershipProof` returns `isValid: true`.

8. COA2's `isValidSignature` returns `0x1626ba7e` (valid), authorizing the operation at COA2 — even though account `A` only ever signed `H` in the context of COA1. [6](#0-5) [4](#0-3) [5](#0-4)

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
