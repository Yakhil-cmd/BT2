### Title
Lack of Replay Protection in `validateCOAOwnershipProof` Signature Schema Enables Permanent ERC-1271 Approval Replay — (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` verifies Cadence account key signatures over an arbitrary `signedData` blob using the generic `"FLOW-V0.0-user"` domain separation tag. The schema enforces no nonce, no expiry, and no binding of `signedData` to `evmAddress`. Once a COA owner has signed any message `H` with that tag, the signature is permanently replayable: any unprivileged EVM transaction can call `isValidSignature(H, proof)` on the COA and receive `ValidERC1271Signature` indefinitely, even after the owner intends to revoke the approval.

---

### Finding Description

`EVM.validateCOAOwnershipProof` (the Cadence function) and the `verifyCOAOwnershipProof` Cadence Arch precompile together implement ERC-1271 for Cadence-Owned Accounts (COAs). The signature verification path is:

1. An EVM caller invokes `COA.isValidSignature(bytes32 _hash, bytes _sig)` in `coa.sol`.
2. `isValidSignature` staticcalls `verifyCOAOwnershipProof(address(this), _hash, _sig)` on the Cadence Arch precompile.
3. The precompile decodes the proof and calls `EVM.validateCOAOwnershipProof(address, path, signedData, keyIndices, signatures, evmAddress)` in Cadence.
4. `validateCOAOwnershipProof` calls `keyList.verify(signatureSet: signatureSet, signedData: signedData, domainSeparationTag: "FLOW-V0.0-user")`.

The `signedData` field is the raw `_hash` bytes passed by the EVM caller. The function performs **no check** that `signedData` encodes a nonce, a timestamp, or the `evmAddress`. The code itself acknowledges this:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [1](#0-0) 

The `"FLOW-V0.0-user"` domain tag is a **generic** user-level tag, not scoped to COA ownership proofs. Any signature Alice produces with that tag for any Cadence-level purpose (e.g., a Cadence-based authentication flow) is structurally identical to a COA ownership proof signature and can be replayed through `isValidSignature`. [2](#0-1) 

The COA's `isValidSignature` implementation in `coa.sol` passes `address(this)` as the `evmAddress` argument, so the address-binding check at lines 1095–1109 does prevent cross-COA replay **through the EVM precompile path**. However, the absence of a nonce means the signature is permanently valid for the same COA and the same hash. [3](#0-2) 

The precompile decodes the proof and forwards it to the Cadence validator without adding any replay-prevention context: [4](#0-3) [5](#0-4) 

The `COAOwnershipProof` struct itself contains no nonce or timestamp field: [6](#0-5) 

---

### Impact Explanation

Any EVM protocol that uses ERC-1271 with a COA (e.g., a DEX order book, a lending protocol, a meta-transaction relayer) and relies on the COA owner being able to revoke a prior approval is permanently broken. Once Alice signs hash `H` (e.g., to approve a DEX order), that signature is valid forever. Alice cannot cancel the approval without revoking her Cadence account key entirely — a drastic action that disables all transactions from that account. An attacker (or the protocol itself) can replay the old signature at any future block to execute the action Alice intended to cancel, causing unauthorized movement of assets from the COA.

Additionally, because `"FLOW-V0.0-user"` is a generic tag, a signature Alice produces for a Cadence-level purpose (e.g., a Cadence-based login or off-chain attestation) can be replayed through `isValidSignature` if the signed bytes happen to match a hash an EVM protocol is checking — a cross-context replay directly analogous to the cross-chain replay described in the external report.

---

### Likelihood Explanation

The entry path requires no privilege: any unprivileged EVM transaction can call `isValidSignature` on any COA. The attacker only needs to observe a prior valid signature (e.g., from a previous on-chain transaction or an off-chain signed message). ERC-1271 is the standard mechanism for smart-contract-wallet approvals and is used by virtually every major EVM DeFi protocol. COAs are the primary smart-contract wallet type on Flow EVM. The combination makes this a realistic, high-frequency attack surface.

---

### Recommendation

1. **Bind `signedData` to `evmAddress`**: Enforce inside `validateCOAOwnershipProof` that `signedData` encodes the `evmAddress` bytes, preventing cross-address replay and making the signature purpose-specific.
2. **Add a nonce or expiry**: Introduce a per-COA nonce register (analogous to Flow transaction sequence numbers) or require `signedData` to include a block-height expiry. Increment the nonce on each successful `isValidSignature` call, or reject proofs whose embedded expiry has passed.
3. **Use a COA-specific domain tag**: Replace `"FLOW-V0.0-user"` with a tag that encodes the COA's EVM address (e.g., `"FLOW-COA-<evmAddress>"`) to prevent cross-context replay of generic user signatures.

---

### Proof of Concept

```
1. Alice owns a COA at EVM address COA_A.
2. Alice signs H = keccak256(order_data) with her Cadence key using
   the "FLOW-V0.0-user" tag to approve a DEX order.
   The signed proof is broadcast on-chain (e.g., in a prior EVM tx).

3. Alice submits a cancellation to the DEX (off-chain or on-chain).

4. Attacker (unprivileged EVM EOA) submits an EVM transaction calling:
     dex.fillOrder(order_data, alice_coa_address)
   The DEX internally calls:
     COA_A.isValidSignature(H, alice_proof)  // ERC-1271 check

5. isValidSignature calls:
     verifyCOAOwnershipProof(COA_A_address, H, alice_proof)
   which calls:
     EVM.validateCOAOwnershipProof(alice_cadence_addr, /public/coa,
                                   H, [0], [alice_sig], COA_A_bytes)

6. validateCOAOwnershipProof:
   - Verifies alice_sig over H with "FLOW-V0.0-user" tag → VALID
     (no nonce check, signature is permanently valid)
   - Checks COA at /public/coa has address COA_A → VALID
   - Returns ValidationResult(isValid: true)

7. isValidSignature returns ValidERC1271Signature (0x1626ba7e).
8. DEX executes the order, transferring Alice's tokens — against her will.
```

The root cause is entirely within Flow's `validateCOAOwnershipProof` at `fvm/evm/stdlib/contract.cdc` lines 1082–1086: the signature is verified over caller-supplied `signedData` with no nonce, no expiry, and no binding to `evmAddress`. [2](#0-1)

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

**File:** fvm/evm/types/proof.go (L139-144)
```go
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
}
```
