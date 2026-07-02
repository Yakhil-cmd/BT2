### Title
Cross-COA Ownership Proof Replay via Unbound `signedData` — (`File: fvm/evm/stdlib/contract.cdc`)

### Summary

`validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` verifies signatures over `signedData` but does not bind `signedData` to the specific `evmAddress` (or `CapabilityPath`) being claimed. An attacker who obtains a valid COA ownership proof for one COA can replay it — with a modified `CapabilityPath` — to falsely authenticate as a different COA owned by the same Cadence account. This is the direct Flow analog of the `validateUserOp()` false-positive issue: the authorization check passes for a target the signer never intended to authorize.

---

### Finding Description

`validateCOAOwnershipProof` performs two independent checks:

1. **Signature check** — verifies that the provided signatures are valid over `signedData` using the account's keys and `domainSeparationTag: "FLOW-V0.0-user"`.
2. **COA address check** — borrows the capability at the caller-supplied `path` and checks that the COA's EVM address matches the provided `evmAddress`.

The critical flaw: `signedData` is **not bound** to `evmAddress` or `CapabilityPath`. The `CapabilityPath` is part of the `COAOwnershipProof` struct (encoded in the proof bytes passed to `isValidSignature`), but it is **not included in what is signed**. The code itself acknowledges this:

> *"Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."* [1](#0-0) 

The `CapabilityPath` is a field of `COAOwnershipProof` that is RLP-encoded into the proof bytes but is never signed: [2](#0-1) 

The signature verification uses only `signedData`: [3](#0-2) 

The capability borrow uses the attacker-controlled `path`: [4](#0-3) 

---

### Impact Explanation

An attacker who observes a valid `COAOwnershipProof` for `COA_A` (e.g., from an on-chain transaction) can construct a modified proof with `CapabilityPath` pointing to `COA_B` (another COA of the same Cadence account). Because the signatures are over `signedData` only — not over the `CapabilityPath` or `evmAddress` — the modified proof passes `validateCOAOwnershipProof` for `COA_B`.

This allows the attacker to call `COA_B.isValidSignature(hash, modified_proof)` and receive `ValidERC1271Signature` (`0x1626ba7e`), falsely proving that the Cadence account owner authorized `hash` for `COA_B`. Any EVM protocol relying on `isValidSignature` for authentication (e.g., ERC-4337 account abstraction, off-chain order signing, permit-style approvals) would accept this as a valid authorization for `COA_B`.

The `COA.sol` `isValidSignature` function passes `address(this)` as the EVM address to the precompile, so the attacker only needs to supply a proof with the correct `CapabilityPath` for `COA_B`: [5](#0-4) 

The precompile routes to `validateCOAOwnershipProof` via `coaOwnershipProofValidator`: [6](#0-5) 

---

### Likelihood Explanation

- **Entry path is unprivileged**: any EVM transaction sender can call `COA_B.isValidSignature(hash, modified_proof)` with a replayed proof. No special privileges are required.
- **Proof bytes are observable on-chain**: once Alice submits a transaction that calls `COA_A.isValidSignature(hash, proof)`, the proof bytes are visible in the transaction calldata.
- **Condition**: Alice must have two COAs published at different public paths. While the comment notes this is historically uncommon, it is not prevented by the protocol, and multi-COA setups are a natural consequence of bridging or multi-wallet patterns.
- **Modification is trivial**: the attacker only needs to change the `CapabilityPath` field in the RLP-encoded proof bytes; the signatures remain valid.

---

### Recommendation

Bind `signedData` to the specific `evmAddress` (and optionally `CapabilityPath`) being claimed. The simplest fix is to require that `signedData` is a commitment over `evmAddress`, e.g.:

```cadence
// Enforce that signedData encodes evmAddress
let expectedPrefix: [UInt8] = evmAddress.toConstantSized()!.toVariableSized()
// signedData must start with or hash-commit to evmAddress
```

Alternatively, enforce this at the precompile level in `DecodeABIEncodedProof` / `NewCOAOwnershipProofInContext` by constructing `signedData` as `keccak256(abi.encode(evmAddress, hash))` before passing it to `validateCOAOwnershipProof`, so the signed payload is always address-scoped. [7](#0-6) 

---

### Proof of Concept

1. Alice owns Cadence account `0xAlice` with two COAs:
   - `COA_A` stored at `/storage/coaA`, published at `/public/coaA`
   - `COA_B` stored at `/storage/coaB`, published at `/public/coaB`

2. Alice signs `hash` to prove ownership of `COA_A` for some EVM protocol. The proof is:
   ```
   COAOwnershipProof {
     Address:        0xAlice,
     CapabilityPath: "coaA",
     KeyIndices:     [0],
     Signatures:     [sig_over_hash]
   }
   ```

3. Attacker observes this proof on-chain and constructs a modified proof:
   ```
   COAOwnershipProof {
     Address:        0xAlice,
     CapabilityPath: "coaB",   // <-- changed
     KeyIndices:     [0],
     Signatures:     [sig_over_hash]  // <-- unchanged, still valid
   }
   ```

4. Attacker calls `COA_B.isValidSignature(hash, rlp_encode(modified_proof))`.

5. `COA_B.isValidSignature` calls `verifyCOAOwnershipProof(address(COA_B), hash, modified_proof)`.

6. The precompile calls `validateCOAOwnershipProof(0xAlice, /public/coaB, hash, [0], [sig_over_hash], COA_B_address)`.

7. `keyList.verify(signatureSet, signedData: hash, domainSeparationTag: "FLOW-V0.0-user")` → **passes** (Alice's key signed `hash`).

8. `acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(/public/coaB)` → returns `COA_B` resource.

9. `coaRef.address().bytes == COA_B_address` → **matches**.

10. Returns `ValidationResult(isValid: true)` → `COA_B.isValidSignature` returns `0x1626ba7e` (valid).

The attacker has successfully impersonated Alice's authorization for `COA_B` using a signature Alice only produced for `COA_A`. [8](#0-7)

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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1115)
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
```

**File:** fvm/evm/types/proof.go (L108-118)
```go
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
