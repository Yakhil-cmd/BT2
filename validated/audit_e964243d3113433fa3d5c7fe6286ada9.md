### Title
Cross-COA Signature Replay in `validateCOAOwnershipProof` Enables ERC-1271 Impersonation - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` does not enforce that `signedData` encodes the `evmAddress` being proven. Because the encoded `COAOwnershipProof` wire format contains only `address`, `path`, `keyIndices`, and `signatures` — and `signedData` / `evmAddress` are supplied as separate, independent arguments — an attacker can take a proof the victim produced for COA\_A, swap the `path` field to point at COA\_B (a second COA owned by the same Cadence account), and replay it against COA\_B's `isValidSignature` ERC-1271 endpoint. The verification passes, making COA\_B appear to have signed data it never signed.

---

### Finding Description

`validateCOAOwnershipProof` performs two checks:

1. The supplied `signatures` are cryptographically valid for the Cadence account's keys over `signedData`.
2. The COA capability at `path` in the account has an EVM address equal to `evmAddress`.

Neither check binds `signedData` to `evmAddress`. The code itself documents this gap:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [1](#0-0) 

The on-chain `COAOwnershipProof` struct (the RLP-encoded blob passed as `_sig` to `isValidSignature`) contains only `KeyIndices`, `Address`, `CapabilityPath`, and `Signatures`: [2](#0-1) 

`SignedData` and `EVMAddress` are not part of the encoded proof; they are injected separately at call time: [3](#0-2) 

The COA's `isValidSignature` ERC-1271 implementation passes `address(this)` as `evmAddress` and the caller-supplied `_hash` as `signedData`: [4](#0-3) 

Because `CapabilityPath` is attacker-controlled inside the encoded proof blob, an attacker can:

1. Obtain a legitimate `encodedProof` the victim produced for COA\_A (e.g., from a dApp authentication flow).
2. Re-encode the proof with `CapabilityPath` changed to COA\_B's public path.
3. Call `COA_B.isValidSignature(H, modifiedProof)`.

The precompile calls `validateCOAOwnershipProof` with:
- `address` = victim's Cadence address (from proof)
- `path` = `/public/coaB` (attacker-modified)
- `signedData` = H (the hash the victim signed for COA\_A)
- `signatures` = victim's original signatures over H
- `evmAddress` = COA\_B's EVM address (from `address(this)`)

Both checks pass: the signatures are valid over H for the victim's keys, and the COA at `/public/coaB` does match COA\_B's EVM address. The function returns `isValid: true`. [5](#0-4) 

The precompile validator that bridges this into Go confirms it passes the proof fields through without any binding check between `signedData` and `evmAddress`: [6](#0-5) 

---

### Impact Explanation

Any EVM contract on Flow that uses ERC-1271 (`isValidSignature`) to authorize asset transfers, approvals, or governance votes against a COA address can be deceived. An attacker who holds a proof the victim generated for COA\_A can make COA\_B appear to have signed an arbitrary hash. If COA\_B holds ERC-20 tokens, NFTs, or governance weight, the attacker can use the forged ERC-1271 response to authorize transfers or votes on COA\_B's behalf without the owner's consent — directly analogous to the ToyBox permit-spoofing that drains tokens from users who gave spending approval.

**Impact: High** — unauthorized EVM-level asset authorization via forged ERC-1271 response.

---

### Likelihood Explanation

**Likelihood: Low-Medium.**

- The victim must own at least two COAs under the same Cadence account (uncommon today but not prohibited by the protocol).
- The attacker must have obtained a valid encoded proof the victim produced for COA\_A (realistic if the victim authenticated with any dApp using COA ownership proofs).
- No privileged access, staked node control, or key compromise is required; the attack is a pure data-manipulation replay executable by any unprivileged transaction sender.

The code comment acknowledges the gap and defers the fix to callers, but no on-chain enforcement exists.

---

### Recommendation

Enforce inside `validateCOAOwnershipProof` that `signedData` encodes `evmAddress`. Concretely, before verifying signatures, check that the first 20 bytes (or a well-known ABI/RLP encoding) of `signedData` match `evmAddress`. Alternatively, define a canonical signed payload format that commits to both the Cadence address and the EVM address, and reject proofs whose `signedData` does not conform. [7](#0-6) 

---

### Proof of Concept

```
1. Victim creates two COAs:
     COA_A stored at /storage/coaA, published at /public/coaA
     COA_B stored at /storage/coaB, published at /public/coaB

2. Victim authenticates with dApp using COA_A:
     dApp requests a COA ownership proof over hash H.
     Victim signs H with their Cadence key and returns:
       encodedProof_A = RLP{ address: victim, path: /public/coaA,
                              keyIndices: [0], signatures: [sig_H] }

3. Attacker intercepts encodedProof_A and re-encodes:
       encodedProof_B = RLP{ address: victim, path: /public/coaB,
                              keyIndices: [0], signatures: [sig_H] }
     (only CapabilityPath changed; signatures are unchanged because
      they cover H, not the proof struct itself)

4. Attacker calls COA_B.isValidSignature(H, encodedProof_B).

5. coa.sol forwards to verifyCOAOwnershipProof(COA_B_evmAddr, H, encodedProof_B).

6. validateCOAOwnershipProof runs:
     - keyList.verify(signatureSet, signedData=H, ...) → true  ✓
       (sig_H is a valid signature over H by victim's key)
     - acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(/public/coaB)
       .address() == COA_B_evmAddr → true  ✓
     → returns ValidationResult(isValid: true)

7. isValidSignature returns ValidERC1271Signature (0x1626ba7e) for COA_B.

8. Any EVM contract that trusted this response now believes COA_B
   authorized hash H — enabling unauthorized approvals or asset transfers
   from COA_B without the owner's knowledge.
```

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

**File:** fvm/evm/handler/coa/coa.sol (L114-120)
```text
    function isValidSignature(
        bytes32 _hash,
        bytes memory _sig
    ) external view virtual returns (bytes4){
        (bool ok, bytes memory data) = cadenceArch.staticcall(abi.encodeWithSignature("verifyCOAOwnershipProof(address,bytes32,bytes)", address(this), _hash, _sig));
        require(ok);
        bool output = abi.decode(data, (bool));
```

**File:** fvm/evm/handler/precompiles.go (L115-152)
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
		if err != nil {
			if types.IsAFatalError(err) {
				panic(err)
			}
			return false, err
		}
		data, ok := value.(cadence.Struct)
		if !ok {
			return false, fmt.Errorf("invalid output data received from validateCOAOwnershipProof")
		}

		isValidValue := cadence.SearchFieldByName(data, ValidationResultTypeIsValidFieldName)
		if isValidValue == nil {
			return false, fmt.Errorf("invalid output data received from validateCOAOwnershipProof")
		}

		return bool(isValidValue.(cadence.Bool)), nil
	}
```
