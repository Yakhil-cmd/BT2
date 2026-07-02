### Title
COA Ownership Proof `CapabilityPath` Is Not Signed, Enabling Cross-COA Replay Attack - (File: fvm/evm/stdlib/contract.cdc)

### Summary
`EVM.validateCOAOwnershipProof` verifies Cadence key signatures over `signedData` and then checks that the capability at the caller-supplied `path` resolves to a COA whose EVM address matches `evmAddress`. Because `path` (the `CapabilityPath` field in the RLP-encoded proof) is not included in the signed data, an attacker who observes a valid proof for COA-A can modify the `CapabilityPath` to point to COA-B — a different COA owned by the same Cadence account — and replay the proof to pass ERC-1271 authentication as COA-B without the account owner's consent.

### Finding Description

**Root cause** — `validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc`:

The function performs two independent checks:

1. It verifies that the provided signatures are cryptographically valid over `signedData` using the Cadence account's keys.
2. It borrows the capability at the caller-supplied `path` and checks that the COA's EVM address matches `evmAddress`. [1](#0-0) 

The `path` parameter originates from the `CapabilityPath` field of the RLP-encoded `COAOwnershipProof` struct. [2](#0-1) 

This field is **not included in the signed data**. The signatures cover only `signedData` (the `_hash` argument). Therefore, an attacker can decode the RLP-encoded proof, swap `CapabilityPath` from `"coaA"` to `"coaB"`, and re-encode it — the original signatures remain cryptographically valid because they were never bound to the path.

The EVM-side entry point is `isValidSignature` in `coa.sol`, which always passes `address(this)` as `evmAddress`: [3](#0-2) 

When the attacker calls `isValidSignature` on COA-B with the modified proof:
- `address(this)` = COA-B's EVM address ✓
- Signatures over `_hash` are still valid for the Cadence account's key ✓
- The capability at `/public/coaB` resolves to COA-B ✓
- COA-B's address matches `evmAddress` ✓

All checks pass. The function returns `ValidERC1271Signature`.

The code comment at lines 1003–1009 explicitly acknowledges this gap but dismisses it as "low-risk" on the assumption that wallets create at most one COA per account: [4](#0-3) 

This assumption is not enforced at the protocol level. `EVM.createCadenceOwnedAccount()` is `access(all)` and can be called any number of times, producing multiple COAs per Cadence account stored at distinct paths. [5](#0-4) 

The `coaOwnershipProofValidator` in `fvm/evm/handler/precompiles.go` is the Go-side bridge that invokes `validateCOAOwnershipProof` from the EVM precompile, passing the attacker-controlled proof fields directly: [6](#0-5) 

The ABI decoding in `DecodeABIEncodedProof` extracts the `caller` address (COA-B's address, from `address(this)`) and the RLP-encoded proof (attacker-modified) without any integrity check binding the proof structure to the EVM address: [7](#0-6) 

### Impact Explanation

Any EVM contract that uses ERC-1271 (`isValidSignature`) to gate access to assets, permissions, or protocol actions is vulnerable. An attacker who observes a valid `COAOwnershipProof` for COA-A (transmitted as public calldata in a prior EVM transaction) can modify the `CapabilityPath` field and replay the proof against COA-B. The result is unauthorized ERC-1271 authentication as COA-B — the attacker is treated as the legitimate owner of COA-B's EVM address for any contract relying on this check. Concrete consequences include unauthorized token withdrawals, NFT transfers, or governance votes gated behind ERC-1271 on COA-B.

### Likelihood Explanation

The preconditions are:
1. The victim Cadence account holds two or more COAs at distinct public capability paths (protocol-permitted, not rare in multi-wallet setups).
2. The attacker observes a valid proof for one COA — proofs are transmitted as EVM calldata and are fully public on-chain.
3. The attacker performs RLP decode → field swap → re-encode, which is straightforward with standard RLP libraries.

No privileged access, leaked keys, or admin control is required. The attack is fully executable by an unprivileged transaction sender who can read on-chain data.

### Recommendation

Bind the signature to the specific COA being claimed by including `evmAddress` (and optionally `CapabilityPath`) in the signed data before verification. Concretely, `validateCOAOwnershipProof` should enforce that `signedData` encodes `evmAddress` — for example, by hashing `evmAddress || userProvidedData` and verifying signatures over that composite value. The EVM-side `isValidSignature` already passes `address(this)` as `evmAddress`, so this binding can be enforced transparently without breaking the existing call convention.

### Proof of Concept

1. Victim creates two COAs: COA-A stored at `/storage/coaA` (published at `/public/coaA`) and COA-B stored at `/storage/coaB` (published at `/public/coaB`).
2. An EVM contract calls `coaA.isValidSignature(_hash, proof)` where `proof` is a valid `COAOwnershipProof` with `CapabilityPath = "coaA"` and signatures over `_hash`. The call succeeds and is recorded on-chain.
3. Attacker reads the `proof` bytes from the transaction calldata.
4. Attacker RLP-decodes the proof, changes `CapabilityPath` from `"coaA"` to `"coaB"`, and RLP-re-encodes it. The `Signatures` field is unchanged.
5. Attacker calls `coaB.isValidSignature(_hash, modifiedProof)`.
6. The EVM precompile invokes `validateCOAOwnershipProof(address: victim, path: /public/coaB, signedData: _hash, keyIndices: [...], signatures: [...], evmAddress: coaB.address)`.
7. Signature verification passes (valid key signatures over `_hash`).
8. `acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(/public/coaB)` succeeds and returns COA-B.
9. COA-B's address equals `evmAddress` (COA-B's address). Check passes.
10. `isValidSignature` returns `ValidERC1271Signature` (0x1626ba7e).
11. The attacker is authenticated as the owner of COA-B in the target EVM contract without the victim's consent for that specific COA.

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L806-817)
```text
    access(all)
    fun createCadenceOwnedAccount(): @CadenceOwnedAccount {
        pre {
            !self.isPaused(): "EVM operations are temporarily paused"
        }
        let acc <-create CadenceOwnedAccount()
        let addr = InternalEVM.createCadenceOwnedAccount(uuid: acc.uuid)
        acc.initAddress(addressBytes: addr)

        emit CadenceOwnedAccountCreated(address: acc.address().toString(), uuid: acc.uuid)
        return <-acc
    }
```

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

**File:** fvm/evm/handler/precompiles.go (L115-153)
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
