### Title
`validateCOAOwnershipProof` Signature Replay — No Nonce or Expiry Binding - (File: fvm/evm/stdlib/contract.cdc)

### Summary

`EVM.validateCOAOwnershipProof` verifies that a Cadence account controls a COA (Cadence-Owned Account) by checking signatures over caller-supplied `signedData`. The function contains no nonce, no expiry, and — as its own inline comment acknowledges — does not enforce that `signedData` encodes the target `evmAddress`. Any valid proof observed on-chain can be replayed indefinitely by an unprivileged EVM transaction sender.

### Finding Description

`EVM.validateCOAOwnershipProof` is a public `access(all)` Cadence function that accepts:
- `address` — the Cadence account whose keys are checked
- `path` — the public capability path to the COA resource
- `signedData` — arbitrary bytes that were signed
- `keyIndices` / `signatures` — the actual cryptographic signatures
- `evmAddress` — the EVM address the COA must match [1](#0-0) 

The function verifies the signatures over `signedData` and then checks that the COA at `path` has address `evmAddress`. It performs **no nonce check, no expiry check, and no binding of `signedData` to `evmAddress`**.

The code itself documents this gap: [2](#0-1) 

The function is reachable from EVM via the Cadence Arch precompile `verifyCOAOwnershipProof(address,bytes32,bytes)`, which any unprivileged EVM transaction can call: [3](#0-2) 

The ERC-1271 `isValidSignature` implementation in `coa.sol` also calls this precompile directly, making every COA an ERC-1271 wallet whose "signature" is a replayable `COAOwnershipProof`: [4](#0-3) 

The `COAOwnershipProof` struct contains no nonce or timestamp field: [5](#0-4) 

### Impact Explanation

An attacker who observes a valid `COAOwnershipProof` (e.g., from a public EVM transaction or off-chain authentication flow) can replay it in any subsequent EVM transaction or script. Because `signedData` is arbitrary and not bound to a nonce or expiry:

1. A proof signed by Alice for EVM dApp X can be replayed to impersonate Alice at EVM dApp Y.
2. A proof signed for COA-A can be replayed against COA-B if Alice owns both (different `CapabilityPath`), since the signature is over the same `signedData` regardless of which COA is targeted.
3. The proof remains valid indefinitely — there is no on-chain invalidation mechanism.

Any EVM smart contract relying on `isValidSignature` (ERC-1271) via the COA precompile, or any off-chain system calling `verifyCOAOwnershipProof` directly, is vulnerable to impersonation via replayed proofs.

### Likelihood Explanation

The entry path requires only an unprivileged EVM transaction. Proofs are submitted in plaintext EVM calldata and are trivially observable on-chain. The only precondition is that a victim has previously submitted a valid proof in any context. This is a realistic condition for any user of EVM dApps that use COA-based ERC-1271 authentication.

### Recommendation

1. **Bind `signedData` to `evmAddress` at the protocol level**: enforce inside `validateCOAOwnershipProof` that `signedData` contains (or commits to) the `evmAddress` argument, rather than leaving this as a caller convention.
2. **Add a nonce or expiry field** to `COAOwnershipProof` and track consumed nonces on-chain, analogous to how Flow transactions use per-key sequence numbers.
3. At minimum, update the comment to a hard revert rather than a documentation note, so callers cannot accidentally omit the binding.

### Proof of Concept

1. Alice signs `signedData = keccak256("authenticate:dappX")` and submits a `COAOwnershipProof` to EVM dApp X. The proof is visible in EVM calldata.
2. EVM dApp Y also uses `isValidSignature` (ERC-1271) via the COA precompile.
3. An attacker extracts Alice's proof from the calldata of step 1.
4. The attacker calls dApp Y's contract, which calls `isValidSignature(_hash, proof)` with the same `_hash` and Alice's proof.
5. `verifyCOAOwnershipProof` → `validateCOAOwnershipProof` verifies the signature (still valid over `signedData`), checks the COA address matches, and returns `true`.
6. The attacker has successfully impersonated Alice at dApp Y without Alice's participation. [6](#0-5)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1001-1018)
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

**File:** fvm/evm/types/proof.go (L131-144)
```go
// COAOwnershipProof is a proof that a flow account
// controls a COA resource. To do so, the flow
// account (Address is address of this account)
// provides signatures (with proper total weights) over an arbitrary data input
// set by proof requester. KeyIndices captures,
// which account keys has been used for signatures.
// Beside signatures, it provides the CapabilityPath
// where the resource EVMAddress capability is stored.
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
}
```
