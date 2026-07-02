### Title
COA Ownership Proof Signature Replay Enables Unauthorized EVM Authorization - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary
`EVM.validateCOAOwnershipProof` and the `verifyCOAOwnershipProof` Cadence Arch precompile do not enforce that `signedData` encodes the target `evmAddress`, include any nonce, or mark signatures as consumed. A valid proof observed on-chain can be replayed indefinitely to any EVM contract or Cadence caller that uses the same `signedData` hash for a different authorization context, enabling unauthorized ERC-1271 approvals and potential asset loss.

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` verifies that a set of Cadence account key signatures covers `signedData`, then checks that the COA resource at the given `path` matches `evmAddress`. The function has three structural gaps that together constitute a signature replay vulnerability:

1. **No enforcement that `signedData` encodes `evmAddress`.** The code comment at lines 1003–1009 explicitly acknowledges this: *"this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."* The check at lines 1095–1105 only verifies that the COA resource at the caller-supplied `path` matches the caller-supplied `evmAddress`; it does not verify that the signer intended to authorize that specific EVM address.

2. **No nonce or used-signature tracking.** There is no `mapping(address => uint256) nonces` equivalent. Once a user produces a valid signature over any `signedData` value, that signature remains valid forever (until the key is revoked). Any observer can replay it.

3. **The COA ERC-1271 implementation passes `_hash` verbatim.** `COA.isValidSignature(bytes32 _hash, bytes memory _sig)` in `coa.sol` calls `verifyCOAOwnershipProof(address(this), _hash, _sig)` with no domain separator, no contract address binding, and no nonce added to `_hash`. The `_hash` is fully attacker-controlled. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation

Any EVM contract that relies on `COA.isValidSignature` (ERC-1271) for authorization — e.g., a token bridge, NFT marketplace, or permit-style approval — is vulnerable to replay of any previously observed COA ownership proof. Because `signedData` is not bound to a specific contract, action, or nonce, a proof submitted for one purpose (e.g., proving COA ownership to bridge contract A) is cryptographically indistinguishable from a proof submitted for a different purpose (e.g., authorizing a token transfer in contract B) if both use the same `bytes32` hash. An attacker who extracts the proof bytes from a past transaction can replay them to any contract that calls `isValidSignature` with the same hash, obtaining a `ValidERC1271Signature` (0x1626ba7e) response and triggering unauthorized asset movements.

Additionally, if a Cadence account owns more than one COA (published at different paths), a proof signed for COA_X can be replayed against COA_Y by supplying the alternate `path` and `evmAddress`, since `signedData` is not bound to either address. [4](#0-3) [5](#0-4) 

### Likelihood Explanation

- **Attacker entry point:** Any unprivileged EVM transaction sender. The `verifyCOAOwnershipProof` precompile is callable from any EVM transaction; `EVM.validateCOAOwnershipProof` is `access(all)` and callable from any Cadence script or transaction.
- **Proof availability:** COA ownership proofs are submitted as calldata in EVM transactions and are permanently visible on-chain. An attacker needs only to observe one valid proof.
- **Replay window:** Unlimited — no nonce, no expiry, no consumed-signature tracking.
- **Precondition:** A target EVM contract must call `COA.isValidSignature` (or `verifyCOAOwnershipProof`) with a `bytes32` hash that the victim has previously signed. This is the normal operating mode of any ERC-1271-aware protocol. [6](#0-5) [7](#0-6) 

### Recommendation

1. **Enforce `evmAddress` in `signedData`:** Inside `validateCOAOwnershipProof`, verify that the raw bytes of `evmAddress` appear within `signedData`, or require callers to commit to the EVM address in the signed payload.

2. **Add a nonce per (Cadence address, COA address) pair:** Maintain an on-chain `{Address: {[UInt8;20]: UInt64}}` nonce map. Include the nonce in the signed payload and increment it on each successful verification.

3. **Add domain separation in `COA.isValidSignature`:** Before passing `_hash` to `verifyCOAOwnershipProof`, bind it to the contract address and chain ID: `bytes32 domainHash = keccak256(abi.encode(block.chainid, address(this), _hash))`. This prevents cross-contract and cross-chain replay. [8](#0-7) 

### Proof of Concept

**Setup:** Victim (Flow account `0xABCD`) owns COA at EVM address `0xCOA1`, published at `/public/coa`. Victim signs `signedData = keccak256("authorize_action_X")` and submits a COA ownership proof to EVM contract `BridgeA` which calls `COA.isValidSignature(signedData, proof)` to authorize a bridge deposit.

**Replay attack:**

1. Attacker extracts `(keyIndices, signatures)` from the victim's on-chain transaction calldata.
2. Attacker constructs an EVM transaction calling `BridgeB.someAction()` where `BridgeB` internally calls:
   ```solidity
   COA(0xCOA1).isValidSignature(
       keccak256("authorize_action_X"),  // same hash
       proof_bytes_from_step_1           // replayed proof
   )
   ```
3. `isValidSignature` calls `verifyCOAOwnershipProof(0xCOA1, keccak256("authorize_action_X"), proof_bytes)`.
4. The precompile calls `EVM.validateCOAOwnershipProof` with the replayed signatures over the same `signedData`.
5. Signature verification passes (same keys, same data). COA address check passes (same COA). Returns `isValid: true`.
6. `BridgeB` treats the response as a valid authorization and executes the action (e.g., transfers tokens from the COA) — an action the victim never authorized.

**Cross-COA variant:** If `0xABCD` also owns COA at `0xCOA2` at `/public/coa2`, attacker calls `EVM.validateCOAOwnershipProof(0xABCD, /public/coa2, signedData, keyIndices, signatures, 0xCOA2)`. The signature check passes (same keys, same `signedData`); the COA address check passes (COA2's address matches the attacker-supplied `evmAddress`). Returns `isValid: true` for COA2, despite the victim only having signed for COA1. [9](#0-8) [10](#0-9)

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

**File:** fvm/evm/types/proof.go (L102-106)
```go
type COAOwnershipProofInContext struct {
	COAOwnershipProof
	SignedData SignedData
	EVMAddress Address
}
```

**File:** fvm/evm/precompiles/arch.go (L30-33)
```go
	ProofVerifierFuncSig = ComputeFunctionSelector(
		"verifyCOAOwnershipProof",
		[]string{"address", "bytes32", "bytes"},
	)
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

**File:** fvm/evm/handler/precompiles.go (L115-133)
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
```
