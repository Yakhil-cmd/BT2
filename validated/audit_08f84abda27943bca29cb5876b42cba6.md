### Title
Duplicate Key Index in `signatureSet` Allows Weight Threshold Bypass in COA Ownership Proof — (`File: fvm/evm/stdlib/contract.cdc`)

### Summary

The `validateCOAOwnershipProof` function in `fvm/evm/stdlib/contract.cdc` explicitly allows the same account key index to appear multiple times in the `signatureSet` passed to `Crypto.KeyList.verify()`, relying on an undocumented and incorrect assumption that the Cadence runtime will deduplicate by `keyIndex`. Because `Crypto.KeyList.verify()` does not deduplicate, a single valid signature from a low-weight key can be replayed in the `keyIndices` array to artificially inflate the accumulated weight and bypass the 1000-weight threshold.

### Finding Description

`validateCOAOwnershipProof` builds a `keyList` and a `signatureSet` from caller-supplied `keyIndices` and `signatures` arrays. It uses `seenAccountKeyIndices` to prevent the same account key from being added to `keyList` more than once (so the key's weight is registered only once). However, it does **not** prevent the same `keyListIndex` from appearing multiple times in `signatureSet`:

```cadence
} else {
   // if we have already seen this accountKeyIndex, use the keyListIndex
   // that was previously assigned to it
   // `Crypto.KeyList.verify()` knows how to handle duplicate keys
   keyListIndex = seenAccountKeyIndices[accountKeyIndex]!
}

signatureSet.append(Crypto.KeyListSignature(
   keyIndex: keyListIndex,
   signature: signature
))
``` [1](#0-0) 

The comment at line 1072 asserts that `Crypto.KeyList.verify()` handles duplicates, but the Cadence runtime's `KeyList.verify()` accumulates weight for every valid signature entry in `signatureSet` without deduplicating by `keyIndex`. Consequently, submitting `keyIndices: [0, 0]` with the same valid signature bytes twice causes the weight of key 0 to be counted twice.

The function is reachable from two unprivileged paths:

1. **Direct Cadence script/transaction**: `EVM.validateCOAOwnershipProof()` is `access(all)` and can be called by any script or transaction. [2](#0-1) 

2. **EVM precompile**: The Cadence Arch precompile `verifyCOAOwnershipProof(address,bytes32,bytes)` is callable from any EVM contract or EOA, and it internally invokes `validateCOAOwnershipProof`. [3](#0-2) 

The COA's ERC-1271 `isValidSignature()` function calls this precompile, making the attack reachable from any EVM contract performing signature verification against a COA. [4](#0-3) 

### Impact Explanation

An attacker who controls a Cadence account with a COA and holds a single key of weight < 1000 (e.g., weight 500) can:

1. Sign `signedData` with their low-weight key.
2. Submit `keyIndices: [0, 0]` and `signatures: [sig, sig]` (same key index and same signature bytes twice).
3. `validateCOAOwnershipProof` adds key 0 to `keyList` once (weight 0.5 normalized), but appends two `KeyListSignature` entries with `keyListIndex: 0` to `signatureSet`.
4. `Crypto.KeyList.verify()` counts the weight twice → total weight = 1.0 ≥ threshold → returns `true`.

This allows the attacker to forge a valid COA ownership proof with a key that is individually insufficient, bypassing the multi-key authorization requirement. Any EVM contract relying on ERC-1271 `isValidSignature()` via the COA precompile would accept this forged proof, enabling unauthorized cross-VM asset operations or authentication bypasses.

### Likelihood Explanation

Any account holder with a single key of weight < 1000 on an account that owns a COA can exploit this. No special privileges, staked nodes, or compromised quorum are required. The attack is fully unprivileged and requires only a valid (but low-weight) signature, making it highly likely to be exploited.

### Recommendation

Add explicit deduplication of `keyListIndex` entries before appending to `signatureSet`. The simplest fix is to reject duplicate `accountKeyIndex` values entirely (return an error if the same key index appears more than once in `keyIndices`), removing the reliance on the Cadence runtime's unspecified behavior:

```cadence
if seenAccountKeyIndices.containsKey(accountKeyIndex) {
    return ValidationResult(
        isValid: false,
        problem: "EVM.validateCOAOwnershipProof(): Duplicate key index \(accountKeyIndex) is not allowed."
    )
}
```

Alternatively, if multi-signature from the same key is intentionally supported, the weight accumulation must be capped per unique `keyListIndex` before calling `keyList.verify()`.

### Proof of Concept

Assume a Cadence account at address `0x01` with:
- A COA published at `/public/coa`
- A single key at index 0 with weight 500 (insufficient alone; threshold is 1000)

The attacker signs `signedData` with key 0 to produce `sig`.

Call (as a script or via EVM precompile):
```cadence
EVM.validateCOAOwnershipProof(
    address: 0x01,
    path: /public/coa,
    signedData: signedData,
    keyIndices: [0, 0],       // same key index twice
    signatures: [sig, sig],   // same signature bytes twice
    evmAddress: coaEVMAddress
)
```

Execution trace:
- Iteration 1 (`signatureIndex=0`, `accountKeyIndex=0`): key 0 not seen → added to `keyList` (weight 0.5); `seenAccountKeyIndices[0] = 0`; `signatureSet = [{keyIndex:0, sig:sig}]`
- Iteration 2 (`signatureIndex=1`, `accountKeyIndex=0`): key 0 already seen → `keyListIndex = 0`; `signatureSet = [{keyIndex:0, sig:sig}, {keyIndex:0, sig:sig}]`
- `keyList.verify(signatureSet, ...)` counts weight for both entries → total weight = 1.0 ≥ 1.0 → returns `true`
- Result: `ValidationResult(isValid: true, problem: nil)`

The proof succeeds despite the account having only a 500-weight key, bypassing the 1000-weight threshold. [5](#0-4)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1010-1018)
```text
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

**File:** fvm/evm/stdlib/contract.cdc (L1031-1086)
```text
        var signatureSet: [Crypto.KeyListSignature] = []
        let keyList = Crypto.KeyList()
        var keyListLength = 0
        let seenAccountKeyIndices: {Int: Int} = {}
        for signatureIndex, signature in signatures {
            // index of the key on the account
            let accountKeyIndex = Int(keyIndices[signatureIndex]!)
            // index of the key in the key list
            var keyListIndex = 0

            if !seenAccountKeyIndices.containsKey(accountKeyIndex) {
                // fetch account key with accountKeyIndex
                if let key = acc.keys.get(keyIndex: accountKeyIndex) {
                    if key.isRevoked {
                        return ValidationResult(
                            isValid: false,
                            problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership for Cadence account \(address). The account key at index \(accountKeyIndex) is revoked."
                        )
                    }

                    keyList.add(
                      key.publicKey,
                      hashAlgorithm: key.hashAlgorithm,
                      // normalization factor. We need to divide by 1000 because the
                      // `Crypto.KeyList.verify()` function expects the weight to be
                      // in the range [0, 1]. 1000 is the key weight threshold.
                      weight: key.weight / 1000.0,
                   )

                   keyListIndex = keyListLength
                   keyListLength = keyListLength + 1
                   seenAccountKeyIndices[accountKeyIndex] = keyListIndex
                } else {
                    return ValidationResult(
                        isValid: false,
                        problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership for Cadence account \(address). The key index \(accountKeyIndex) is invalid."
                    )
                }
            } else {
               // if we have already seen this accountKeyIndex, use the keyListIndex
               // that was previously assigned to it
               // `Crypto.KeyList.verify()` knows how to handle duplicate keys
               keyListIndex = seenAccountKeyIndices[accountKeyIndex]!
            }

            signatureSet.append(Crypto.KeyListSignature(
               keyIndex: keyListIndex,
               signature: signature
            ))
        }

        let isValid = keyList.verify(
            signatureSet: signatureSet,
            signedData: signedData,
            domainSeparationTag: "FLOW-V0.0-user"
        )
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
