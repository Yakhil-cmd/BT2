### Title
COA Ownership Proof Signed Data Excludes `evmAddress`, Enabling Cross-COA Replay — (`fvm/evm/stdlib/contract.cdc`)

### Summary

`EVM.validateCOAOwnershipProof` verifies Cadence account key signatures over caller-supplied `signedData`, but does not enforce that `signedData` encodes the `evmAddress` being proven. The `evmAddress` is passed as a separate, unconstrained argument and is only checked against the on-chain COA resource after signature verification succeeds. A proof (signed data + signatures) produced to prove ownership of one COA can be replayed by any caller to prove ownership of a different COA belonging to the same Cadence account, without the signer's consent.

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` accepts six arguments: `address`, `path`, `signedData`, `keyIndices`, `signatures`, and `evmAddress`. The signature verification step at lines 1082–1086 verifies the signatures only over `signedData`:

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,
    domainSeparationTag: "FLOW-V0.0-user"
)
``` [1](#0-0) 

The `evmAddress` argument is never included in the signed payload. After signature verification passes, the function separately checks that the COA resource stored at `path` has an address matching `evmAddress`:

```cadence
if let coaRef = acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(path) {
    let coaAddressBytes = coaRef.address().bytes
    for index, item in coaAddressBytes {
        if item != evmAddress[index] { ... }
    }
``` [2](#0-1) 

These two checks are independent. The code itself acknowledges this gap:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [3](#0-2) 

`validateCOAOwnershipProof` is declared `access(all)` and is callable from any Cadence script or transaction by any unprivileged sender. [4](#0-3) 

The function is also invoked by the `coaOwnershipProofValidator` backend in `fvm/evm/handler/precompiles.go`, which is wired into the `verifyCOAOwnershipProof` Cadence Arch precompile callable from EVM: [5](#0-4) 

The COA's ERC-1271 `isValidSignature` implementation in `coa.sol` calls the precompile with `address(this)` hardcoded, so that EVM-internal path is safe. However, the Cadence-level `validateCOAOwnershipProof` function is directly callable with an attacker-chosen `evmAddress` and `path`. [6](#0-5) 

### Impact Explanation

A Cadence account may own multiple COAs stored at different public paths (the protocol does not limit this to one). If Alice signs `signedData` to prove ownership of `COA_A` (EVM address `0xAAA`) for dApp X, an attacker who observed that proof can replay the identical `(signedData, keyIndices, signatures)` tuple in a call to `validateCOAOwnershipProof(alice_addr, /public/coa_b_path, signedData, keyIndices, signatures, 0xBBB)`. Because the signatures are valid over `signedData` (which does not bind to any EVM address), and because `COA_B` at `/public/coa_b_path` legitimately has address `0xBBB`, the function returns `isValid: true` — asserting that Alice authorized ownership of `COA_B` when she only authorized `COA_A`. Any dApp or protocol that uses `validateCOAOwnershipProof` to gate asset transfers or privileged actions on a specific EVM address is vulnerable to this cross-COA authorization bypass.

### Likelihood Explanation

- `validateCOAOwnershipProof` is `access(all)` — reachable by any unprivileged Cadence transaction or script sender with no special role.
- Proofs are submitted on-chain or shared with dApps, making `signedData` and `signatures` observable by third parties.
- A Cadence account with multiple COAs is a supported and documented configuration (the `path` argument exists precisely to select among them).
- No brute force, key compromise, or staked-node control is required.

### Recommendation

Enforce that `signedData` encodes `evmAddress` inside `validateCOAOwnershipProof` itself, rather than relying on callers to do so. Concretely, reconstruct the expected signed payload as `evmAddress || callerSuppliedData` and verify signatures against that reconstructed message, or reject calls where `signedData` does not contain the 20-byte `evmAddress` as a prefix/suffix. This mirrors the fix recommended in the external report: bind the signed data to the specific target identifier (here, the EVM address) so that a proof for one COA cannot be replayed for another.

### Proof of Concept

1. Alice owns a Cadence account `0xAlice` with two COAs:
   - `COA_A` (EVM `0xAAA`) published at `/public/coa_a`
   - `COA_B` (EVM `0xBBB`) published at `/public/coa_b`
2. Alice signs `signedData = <arbitrary bytes>` with her account key to prove ownership of `COA_A` for dApp X. The proof `(signedData, [0], [sig])` is submitted on-chain and becomes public.
3. Attacker calls (from any Cadence script):
   ```cadence
   EVM.validateCOAOwnershipProof(
       address: 0xAlice,
       path: /public/coa_b,       // ← different COA
       signedData: signedData,    // ← replayed from step 2
       keyIndices: [0],
       signatures: [sig],         // ← replayed from step 2
       evmAddress: 0xBBB          // ← COA_B's address
   )
   ```
4. Signature verification passes (signatures are valid over `signedData`). COA address check passes (`COA_B.address() == 0xBBB`). The function returns `ValidationResult(isValid: true)` — falsely asserting Alice authorized ownership of `COA_B`. [7](#0-6) [8](#0-7)

### Citations

**File:** fvm/evm/stdlib/contract.cdc (L1001-1116)
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
        // make signature set first
        // check number of signatures matches number of key indices
        if keyIndices.length != signatures.length {
            return ValidationResult(
                isValid: false,
                problem: "EVM.validateCOAOwnershipProof(): Key indices array length doesn't match the signatures array length!"
            )
        }

        // fetch account
        let acc = getAccount(address)

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
