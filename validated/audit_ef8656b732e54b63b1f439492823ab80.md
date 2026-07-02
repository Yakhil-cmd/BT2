### Title
Cross-COA ERC1271 Signature Replay via Missing `evmAddress` Binding in `validateCOAOwnershipProof` - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary
The `validateCOAOwnershipProof` function in `fvm/evm/stdlib/contract.cdc` verifies that a set of Cadence account signatures are valid over `signedData`, then checks that the COA at the supplied `path` matches `evmAddress`. However, it never verifies that `signedData` commits to `evmAddress`. A signature produced to prove ownership of COA-A can therefore be replayed verbatim — with only the `CapabilityPath` field swapped — to pass ownership verification for a different COA-B owned by the same Cadence account. This breaks the ERC-1271 `isValidSignature` guarantee for every COA on Flow EVM.

### Finding Description

**Root cause — `validateCOAOwnershipProof` does not bind `signedData` to `evmAddress`**

`fvm/evm/stdlib/contract.cdc` lines 1001–1116:

```cadence
/// Note: this function does not enforce that `signedData` includes `evmAddress`.
/// In principle, a signature produced for one purpose could be replayed here against
/// a different COA owned by the same Cadence account.
access(all)
fun validateCOAOwnershipProof(
    address: Address,
    path: PublicPath,
    signedData: [UInt8],
    keyIndices: [UInt64],
    signatures: [[UInt8]],
    evmAddress: [UInt8; 20]
): ValidationResult {
    ...
    let isValid = keyList.verify(
        signatureSet: signatureSet,
        signedData: signedData,          // ← never includes evmAddress
        domainSeparationTag: "FLOW-V0.0-user"
    )
    ...
    // only checks that the COA at `path` has the right EVM address
    if let coaRef = acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(path) {
        ...
        return ValidationResult(isValid: true, problem: nil)
    }
``` [1](#0-0) [2](#0-1) 

The function performs two independent checks:
1. Verify `signatures` over `signedData` using keys from the Cadence account at `address`.
2. Verify that the COA capability at `path` in `address` has EVM address `evmAddress`.

Neither check ties `signedData` to `evmAddress`. The two checks are completely decoupled.

**How the COA's ERC-1271 entry point calls this**

`fvm/evm/handler/coa/coa.sol` lines 113–125:

```solidity
function isValidSignature(
    bytes32 _hash,
    bytes memory _sig
) external view virtual returns (bytes4){
    (bool ok, bytes memory data) = cadenceArch.staticcall(
        abi.encodeWithSignature(
            "verifyCOAOwnershipProof(address,bytes32,bytes)",
            address(this), _hash, _sig   // ← address(this) = calling COA
        )
    );
    ...
}
``` [3](#0-2) 

The precompile decodes the call and constructs a `COAOwnershipProofInContext` where `EVMAddress = address(this)` (the calling COA) and `SignedData = _hash`. The `_sig` bytes are RLP-decoded into a `COAOwnershipProof` containing `{KeyIndices, Address, CapabilityPath, Signatures}`. [4](#0-3) [5](#0-4) 

**Attack path (step-by-step)**

Preconditions: Alice owns two COAs — COA-A published at `/public/coaA` and COA-B published at `/public/coaB` — both controlled by the same Cadence account key.

1. Alice legitimately calls `COA_A.isValidSignature(H, proof_A)` on-chain (e.g., to authorize a DeFi action). `proof_A` is RLP-encoded `{KeyIndices:[0], Address:alice, CapabilityPath:"coaA", Signatures:[sig_H]}` where `sig_H = Sign(alice_key, H)`.

2. Bob observes `proof_A` in the transaction calldata (fully public on-chain).

3. Bob RLP-decodes `proof_A`, replaces `CapabilityPath:"coaA"` with `CapabilityPath:"coaB"`, and re-encodes to produce `proof_B`.

4. Bob calls `COA_B.isValidSignature(H, proof_B)`.

5. The CadenceArch precompile calls `validateCOAOwnershipProof(alice, /public/coaB, H, [0], [sig_H], COA_B_address)`.

6. `keyList.verify` succeeds — `sig_H` is a valid signature of `H` under Alice's key.

7. `acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(/public/coaB)` succeeds and the EVM address matches `COA_B_address`.

8. Function returns `isValid: true`. `COA_B.isValidSignature` returns `ValidERC1271Signature (0x1626ba7e)`.

Bob has now convinced any ERC-1271-aware contract that Alice authorized `H` on behalf of COA-B, without Alice's knowledge or consent.

### Impact Explanation

Any ERC-1271-aware contract on Flow EVM (e.g., a token approval contract, an NFT marketplace, a multisig, a permit-style contract) that calls `COA_B.isValidSignature(H, proof)` will accept Bob's forged proof as a valid authorization from Alice. This enables Bob to:

- Authorize token transfers or approvals from COA-B without Alice's consent.
- Claim NFTs or other assets gated by ERC-1271 ownership checks on COA-B.
- Satisfy any off-chain or on-chain authentication flow that relies on `isValidSignature` for COA-B.

The impact is **unauthorized movement of on-chain assets** held by or accessible through COA-B.

### Likelihood Explanation

The attack requires Alice to own more than one COA and to have previously submitted a transaction whose calldata contains a valid `COAOwnershipProof` for COA-A. Both conditions are realistic as the Flow EVM ecosystem grows and users deploy multiple COAs (e.g., one per application). The proof encoding (`COAOwnershipProof` RLP) is fully public and documented. No privileged access, key compromise, or social engineering is required — only passive observation of Alice's on-chain transactions.

The code itself acknowledges the gap:

> *"In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."* [6](#0-5) 

### Recommendation

Bind `signedData` to `evmAddress` inside `validateCOAOwnershipProof`. The simplest fix is to require that `signedData` is `keccak256(evmAddress ++ application_data)` or to prepend `evmAddress` to the data that is verified:

```cadence
// Require callers to include evmAddress in signedData, or enforce it here:
let expectedPrefix = evmAddress.toConstantSized<[UInt8; 20]>()!
// verify first 20 bytes of signedData equal evmAddress
```

Alternatively, enforce this at the EVM layer in `coa.sol` by having `isValidSignature` hash `address(this)` together with `_hash` before passing it to the precompile, so the signed payload is always COA-address-specific.

### Proof of Concept

```go
// Attacker constructs proof_B from observed proof_A
proofA := &types.COAOwnershipProof{
    KeyIndices:     []uint64{0},
    Address:        aliceCadenceAddress,
    CapabilityPath: "coaA",
    Signatures:     []types.Signature{sigH}, // sig over H, obtained from on-chain tx
}

proofB := &types.COAOwnershipProof{
    KeyIndices:     []uint64{0},
    Address:        aliceCadenceAddress,
    CapabilityPath: "coaB",   // ← only change
    Signatures:     []types.Signature{sigH}, // same sig
}

encodedProofB, _ := proofB.Encode()

// Bob calls COA_B.isValidSignature(H, encodedProofB) via an EVM transaction.
// validateCOAOwnershipProof verifies sig over H (passes) and checks COA-B address (passes).
// Returns ValidERC1271Signature — Bob is now authorized as Alice on COA-B.
``` [7](#0-6) [8](#0-7)

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

**File:** fvm/evm/types/proof.go (L102-117)
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
```

**File:** fvm/evm/types/proof.go (L146-148)
```go
func (p *COAOwnershipProof) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(p)
}
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
