### Title
COA Ownership Proof Signature Replay Across Multiple COAs Owned by the Same Cadence Account - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary

`EVM.validateCOAOwnershipProof` verifies Cadence key signatures over an arbitrary `signedData` blob but does not enforce that `signedData` encodes the target `evmAddress`. Because the signature is bound only to the raw data and a fixed domain tag (`"FLOW-V0.0-user"`), a valid signature produced for one COA can be replayed against a different COA owned by the same Cadence account. The code itself documents this gap but dismisses it as low-risk based on a non-enforced assumption. The function is `access(all)` and callable by any unprivileged Cadence script or EVM transaction.

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` performs two independent checks:

1. **Signature check** (lines 1082–1086): verifies that the provided signatures over `signedData` are valid for the Cadence account's keys using `domainSeparationTag: "FLOW-V0.0-user"`.
2. **Address check** (lines 1095–1110): verifies that the COA resource at the given `path` has an EVM address matching `evmAddress`. [1](#0-0) 

These two checks are **independent**. The signatures are verified over `signedData` alone — `evmAddress` is never included in what is signed. The code explicitly acknowledges this: [2](#0-1) 

The EVM-side `isValidSignature` in `coa.sol` calls the Cadence Arch precompile `verifyCOAOwnershipProof(address(this), _hash, _sig)`, where `address(this)` is the calling COA's EVM address: [3](#0-2) 

The precompile decodes the proof and passes `signedData = _hash` and `EVMAddress = address(this)` to `validateCOAOwnershipProof`: [4](#0-3) 

**Cross-address replay attack path:**

Suppose a Cadence account `A` owns two COAs: `COA_X` (published at `/public/coaX`) and `COA_Y` (published at `/public/coaY`). A user signs `hash H` for a DeFi protocol interacting with `COA_X`. The resulting `COAOwnershipProof` contains `CapabilityPath = "coaX"` and `Signatures = [sig_over_H]`.

An attacker constructs a new proof with `CapabilityPath = "coaY"` and the same `Signatures = [sig_over_H]`. When `COA_Y.isValidSignature(H, malicious_proof)` is called:

- `validateCOAOwnershipProof` verifies `sig_over_H` against `signedData = H` → **passes** (signature is valid over H regardless of which COA it was intended for)
- It then checks that the COA at `/public/coaY` has address `COA_Y` → **passes** (it does)
- Returns `isValid: true`

The function returns a valid result even though the user only authorized `H` in the context of `COA_X`.

Additionally, `validateCOAOwnershipProof` is `access(all)` and can be called directly from any Cadence script with attacker-controlled `path` and `evmAddress` arguments, bypassing the EVM-side protection where `address(this)` is always the calling COA. [5](#0-4) 

The `COAOwnershipProof` struct does not include `evmAddress` — it only carries `KeyIndices`, `Address`, `CapabilityPath`, and `Signatures`: [6](#0-5) 

### Impact Explanation

Any ERC-1271 consumer (ERC-20 `permit`, NFT marketplace approvals, DeFi authorization flows) that calls `isValidSignature` on a COA can be deceived into accepting a signature the user produced for a different COA on the same Cadence account. This enables unauthorized token approvals or action authorizations against `COA_Y` using a signature the user only intended for `COA_X`. Off-chain authentication systems built directly on `EVM.validateCOAOwnershipProof` (which is `access(all)`) are directly exploitable without going through the EVM layer at all.

### Likelihood Explanation

The preconditions are:
1. A Cadence account holds more than one COA — the protocol supports this and nothing prevents it.
2. A valid signature over some hash `H` exists for one of those COAs (e.g., obtained from a legitimate prior interaction).
3. The verifying DeFi protocol does not embed the COA address inside the signed hash (i.e., does not use EIP-712 with the COA as the verifying contract).

Condition 3 is common in simpler protocols and in any off-chain authentication flow built directly on `validateCOAOwnershipProof`. The attacker needs no privileged access — they only need to observe a valid proof from a prior on-chain transaction and submit a modified one with a different `CapabilityPath`.

### Recommendation

Enforce that `signedData` commits to `evmAddress` inside `validateCOAOwnershipProof` itself, rather than delegating this responsibility to callers. Concretely, before verifying signatures, reconstruct the expected signed payload as `hash(evmAddress || signedData)` (or a structured equivalent) and verify signatures over that composite value. This mirrors the ERC-7739 defensive rehashing approach referenced in the external report — binding the signature to the specific account it is intended for.

Alternatively, include `evmAddress` in the `COAOwnershipProof` struct itself so it is part of the RLP-encoded, signed artifact, making cross-address replay cryptographically impossible. [7](#0-6) 

### Proof of Concept

1. Cadence account `A` creates two COAs: `COA_X` at `/storage/coaX` (published at `/public/coaX`) and `COA_Y` at `/storage/coaY` (published at `/public/coaY`).
2. A DeFi protocol requests a COA ownership proof for `COA_X` over hash `H`. The user signs `H` with their Cadence key and produces `proof_X = {Address: A, CapabilityPath: "coaX", KeyIndices: [0], Signatures: [sig_H]}`.
3. The attacker observes `proof_X` on-chain and constructs `proof_Y = {Address: A, CapabilityPath: "coaY", KeyIndices: [0], Signatures: [sig_H]}` — identical except for `CapabilityPath`.
4. The attacker calls `COA_Y.isValidSignature(H, encode(proof_Y))` from an EVM transaction.
5. The Cadence Arch precompile calls `EVM.validateCOAOwnershipProof(address: A, path: /public/coaY, signedData: H, keyIndices: [0], signatures: [sig_H], evmAddress: COA_Y_addr)`.
6. Signature verification passes (sig_H is valid over H for account A's key 0). The COA at `/public/coaY` has address `COA_Y_addr`. Both checks pass.
7. `isValidSignature` returns `0x1626ba7e` (valid), authorizing an action on `COA_Y` that the user never intended. [8](#0-7)

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

**File:** fvm/evm/types/proof.go (L139-147)
```go
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
}

func (p *COAOwnershipProof) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(p)
```
