### Title
COA Ownership Proof Verifier Does Not Bind `signedData` to `evmAddress`, Enabling Cross-COA Signature Replay - (File: fvm/evm/stdlib/contract.cdc)

### Summary
The `validateCOAOwnershipProof` function in `fvm/evm/stdlib/contract.cdc` does not enforce that `signedData` encodes `evmAddress`. An attacker who observes a valid Cadence account signature over any `signedData` can replay it against a different COA owned by the same Cadence account by supplying an attacker-controlled `CapabilityPath` in the RLP-encoded proof. The EVM precompile and the ERC-1271 `isValidSignature` entry point on every COA contract accept the forged proof, returning `ValidERC1271Signature` for the target COA without the account owner ever authorizing that COA.

### Finding Description
`validateCOAOwnershipProof` performs two independent checks:

1. **Signature check** — verifies that the supplied signatures are valid over `signedData` under the Cadence account's keys.
2. **COA address check** — borrows the `CadenceOwnedAccount` capability at the caller-supplied `path` and verifies that its EVM address equals the supplied `evmAddress`.

The two checks are never cross-bound. `signedData` is a free `bytes32` value; the function never asserts that it encodes `evmAddress`. The `CapabilityPath` field is part of the attacker-controlled RLP-encoded proof blob and is accepted verbatim.

The code itself documents the gap:

> *"Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."* [1](#0-0) 

The full verification logic that omits the binding: [2](#0-1) 

The `CapabilityPath` is decoded from the attacker-supplied RLP proof without any canonical-path enforcement: [3](#0-2) 

The EVM precompile decodes the proof and passes it directly to the validator: [4](#0-3) 

The COA's ERC-1271 entry point calls the precompile with `address(this)` as `evmAddress`, so the `evmAddress` is always the calling COA's address — but the `signedData` is whatever the caller supplies: [5](#0-4) 

### Impact Explanation
Any EVM contract or bridge that relies on ERC-1271 (`isValidSignature`) to authorize operations on a COA can be deceived. An attacker who has observed a single valid Cadence signature over any `bytes32` value `D` can present that signature as proof of ownership of an entirely different COA (COA_B) owned by the same Cadence account, by embedding `CapabilityPath = "coa_b"` in the proof. The ERC-1271 call returns `ValidERC1271Signature` for COA_B. Any bridge, vault, or DeFi protocol that gates withdrawals or asset releases on `isValidSignature` from COA_B will execute the operation as if COA_B's owner authorized it. This maps directly to the report's impact class: cross-VM asset loss and bridge escrow mis-accounting triggered by a forged proof that passes the verifier without a genuine authorization from the target COA.

### Likelihood Explanation
The attack requires two preconditions: (a) the victim Cadence account controls more than one COA published at distinct public paths, and (b) the attacker has observed an on-chain or off-chain signature from that account over a `bytes32` value that a target protocol will later present to COA_B's `isValidSignature`. Both conditions are uncommon today ("Flow wallets historically create at most one COA per account"), but neither is impossible. Multi-COA setups are a natural evolution as users separate bridge, DeFi, and custody COAs. The attack requires no privileged access, no staked-node compromise, and no brute force — only passive observation of a prior signature event.

### Recommendation
- Require that `signedData` encodes `evmAddress` before the signature check is performed inside `validateCOAOwnershipProof`. A minimal fix is to prepend or hash `evmAddress` into the signed payload and verify the commitment before calling `keyList.verify`.
- Alternatively, restrict `CapabilityPath` to a single canonical value (e.g., `/public/evm`) so that one Cadence account can only ever prove ownership of one COA through this interface.
- Add a negative test: craft a proof with a valid signature for COA_A but with `CapabilityPath` pointing to COA_B and assert that `validateCOAOwnershipProof` returns `isValid = false`.

### Proof of Concept
```
Setup:
  - Cadence account A owns COA_A published at /public/coa_a  (EVM addr 0xAAAA)
  - Cadence account A owns COA_B published at /public/coa_b  (EVM addr 0xBBBB)

Step 1 (legitimate):
  Account A signs bytes32 D for COA_A (e.g., for an ERC-1271 check on COA_A).
  Signature sig_A is emitted on-chain or observed off-chain.

Step 2 (attacker):
  Attacker RLP-encodes a COAOwnershipProof:
    KeyIndices     = [0]          // same key as used for COA_A
    Address        = A            // same Cadence account
    CapabilityPath = "coa_b"      // ← attacker-controlled, points to COA_B
    Signatures     = [sig_A]      // ← replayed signature

Step 3 (attacker calls ERC-1271 on COA_B):
  COA_B.isValidSignature(D, rlp_encoded_proof)
    → precompile verifyCOAOwnershipProof(0xBBBB, D, rlp_encoded_proof)
    → validateCOAOwnershipProof(A, /public/coa_b, D, [0], [sig_A], 0xBBBB)
      • keyList.verify([sig_A], D, "FLOW-V0.0-user") → true  (valid sig over D)
      • acc.capabilities.borrow<&EVM.CadenceOwnedAccount>(/public/coa_b)
          .address().bytes == 0xBBBB → true
      • returns ValidationResult(isValid: true)
    → isValidSignature returns ValidERC1271Signature (0x1626ba7e)

Result: any bridge or vault that gates on COA_B.isValidSignature(D, …) now
        treats the attacker's submission as authorized by COA_B's owner.
``` [6](#0-5) [7](#0-6)

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
