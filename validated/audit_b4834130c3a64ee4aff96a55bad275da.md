### Title
Cross-COA Signature Replay in `EVM.validateCOAOwnershipProof` Due to Missing `evmAddress` Binding in Signed Data - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` does not enforce that the caller-supplied `signedData` encodes the target `evmAddress`. A signature produced by a Cadence account to prove ownership of one COA (COA_A) can be replayed verbatim against a different COA (COA_B) owned by the same Cadence account, causing the function to return `isValid: true` for the wrong COA. This is the direct Flow analog of the Gateway contract bug where the signed message omits the `account` address.

---

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` performs two checks:

1. It verifies that the provided `signatures` over `signedData` are valid against keys of the Cadence account at `address` (weight ≥ 1000).
2. It verifies that the COA resource at the given `path` has an EVM address matching the supplied `evmAddress`.

The code itself documents the gap:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [1](#0-0) 

Because `signedData` is an opaque `[UInt8]` blob whose content is never inspected, the function only checks *who* signed, not *what COA* the signature was intended for. If a Cadence account owns two COAs (COA_A at `/public/coaA` and COA_B at `/public/coaB`), a signature `sig = sign(signedData)` produced for COA_A passes validation when submitted with `evmAddress = COA_B.address` and `path = /public/coaB`, because:

- The cryptographic check passes (same Cadence account keys sign both).
- The COA address check passes (COA_B's address matches the supplied `evmAddress`). [2](#0-1) 

The EVM-side entry point is `coa.sol`'s `isValidSignature`, which calls the `verifyCOAOwnershipProof` precompile with `address(this)` as the COA address: [3](#0-2) 

This means any EVM contract that calls `COA_B.isValidSignature(_hash, proof_for_COA_A)` will receive a valid ERC-1271 response, even though the signer only authorized COA_A.

---

### Impact Explanation

An attacker who obtains a valid COA ownership proof (signature + `signedData`) for COA_A can replay it against COA_B if both are owned by the same Cadence account. The concrete impact is **unauthorized ERC-1271 signature validation**: EVM smart contracts that rely on `isValidSignature` to gate access (e.g., ERC-4337 account abstraction, NFT marketplace approvals, DAO voting) will accept the replayed proof as a valid authorization from COA_B, even though the account holder only signed for COA_A. This constitutes unauthorized account mutation / cross-VM asset authorization bypass.

---

### Likelihood Explanation

The comment in the code acknowledges the issue but dismisses it as "low-risk" because wallets historically create at most one COA per account. However:

- The Flow EVM ecosystem is growing and multi-COA setups are not prohibited.
- `validateCOAOwnershipProof` is a public, permissionless Cadence function callable from any script or EVM transaction.
- Any off-chain authentication flow (e.g., Sign-In with Ethereum, ERC-1271 based wallet integrations) that calls this function directly is immediately vulnerable if the user has more than one COA.
- The attacker only needs a previously captured valid proof for COA_A — no private key material is required.

Likelihood is **medium**: requires a Cadence account with two COAs, but the attack is trivially executable once that condition is met.

---

### Recommendation

Enforce that `signedData` encodes `evmAddress` inside `validateCOAOwnershipProof`, or document and enforce this as a hard protocol requirement. The simplest fix is to verify that `signedData` contains the 20-byte `evmAddress` as a prefix or suffix before accepting the proof as valid, analogous to the Gateway contract recommendation to include the `account` field in the signed message.

---

### Proof of Concept

1. Cadence account `0xALICE` owns two COAs: COA_A (at `/public/coaA`) and COA_B (at `/public/coaB`).
2. Alice signs `signedData = <arbitrary bytes>` with her key index 0, producing `sig`.
3. Attacker constructs a `COAOwnershipProof` with `Address = 0xALICE`, `CapabilityPath = /public/coaB`, `KeyIndices = [0]`, `Signatures = [sig]`.
4. Attacker calls `EVM.validateCOAOwnershipProof(address: 0xALICE, path: /public/coaB, signedData: signedData, keyIndices: [0], signatures: [sig], evmAddress: COA_B.address)`.
5. Step 1 (crypto check): `sig` is valid over `signedData` under Alice's key 0 → passes.
6. Step 2 (COA address check): COA at `/public/coaB` has address `COA_B.address` → passes.
7. Function returns `ValidationResult(isValid: true)` — the proof for COA_A has been accepted as proof for COA_B. [4](#0-3) [5](#0-4)

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

**File:** fvm/evm/stdlib/contract.cdc (L1011-1017)
```text
    fun validateCOAOwnershipProof(
        address: Address,
        path: PublicPath,
        signedData: [UInt8],
        keyIndices: [UInt64],
        signatures: [[UInt8]],
        evmAddress: [UInt8; 20]
```

**File:** fvm/evm/stdlib/contract.cdc (L1082-1105)
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
