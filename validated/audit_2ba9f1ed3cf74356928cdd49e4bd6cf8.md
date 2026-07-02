### Title
Cross-Address COA Ownership Proof Replay Enables Forged ERC-1271 Signatures - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` does not enforce that `signedData` encodes the target `evmAddress`. When a single Flow account owns multiple `CadenceOwnedAccount` (COA) resources, a proof (including account-key signatures) produced for COA\_1 can be replayed verbatim against COA\_2 by an unprivileged attacker who merely changes the `CapabilityPath` field. The function returns `isValid: true` for the wrong COA, allowing the attacker to forge valid ERC-1271 signatures on behalf of COA\_2 without ever holding Account A's private key.

---

### Finding Description

`EVM.validateCOAOwnershipProof` performs two independent checks:

1. **Signature check** – verifies that the supplied signatures are valid for the named Flow account's keys over `signedData`.
2. **EVM-address check** – borrows the COA capability at the supplied `path` and confirms its `.address()` matches `evmAddress`. [1](#0-0) 

The function's own NatSpec comment acknowledges the gap:

> *"this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."* [2](#0-1) 

Because the two checks are independent, an attacker who observes a legitimate proof `{address: A, path: /public/coa1, signatures: [σ], keyIndices: [k]}` for COA\_1 can construct a modified proof `{address: A, path: /public/coa2, signatures: [σ], keyIndices: [k]}` for COA\_2. The signature check still passes (σ is a valid signature by Account A's key over the same `signedData`), and the EVM-address check passes because the COA at `/public/coa2` genuinely has EVM address Y.

The EVM-side entry point is `CadenceOwnedAccount.isValidSignature` in `coa.sol`, which calls the Cadence Arch precompile `verifyCOAOwnershipProof(address(this), _hash, _sig)` — always supplying the calling contract's own EVM address as the `evmAddress` argument: [3](#0-2) 

The Cadence Arch precompile routes this call to `EVM.validateCOAOwnershipProof` via `coaOwnershipProofValidator`: [4](#0-3) 

The `COAOwnershipProof` struct is attacker-controlled: it is RLP-encoded bytes supplied as the `_sig` argument to `isValidSignature`, and the `CapabilityPath` field inside it is never authenticated against the `evmAddress`: [5](#0-4) 

---

### Impact Explanation

An attacker who observes any on-chain proof for COA\_1 (e.g., from a prior EVM transaction) can replay it against COA\_2 owned by the same Flow account. Any EVM contract that relies on ERC-1271 (`isValidSignature`) to gate asset transfers, token approvals, or governance votes will accept the forged proof as a valid signature from COA\_2's owner. This constitutes unauthorized cross-VM asset access: the attacker can trigger approvals or transfers from COA\_2's EVM address without the account holder's consent.

---

### Likelihood Explanation

- The attack requires Account A to own **two or more COAs**. The code comment notes this is historically uncommon ("Flow wallets historically create at most one COA per account"), but the protocol imposes no limit, and `EVM.createCadenceOwnedAccount()` is `access(all)`.
- The attacker needs only to observe a prior valid proof for COA\_1 — these are submitted as plain bytes in public EVM transactions and are fully observable.
- No private key material, staked-node access, or admin privilege is required.
- As multi-COA usage grows (e.g., DeFi protocols creating per-strategy COAs), the attack surface widens.

Likelihood: **Low-Medium** (currently constrained by single-COA wallet convention; structurally reachable with no privilege).

---

### Recommendation

Enforce that `signedData` commits to `evmAddress` inside `validateCOAOwnershipProof`. The simplest fix is to require callers to include the target EVM address as a prefix or suffix of `signedData` and verify this binding before accepting the proof:

```cadence
// Require signedData to begin with the 20-byte evmAddress
pre {
    signedData.length >= 20 &&
    signedData.slice(from: 0, upTo: 20) == evmAddress.toBytes():
        "EVM.validateCOAOwnershipProof(): signedData must commit to evmAddress"
}
```

Alternatively, document and enforce this requirement at the EVM layer in `coa.sol` by hashing `abi.encodePacked(address(this), _hash)` before passing it as `signedData`. [6](#0-5) 

---

### Proof of Concept

```
1. Account A creates COA_1 (EVM address X) and COA_2 (EVM address Y).
   Account A publishes:
     /public/coa1  →  &EVM.CadenceOwnedAccount  (COA_1)
     /public/coa2  →  &EVM.CadenceOwnedAccount  (COA_2)

2. Account A legitimately calls isValidSignature(hash, proof1) on COA_1's EVM contract,
   where proof1 = RLP{ address: A, path: "coa1", keyIndices: [0], signatures: [σ] }
   and σ = Sign_A(hash).  The transaction is public on-chain.

3. Attacker observes proof1 and constructs:
   proof2 = RLP{ address: A, path: "coa2", keyIndices: [0], signatures: [σ] }
   (only CapabilityPath changed; signatures are identical)

4. Attacker calls isValidSignature(hash, proof2) on COA_2's EVM contract.

5. coa.sol calls verifyCOAOwnershipProof(Y, hash, proof2) via Cadence Arch.

6. validateCOAOwnershipProof:
   - Signature check: σ is valid for Account A's key[0] over hash  ✓
   - EVM-address check: COA at /public/coa2 has address Y           ✓
   → returns ValidationResult(isValid: true)

7. isValidSignature returns ValidERC1271Signature (0x1626ba7e).
   Any EVM contract gating on ERC-1271 now treats hash as signed by COA_2's owner.
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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1115)
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

        return ValidationResult(
            isValid: false,
            problem: "EVM.validateCOAOwnershipProof(): Cannot validate COA ownership. Could not borrow the COA resource for account \(address)."
        )
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

**File:** fvm/evm/types/proof.go (L139-144)
```go
type COAOwnershipProof struct {
	KeyIndices     KeyIndices
	Address        FlowAddress
	CapabilityPath PublicPath
	Signatures     Signatures
}
```
