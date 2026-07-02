### Title
Cross-Address COA Ownership Proof Replay via Missing `signedData`/`evmAddress` Binding — (`File: fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` verifies that a Cadence account's keys signed `signedData`, and that the account holds a COA at the given `path` whose EVM address matches `evmAddress`. However, the function **does not enforce that `signedData` encodes `evmAddress`**. A signature produced by a Cadence account owner for any arbitrary purpose (e.g., signing a message for COA-A) can be replayed against a different COA (COA-B) owned by the same Cadence account, causing `validateCOAOwnershipProof` to return `isValid: true` for COA-B without the account owner ever intending to authorize COA-B. This is an authorization bypass in the COA ownership proof mechanism, directly analogous to the external report's "insufficient origin verification" class.

---

### Finding Description

The function `validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` accepts six caller-controlled parameters: `address`, `path`, `signedData`, `keyIndices`, `signatures`, and `evmAddress`.

The validation logic performs two independent checks:

1. **Signature check** (lines 1082–1093): Verifies that the provided `signatures` over `signedData` are valid for the account keys at `address`.
2. **COA address check** (lines 1095–1110): Borrows the COA resource at `path` from `address` and checks that its EVM address matches `evmAddress`.

The code comment at lines 1001–1009 explicitly acknowledges the gap:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."

The two checks are **not cryptographically bound to each other**. The `signedData` is never required to commit to `evmAddress`. An attacker who obtains a valid signature from a Cadence account owner over any `signedData` (e.g., a signature produced for COA-A's EVM address, or any other signed message from that account) can supply a different `evmAddress` (COA-B) and a different `path` pointing to COA-B, and the function will return `isValid: true` for COA-B — even though the account owner never signed anything that referenced COA-B.

The EVM-side precompile `verifyCOAOwnershipProof` (called from `fvm/evm/handler/precompiles.go` via `coaOwnershipProofValidator`) always passes the **calling contract's** EVM address as `evmAddress`, which prevents the attack through the EVM precompile path. However, `validateCOAOwnershipProof` is also a **public `access(all)` Cadence function** callable directly from any Cadence script or transaction, where the caller fully controls all six parameters including `evmAddress` and `path`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

Any Cadence script or transaction author (unprivileged, no keys required beyond what they already hold) can call `EVM.validateCOAOwnershipProof` directly with:
- `address` = victim's Cadence address
- `path` = `/public/coa_b` (path to victim's second COA)
- `signedData` = any data the victim previously signed (e.g., obtained from a prior on-chain interaction or off-chain authentication flow)
- `signatures` = the victim's valid signatures over that `signedData`
- `evmAddress` = victim's COA-B EVM address

The function returns `isValid: true`, falsely asserting that the victim authorized COA-B. Any off-chain or on-chain system that relies on `validateCOAOwnershipProof` returning `true` as proof that the Cadence account owner authorized a specific EVM address will be deceived. This enables **unauthorized cross-VM identity assertion**: an attacker can impersonate a victim's ownership of a COA they never authorized in the current context, potentially enabling unauthorized asset bridging, ERC-1271 signature forgery, or access control bypass in any protocol that uses this proof as an authorization gate. [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

The attack requires:
1. A Cadence account that owns **more than one COA** (or has published a COA capability at a known path).
2. A valid signature from that account over any `signedData` — obtainable from any prior on-chain transaction, authentication flow, or off-chain interaction.

Both conditions are realistic. The code comment itself acknowledges the risk and notes it is "low-risk" only because "Flow wallets historically create at most one COA per account" — but this is a social/operational assumption, not a protocol enforcement. Any protocol or dApp that creates multiple COAs per account, or that uses `validateCOAOwnershipProof` in an off-chain authentication flow where `signedData` does not encode `evmAddress`, is directly exploitable. The function is `access(all)` and callable by any unprivileged transaction sender. [7](#0-6) 

---

### Recommendation

Enforce that `signedData` cryptographically commits to `evmAddress`. Specifically:

- Require that `signedData` is structured as `hash(evmAddress || nonce || context)` or similar, and verify this structure inside `validateCOAOwnershipProof` before accepting the proof as valid.
- Alternatively, document and enforce at the protocol level that callers of `validateCOAOwnershipProof` must construct `signedData` to include `evmAddress`, and add a runtime check that rejects proofs where `signedData` does not contain the expected `evmAddress` bytes.
- The EVM precompile path (`verifyCOAOwnershipProof`) already enforces the correct `evmAddress` by passing `address(this)`, but the Cadence-callable path has no such enforcement. [2](#0-1) 

---

### Proof of Concept

**Setup**: Victim account `V` owns two COAs: COA-A at `/public/coa_a` (EVM address `0xAAAA...`) and COA-B at `/public/coa_b` (EVM address `0xBBBB...`). Victim previously signed `signedData = "hello"` for COA-A (e.g., in an ERC-1271 flow), producing `sig`.

**Attack** (Cadence script, callable by any unprivileged sender):

```cadence
import EVM from <EVM_CONTRACT_ADDRESS>

access(all)
fun main(): EVM.ValidationResult {
    // Attacker supplies victim's signature over "hello" (originally for COA-A),
    // but targets COA-B's evmAddress and path.
    return EVM.validateCOAOwnershipProof(
        address: <VICTIM_CADENCE_ADDRESS>,
        path: /public/coa_b,                  // COA-B's path
        signedData: "hello".utf8,             // data victim signed for COA-A
        keyIndices: [0],
        signatures: [<VICTIM_SIG_OVER_HELLO>],
        evmAddress: <COA_B_EVM_ADDRESS_BYTES> // COA-B's address
    )
    // Returns: ValidationResult(isValid: true, problem: nil)
    // — even though victim never signed anything referencing COA-B
}
```

The function passes both checks: the signature over `"hello"` is valid for the victim's key, and COA-B's EVM address matches the supplied `evmAddress`. The result falsely asserts COA-B ownership authorization. [8](#0-7) [9](#0-8)

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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1116)
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

**File:** fvm/evm/precompiles/arch.go (L27-46)
```go
var (
	FlowBlockHeightFuncSig = ComputeFunctionSelector("flowBlockHeight", nil)

	ProofVerifierFuncSig = ComputeFunctionSelector(
		"verifyCOAOwnershipProof",
		[]string{"address", "bytes32", "bytes"},
	)

	RandomSourceFuncSig = ComputeFunctionSelector("getRandomSource", []string{"uint64"})

	RevertibleRandomFuncSig = ComputeFunctionSelector("revertibleRandom", nil)

	// FlowBlockHeightFixedGas is set to match the `number` opCode (0x43)
	FlowBlockHeightFixedGas = uint64(2)
	// ProofVerifierBaseGas covers the cost of decoding, checking capability the resource
	// and the rest of operations excluding signature verification
	ProofVerifierBaseGas = uint64(1_000)
	// ProofVerifierGasMultiplerPerSignature is set to match `ECRECOVER`
	// but we might increase this in the future
	ProofVerifierGasMultiplerPerSignature = uint64(3_000)
```
