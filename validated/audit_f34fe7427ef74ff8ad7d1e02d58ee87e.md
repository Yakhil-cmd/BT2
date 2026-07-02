### Title
Cross-COA Signature Replay in `validateCOAOwnershipProof` — (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

The `EVM.validateCOAOwnershipProof` function does not enforce that `signedData` encodes the `evmAddress` being proven. A valid signature produced by a Cadence account for one of its COAs can be replayed by any unprivileged caller to pass ownership validation for a *different* COA on the same account. The code itself acknowledges this gap in a comment but treats it as a caller responsibility rather than enforcing it at the protocol level.

---

### Finding Description

`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` (lines 1011–1116) accepts six caller-supplied arguments: `address`, `path`, `signedData`, `keyIndices`, `signatures`, and `evmAddress`. It verifies that the signatures are cryptographically valid over `signedData` and that the account at `address` holds a COA whose EVM address matches `evmAddress`. However, it performs **no check that `signedData` commits to `evmAddress`**.

The code comment at lines 1002–1009 explicitly acknowledges this:

> *"Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account."*

The function is `access(all)` and callable by any Cadence script or transaction without privilege. The attacker-controlled entry path is:

1. Alice holds a Cadence account with two COAs: `COA_A` published at `/public/coaA` and `COA_B` published at `/public/coaB`.
2. Alice signs arbitrary `signedData` (e.g., for a dApp login or ERC-1271 flow) to prove ownership of `COA_A`. The signature is submitted on-chain and is publicly observable.
3. An attacker constructs a call to `EVM.validateCOAOwnershipProof` supplying:
   - `address` = Alice's Cadence address
   - `path` = `/public/coaB`
   - `signedData` = the same bytes Alice signed
   - `keyIndices` / `signatures` = Alice's observed signature set
   - `evmAddress` = `COA_B`'s EVM address
4. Because the signature is valid over `signedData` and Alice's account does hold `COA_B` at `/public/coaB`, the function returns `isValid: true`.
5. Any on-chain protocol that gates asset transfers or privileged calls on the result of `validateCOAOwnershipProof` now treats the attacker as the proven owner of `COA_B`.

The EVM-side precompile path (`verifyCOAOwnershipProof` in `fvm/evm/precompiles/arch.go`, invoked via `coa.sol`'s `isValidSignature`) is partially mitigated because the precompile always passes `address(this)` as the COA address. However, the Cadence-native `EVM.validateCOAOwnershipProof` function is directly callable from any script or transaction and carries no such constraint.

---

### Impact Explanation

Any on-chain Cadence contract or protocol that calls `EVM.validateCOAOwnershipProof` to gate asset movement or privileged operations — without itself binding `signedData` to the specific `evmAddress` — can be deceived into authorizing actions on a COA the caller did not sign for. Concretely, if a bridge, marketplace, or authentication contract accepts a proof result as sufficient authorization to withdraw tokens or NFTs from a COA, an attacker can replay a legitimately obtained signature to drain a *different* COA on the same account. The root cause is in the Flow protocol contract itself, not in any downstream caller.

---

### Likelihood Explanation

Conditions required:
- A Cadence account holds more than one COA (possible; the protocol does not restrict this).
- A protocol uses `EVM.validateCOAOwnershipProof` for authorization without binding `signedData` to `evmAddress` (realistic, given the function is `access(all)` and the warning is only in a comment).
- The attacker can observe a prior valid signature from the target account (trivially satisfied: Flow transactions and their signatures are public).

The comment's own framing ("low-risk in practice") relies on the assumption that wallets create at most one COA per account — an assumption that is not enforced by the protocol and will erode as multi-COA usage grows.

---

### Recommendation

Enforce inside `validateCOAOwnershipProof` that `signedData` commits to `evmAddress`, for example by requiring the first 20 bytes of `signedData` to equal `evmAddress`, or by hashing `evmAddress` into the signed payload before verification. This removes the replay surface at the protocol level rather than delegating it to every caller.

---

### Proof of Concept

```cadence
// Attacker script — no privileges required
import EVM from <EVM_CONTRACT_ADDRESS>

access(all)
fun main(
    aliceAddress: Address,
    aliceSignedData: [UInt8],      // observed from Alice's prior on-chain tx
    aliceKeyIndices: [UInt64],     // observed from Alice's prior on-chain tx
    aliceSignatures: [[UInt8]],    // observed from Alice's prior on-chain tx
    coaBEvmAddress: [UInt8; 20]    // Alice's second COA address, discoverable on-chain
): EVM.ValidationResult {
    // path points to Alice's SECOND COA, not the one she signed for
    return EVM.validateCOAOwnershipProof(
        address: aliceAddress,
        path: /public/coaB,
        signedData: aliceSignedData,
        keyIndices: aliceKeyIndices,
        signatures: aliceSignatures,
        evmAddress: coaBEvmAddress
    )
    // Returns isValid: true — attacker is now "proven" owner of COA_B
}
```

Root cause lines: [1](#0-0) [2](#0-1) 

Supporting precompile entry point (partially mitigated path): [3](#0-2) 

ERC-1271 surface in the COA contract: [4](#0-3)

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

**File:** fvm/evm/stdlib/contract.cdc (L1082-1086)
```text
        let isValid = keyList.verify(
            signatureSet: signatureSet,
            signedData: signedData,
            domainSeparationTag: "FLOW-V0.0-user"
        )
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
