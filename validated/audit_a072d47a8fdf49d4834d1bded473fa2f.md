### Title
Cross-chain replay of COA ownership proofs via chain-agnostic `domainSeparationTag` in `validateCOAOwnershipProof` - (File: `fvm/evm/stdlib/contract.cdc`)

---

### Summary

`EVM.validateCOAOwnershipProof` verifies Cadence account signatures over arbitrary `signedData` using a fixed `domainSeparationTag: "FLOW-V0.0-user"` that contains no chain ID. Because this tag is identical across all Flow networks (mainnet, testnet, previewnet, etc.), a signature produced on one network is cryptographically valid on any other network for the same `signedData`. The protocol does not enforce that `signedData` encodes any chain-specific context, enabling cross-chain replay of COA ownership proofs.

---

### Finding Description

**Root cause — `fvm/evm/stdlib/contract.cdc`, lines 1082–1086:**

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

The `domainSeparationTag` is the hardcoded string `"FLOW-V0.0-user"`. It is identical on every Flow network. The function accepts caller-supplied `signedData: [UInt8]` bytes with no enforcement that they encode the chain ID (e.g., `"flow-mainnet"`, `"flow-testnet"`). [1](#0-0) 

The code's own comment at lines 1003–1009 acknowledges a related cross-address replay risk but does not address cross-chain replay:

> "Note: this function does not enforce that `signedData` includes `evmAddress`. In principle, a signature produced for one purpose could be replayed here against a different COA owned by the same Cadence account." [2](#0-1) 

**Exposure surface — two reachable entry paths:**

1. **ERC-1271 via the Cadence Arch EVM precompile.** The COA contract's `isValidSignature(bytes32 _hash, bytes _sig)` calls `verifyCOAOwnershipProof(address(this), _hash, _sig)` on the Cadence Arch precompile, which in turn invokes `validateCOAOwnershipProof`. [3](#0-2) [4](#0-3) 

2. **Direct Cadence script/transaction call** to `EVM.validateCOAOwnershipProof` with attacker-controlled arguments.

**COA EVM address determinism — why replay is feasible:**

COA EVM addresses are derived solely from the Cadence resource UUID via `AllocateCOAAddress(uuid)` → `MakeCOAAddress(uuid)` → `mapAddressIndex(uuid) * addressIndexMultiplierConstant`. The mapping is purely arithmetic and contains no chain-specific input. [5](#0-4) [6](#0-5) 

If the same Cadence account creates a COA with the same resource UUID on two different networks (e.g., on a newly launched network where the UUID counter starts from the same value, or on testnet and previewnet), the resulting EVM address is identical on both networks. A signature over `signedData` produced on network A is then cryptographically valid on network B.

**End-to-end exploit path:**

1. User creates a COA on Flow testnet (UUID = N → EVM address X). User signs `signedData = hash(some_message)` with their Cadence key to prove COA ownership for an ERC-1271 integration (e.g., a DEX order).
2. The same user's COA on Flow mainnet also has UUID = N (possible when both networks share the same early-state UUID counter, e.g., previewnet → mainnet migration, or a newly bootstrapped network). The COA EVM address is therefore also X on mainnet.
3. Attacker observes the testnet proof `(address, path, signedData, keyIndices, signatures, evmAddress=X)`.
4. Attacker submits the identical proof to the mainnet ERC-1271 consumer contract, which calls `isValidSignature(hash(some_message), encodedProof)` on the COA at address X.
5. The precompile calls `validateCOAOwnershipProof` with the replayed proof. The signature verifies because `domainSeparationTag: "FLOW-V0.0-user"` is identical on both networks and `signedData` is the same bytes.
6. The ERC-1271 consumer accepts the signature as valid and executes the authorized action (token transfer, order fill, multisig approval, etc.) on mainnet.

---

### Impact Explanation

An attacker who observes a valid COA ownership proof on one Flow network can replay it on any other Flow network where the same Cadence account holds a COA with the same EVM address. ERC-1271 consumers (DEX order books, multisig wallets, token approvals) that rely on `isValidSignature` would accept the replayed proof and execute the authorized EVM action without the user's mainnet consent. This constitutes unauthorized access to on-chain EVM assets.

---

### Likelihood Explanation

**Medium-low.** The replay requires the victim's COA to have the same EVM address on both networks, which depends on the Cadence resource UUID being identical across chains. This is most likely when:
- A new Flow network is bootstrapped from a state snapshot of another network (e.g., previewnet → mainnet migration).
- A user creates a COA very early on both networks before many other resources are created, resulting in the same UUID.
- An application uses a fixed or predictable `signedData` value (e.g., a static challenge string) on multiple networks.

The `domainSeparationTag` being chain-agnostic is a structural gap that makes the replay cryptographically valid whenever the address condition is met.

---

### Recommendation

Include the chain ID in the domain separation tag used by `validateCOAOwnershipProof`. Replace the hardcoded `"FLOW-V0.0-user"` with a chain-scoped tag, for example:

```cadence
domainSeparationTag: "FLOW-V0.0-user-".concat(self.chainID)
```

where `self.chainID` is the network identifier (e.g., `"flow-mainnet"`, `"flow-testnet"`). Alternatively, enforce at the protocol level that `signedData` must encode the chain ID before signature verification proceeds.

---

### Proof of Concept

**Setup:**
- Flow testnet and a newly launched Flow network (e.g., previewnet) both start with UUID counter at the same value.
- Alice creates a COA on testnet (UUID = 1 → EVM address `0x000000000000000000000002ffeeddccbbaa9977`).
- Alice creates a COA on previewnet (UUID = 1 → same EVM address `0x000000000000000000000002ffeeddccbbaa9977`).

**Step 1 — Alice signs on testnet:**
```go
data := someHash // e.g., keccak256("authorize_transfer")
hasher, _ := crypto.NewPrefixedHashing(privateKey.HashAlgo, "FLOW-V0.0-user")
sig, _ := privateKey.PrivateKey.Sign(data.Bytes(), hasher)
proof := types.COAOwnershipProof{
    KeyIndices:     []uint64{0},
    Address:        aliceFlowAddress,
    CapabilityPath: "coa",
    Signatures:     []types.Signature{sig},
}
```

**Step 2 — Attacker replays on previewnet:**
The attacker submits an EVM transaction on previewnet calling `isValidSignature(someHash, encodedProof)` on Alice's COA at `0x000000000000000000000002ffeeddccbbaa9977`. The precompile calls `validateCOAOwnershipProof` with the testnet proof. Because `domainSeparationTag: "FLOW-V0.0-user"` is identical on both networks and `someHash` is the same bytes, the signature verifies and `isValidSignature` returns `0x1626ba7e` (valid). [5](#0-4) [1](#0-0) [3](#0-2)

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

**File:** fvm/evm/handler/addressAllocator.go (L40-46)
```go
func (aa *AddressAllocator) AllocateCOAAddress(uuid uint64) types.Address {
	return MakeCOAAddress(uuid)
}

func MakeCOAAddress(index uint64) types.Address {
	return makePrefixedAddress(mapAddressIndex(index), types.FlowEVMCOAAddressPrefix)
}
```

**File:** fvm/evm/handler/addressAllocator.go (L80-81)
```go
func mapAddressIndex(index uint64) uint64 {
	return uint64(index * addressIndexMultiplierConstant)
```
