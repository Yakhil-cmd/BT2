### Title
Cross-Network Replay of COA Ownership Proof Signatures Due to Chain-Agnostic Domain Separation Tag - (File: `fvm/evm/stdlib/contract.cdc`)

### Summary
`EVM.validateCOAOwnershipProof` verifies Cadence account signatures over an arbitrary `signedData` blob using the fixed domain separation tag `"FLOW-V0.0-user"`. This tag contains no chain/network identifier. A valid COA ownership proof signature produced on one Flow network (e.g., testnet) is cryptographically indistinguishable from one produced on another (e.g., mainnet), enabling cross-network replay attacks against EVM smart contracts that rely on ERC-1271 COA ownership proofs for authorization.

### Finding Description
`EVM.validateCOAOwnershipProof` in `fvm/evm/stdlib/contract.cdc` verifies a set of Cadence account signatures over caller-supplied `signedData`:

```cadence
let isValid = keyList.verify(
    signatureSet: signatureSet,
    signedData: signedData,
    domainSeparationTag: "FLOW-V0.0-user"
)
```

The domain separation tag `"FLOW-V0.0-user"` is a **fixed, network-agnostic string**. It does not incorporate the Flow chain ID (`flow-mainnet`, `flow-testnet`, etc.) or any other network-specific value. The `signedData` field is an opaque byte array supplied entirely by the caller — the protocol imposes no requirement that it encode the network, the EVM chain ID, or any other binding context.

The function is exposed as a public Cadence function callable from any Cadence script or transaction, and is also invoked by the `verifyCOAOwnershipProof` Cadence Arch precompile, which is in turn called by the COA's ERC-1271 `isValidSignature` implementation in `fvm/evm/handler/coa/coa.sol`:

```solidity
function isValidSignature(bytes32 _hash, bytes memory _sig) external view virtual returns (bytes4) {
    (bool ok, bytes memory data) = cadenceArch.staticcall(
        abi.encodeWithSignature("verifyCOAOwnershipProof(address,bytes32,bytes)", address(this), _hash, _sig)
    );
    ...
}
```

The code comment at lines 1003–1009 acknowledges a related cross-address replay risk but explicitly dismisses it as low-risk and does not address cross-network replay at all.

### Impact Explanation
An attacker who observes a valid `COAOwnershipProof` (Cadence signatures + capability path) produced on one Flow network can replay it verbatim on another Flow network where the same Cadence account exists with the same keys and a COA at the same capability path. Because the domain tag is identical across networks, `validateCOAOwnershipProof` returns `isValid: true` on the target network.

The concrete impact is against EVM smart contracts that use ERC-1271 (`isValidSignature`) backed by COA ownership proofs for authorization — e.g., multisig wallets, order books, permit-style approvals, or governance contracts. An attacker can impersonate a COA owner on mainnet using a signature the victim produced on testnet (or any other Flow network), causing the EVM contract to accept an unauthorized action.

### Likelihood Explanation
- Flow accounts are deterministically addressed; the same account address and key set routinely exists on both testnet and mainnet for developers and power users.
- COA capability paths are conventionally `/public/coa` (as shown in tests and documentation), making the path match trivially.
- EVM contracts are frequently deployed at the same address on multiple networks via CREATE2 or deterministic deployers.
- The attacker only needs to observe a single valid proof on any Flow network — no privileged access is required. The proof is submitted as calldata to an EVM transaction, which is public.
- The `signedData` is a `bytes32` hash; if the EVM contract on mainnet presents the same hash (e.g., same order hash, same permit hash), the replayed proof is accepted.

### Recommendation
Include the Flow chain ID in the domain separation tag used for COA ownership proof signature verification, so that signatures are cryptographically bound to a specific network. One approach is to derive the tag dynamically from the chain ID at contract initialization or at verification time:

```cadence
// Instead of the fixed tag:
domainSeparationTag: "FLOW-V0.0-user"

// Use a chain-specific tag, e.g.:
domainSeparationTag: "FLOW-V0.0-user-".concat(getCurrentChainID())
```

Alternatively, mandate that `signedData` encodes the chain ID (and ideally the EVM chain ID) as part of the signed message, and enforce this at the protocol level rather than leaving it to callers.

### Proof of Concept
1. On **testnet**: a user's Cadence account `0xABCD` has key index 0 and a COA at `/public/coa`. An EVM dApp on testnet asks the user to sign `keccak256("approve order #42")` → the user produces a `COAOwnershipProof` with their Cadence key, signing `signedData = keccak256("approve order #42")` under tag `"FLOW-V0.0-user"`.

2. An attacker observes the encoded proof (it is public calldata in the EVM transaction on testnet).

3. On **mainnet**: the same account `0xABCD` exists with the same key. An EVM contract (deployed at the same address via CREATE2) calls `coa.isValidSignature(keccak256("approve order #42"), encodedProof)`.

4. The call reaches `validateCOAOwnershipProof` on mainnet. The domain tag is `"FLOW-V0.0-user"` — identical to testnet. The signature verifies. The function returns `isValid: true`.

5. The EVM contract on mainnet accepts the replayed proof as a valid authorization, allowing the attacker to execute the order on behalf of the victim.

---

**Root cause lines:** [1](#0-0) 

**Fixed domain tag with no chain binding:** [2](#0-1) 

**ERC-1271 entry point that triggers the vulnerable path:** [3](#0-2) 

**Precompile dispatcher that routes to `validateCOAOwnershipProof`:** [4](#0-3) 

**`SignedData` type — opaque bytes, no chain binding enforced:** [5](#0-4)

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

**File:** fvm/evm/types/proof.go (L36-47)
```go
type SignedData []byte

var SignedDataCadenceType = cadence.NewVariableSizedArrayType(cadence.UInt8Type)
var SignedDataSemaType = sema.ByteArrayType

func (sd SignedData) ToCadenceValue() cadence.Array {
	values := make([]cadence.Value, len(sd))
	for i, v := range sd {
		values[i] = cadence.NewUInt8(v)
	}
	return cadence.NewArray(values).WithType(SignedDataCadenceType)
}
```
