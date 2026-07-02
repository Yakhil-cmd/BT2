### Title
COA Contract `supportsInterface` Does Not Advertise ERC-1271 Support, Breaking Smart-Contract-Wallet Integration - (File: `fvm/evm/handler/coa/coa.sol`)

### Summary
The Cadence-Owned Account (COA) EVM contract implements `isValidSignature` (ERC-1271) but its `supportsInterface` (ERC-165) function does not include the ERC-1271 interface ID (`0x1626ba7e`). Any EVM protocol or contract that follows the standard ERC-165 discovery pattern before calling `isValidSignature` will conclude that COAs do not support ERC-1271, making COAs unusable as smart-contract-wallet signers in those protocols — despite the protocol documentation explicitly advertising ERC-1271 support.

### Finding Description

The COA contract in `fvm/evm/handler/coa/coa.sol` declares itself as implementing `ERC1155TokenReceiver`, `ERC777TokensRecipient`, `ERC721TokenReceiver`, and `IERC165`, and also provides a fully functional `isValidSignature(bytes32,bytes)` implementation (ERC-1271). [1](#0-0) 

The `supportsInterface` function, however, only advertises four interface IDs:

```solidity
function supportsInterface(bytes4 id) external view virtual override returns (bool) {
    return
        id == type(ERC1155TokenReceiver).interfaceId ||
        id == type(ERC721TokenReceiver).interfaceId ||
        id == type(ERC777TokensRecipient).interfaceId ||
        id == type(IERC165).interfaceId;
}
``` [2](#0-1) 

The ERC-1271 interface ID — `bytes4(keccak256("isValidSignature(bytes32,bytes)"))` = `0x1626ba7e` — is **absent** from this list. The same value is already defined as a constant in the contract for use as the valid-signature return value: [3](#0-2) 

Meanwhile, the Cadence-side `EVM.cdc` contract documentation explicitly states:

> "From the EVM perspective, COAs are smart contract wallets that accept native token transfers and support several ERCs including ERC-165, ERC-721, ERC-777, ERC-1155, **ERC-1271**." [4](#0-3) 

The `isValidSignature` implementation itself is present and functional: [5](#0-4) 

The compiled bytecode of this contract is embedded and deployed for every COA via `coa.ContractBytes`: [6](#0-5) 

Every `DeployCOA` call deploys this exact bytecode: [7](#0-6) 

### Impact Explanation

Any EVM-side protocol (e.g., a multisig, a DEX, a lending protocol) that follows the standard ERC-165 introspection pattern — calling `supportsInterface(0x1626ba7e)` before invoking `isValidSignature` — will receive `false` from every COA. The protocol will then either reject the COA as a signer or fall back to EOA-style ECDSA verification, which COAs cannot satisfy (they have no private key by design). This makes COAs non-functional as ERC-1271 smart-contract-wallet signers in any standard-compliant EVM protocol, despite the protocol explicitly advertising ERC-1271 support.

### Likelihood Explanation

The ERC-165 pre-check before ERC-1271 usage is a widely adopted pattern in EVM tooling and protocols (Safe, OpenSea, 1inch, etc.). Any unprivileged EVM transaction sender can trigger this path simply by deploying or interacting with a contract that performs the standard `supportsInterface` check on a COA address. No special privileges are required. Every COA deployed on Flow EVM is affected because the flaw is in the shared bytecode embedded at compile time.

### Recommendation

Add the ERC-1271 interface ID to the `supportsInterface` check in `coa.sol`:

```solidity
bytes4 constant internal ERC1271InterfaceId = 0x1626ba7e;

function supportsInterface(bytes4 id) external view virtual override returns (bool) {
    return
        id == type(ERC1155TokenReceiver).interfaceId ||
        id == type(ERC721TokenReceiver).interfaceId ||
        id == type(ERC777TokensRecipient).interfaceId ||
        id == type(IERC165).interfaceId ||
        id == ERC1271InterfaceId;          // ← add this
}
```

After updating the Solidity source, recompile and update `coa_bytes.hex` and `coa_abi.json` accordingly.

### Proof of Concept

1. Deploy any EVM contract on Flow EVM that performs:
   ```solidity
   bytes4 constant ERC1271_ID = 0x1626ba7e;
   bool supported = IERC165(coaAddress).supportsInterface(ERC1271_ID);
   // supported == false  ← COA is not recognized as ERC-1271 wallet
   ```
2. The call returns `false` for every COA address, because `supportsInterface` in `coa.sol` lines 67–73 does not include `0x1626ba7e`.
3. Any protocol that gates `isValidSignature` calls behind this check will refuse to use the COA as a signer, even though `isValidSignature` is fully implemented and functional on the COA.
4. The root cause is in the embedded bytecode at `fvm/evm/handler/coa/coa_bytes.hex` (compiled from `coa.sol`), deployed for every COA via `ContractHandler.deployCOA`.

### Citations

**File:** fvm/evm/handler/coa/coa.sol (L49-49)
```text
contract COA is ERC1155TokenReceiver, ERC777TokensRecipient, ERC721TokenReceiver, IERC165 {
```

**File:** fvm/evm/handler/coa/coa.sol (L61-63)
```text
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 constant internal ValidERC1271Signature = 0x1626ba7e;
    bytes4 constant internal InvalidERC1271Signature = 0xffffffff;
```

**File:** fvm/evm/handler/coa/coa.sol (L67-73)
```text
    function supportsInterface(bytes4 id) external view virtual override returns (bool) {
        return
            id == type(ERC1155TokenReceiver).interfaceId ||
            id == type(ERC721TokenReceiver).interfaceId ||
            id == type(ERC777TokensRecipient).interfaceId ||
            id == type(IERC165).interfaceId;
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

**File:** fvm/evm/stdlib/contract.cdc (L466-474)
```text
    /* 
        Cadence-Owned Accounts (COA) 
        A COA is a natively supported EVM smart contract wallet type 
        that allows a Cadence resource to own and control an EVM address.
        This native wallet provides the primitives needed to bridge
        or control assets across Flow EVM and Cadence.
        From the EVM perspective, COAs are smart contract wallets
        that accept native token transfers and support several ERCs
        including ERC-165, ERC-721, ERC-777, ERC-1155, ERC-1271.
```

**File:** fvm/evm/handler/coa/coa.go (L10-14)
```go
//go:embed coa_bytes.hex
var contractBytesInHex string

// ContractBytes is the compiled version of the coa smart contract.
var ContractBytes, _ = hex.DecodeString(contractBytesInHex)
```

**File:** fvm/evm/handler/handler.go (L173-195)
```go
func (h *ContractHandler) deployCOA(uuid uint64) (*types.Result, error) {
	// step 1 - check enough computation is available
	gaslimit := types.GasLimit(coa.ContractDeploymentRequiredGas)
	err := h.checkGasLimit(gaslimit)
	if err != nil {
		return nil, err
	}

	// step 2 - allocate a new address for the COA
	target := h.addressAllocator.AllocateCOAAddress(uuid)

	// step 3 - create a COA deployment call
	factory := h.addressAllocator.COAFactoryAddress()
	factoryAccount := h.AccountByAddress(factory, false)
	factoryNonce := factoryAccount.Nonce()
	call := types.NewDeployCallWithTargetAddress(
		factory,
		target,
		coa.ContractBytes,
		uint64(gaslimit),
		new(big.Int),
		factoryNonce,
	)
```
