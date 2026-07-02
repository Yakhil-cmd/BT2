### Title
COA Contract Implements ERC-1271 But Omits It From `supportsInterface` - (File: fvm/evm/handler/coa/coa.sol)

### Summary
The Cadence-Owned Account (COA) EVM smart contract implements the ERC-1271 `isValidSignature` function and is explicitly documented as supporting ERC-1271, but its `supportsInterface` (ERC-165) implementation does not include the ERC-1271 interface ID (`0x1626ba7e`). Any EVM contract or off-chain integration that performs an ERC-165 introspection check before invoking ERC-1271 will incorrectly conclude that COAs do not support smart-contract signature validation, breaking the advertised capability.

### Finding Description
The COA contract in `fvm/evm/handler/coa/coa.sol` is the system-level EVM smart contract wallet deployed for every Flow Cadence-Owned Account. The official documentation in `fvm/evm/stdlib/contract.cdc` explicitly states:

> "COAs are smart contract wallets that accept native token transfers and support several ERCs including ERC-165, ERC-721, ERC-777, ERC-1155, **ERC-1271**."

The contract does implement `isValidSignature(bytes32,bytes)` (the sole function of ERC-1271), delegating to the `verifyCOAOwnershipProof` Cadence Arch precompile. However, the `supportsInterface` function only advertises four interfaces:

```solidity
function supportsInterface(bytes4 id) external view virtual override returns (bool) {
    return
        id == type(ERC1155TokenReceiver).interfaceId ||
        id == type(ERC721TokenReceiver).interfaceId  ||
        id == type(ERC777TokensRecipient).interfaceId ||
        id == type(IERC165).interfaceId;
}
```

The ERC-1271 interface ID — `bytes4(keccak256("isValidSignature(bytes32,bytes)"))` = `0x1626ba7e` — is absent. Notably, the contract already defines this exact value as the constant `ValidERC1271Signature` (used as the return value for a valid signature), yet never uses it in `supportsInterface`. [1](#0-0) [2](#0-1) 

### Impact Explanation
ERC-165 introspection is the standard mechanism by which EVM contracts and off-chain tooling (wallets, DeFi protocols, NFT marketplaces, multisig frameworks) determine whether a contract supports a given interface before calling it. The ERC-1271 standard itself recommends checking `supportsInterface` before calling `isValidSignature`. Any integrator following this pattern will receive `false` for `supportsInterface(0x1626ba7e)` on a COA address and will either:
- Skip the ERC-1271 call entirely, treating the COA as an EOA (which it is not), causing signature validation to fail; or
- Reject the COA as a valid signer in contexts that require ERC-1271 support (e.g., Safe multisig, Permit2, EIP-4337 account abstraction flows).

This breaks the ERC-1271 functionality that is a core, documented feature of every COA on the network. [3](#0-2) 

### Likelihood Explanation
Every COA deployed on Flow EVM is affected — this is a protocol-level contract, not a user-deployed one. Any EVM contract or off-chain tool that follows the standard ERC-165 introspection pattern before using ERC-1271 will encounter this issue. The likelihood is high because ERC-165 checks before ERC-1271 calls are a widely adopted pattern in the EVM ecosystem.

### Recommendation
Add the ERC-1271 interface ID to `supportsInterface`. The constant is already defined in the contract:

```solidity
// bytes4(keccak256("isValidSignature(bytes32,bytes)"))
bytes4 constant internal ValidERC1271Signature = 0x1626ba7e;
```

Update `supportsInterface` to:

```solidity
function supportsInterface(bytes4 id) external view virtual override returns (bool) {
    return
        id == type(ERC1155TokenReceiver).interfaceId ||
        id == type(ERC721TokenReceiver).interfaceId  ||
        id == type(ERC777TokensRecipient).interfaceId ||
        id == type(IERC165).interfaceId               ||
        id == ValidERC1271Signature;                   // ERC-1271
}
``` [4](#0-3) 

### Proof of Concept
1. Any unprivileged EVM transaction sender deploys or obtains a COA address (e.g., via `EVM.createCadenceOwnedAccount()`).
2. The sender calls `supportsInterface(0x1626ba7e)` on the COA address.
3. The call returns `false`, despite the COA implementing `isValidSignature`.
4. An EVM contract such as a Safe multisig or any EIP-1271-aware protocol that checks `IERC165(coa).supportsInterface(0x1626ba7e)` before calling `isValidSignature` will treat the COA as a non-ERC-1271 contract and reject it as a signer.

The root cause is entirely within the production file `fvm/evm/handler/coa/coa.sol` at lines 67–73, reachable by any unprivileged EVM caller querying the COA contract. [5](#0-4) [6](#0-5)

### Citations

**File:** fvm/evm/handler/coa/coa.sol (L49-73)
```text
contract COA is ERC1155TokenReceiver, ERC777TokensRecipient, ERC721TokenReceiver, IERC165 {
    address constant public cadenceArch = 0x0000000000000000000000010000000000000001;

    // bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))
    bytes4 constant internal ERC721ReceivedIsSupported = 0x150b7a02;

    // bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))
    bytes4 constant internal ERC1155ReceivedIsSupported = 0xf23a6e61;

    // bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))
    bytes4 constant internal ERC1155BatchReceivedIsSupported = 0xbc197c81;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 constant internal ValidERC1271Signature = 0x1626ba7e;
    bytes4 constant internal InvalidERC1271Signature = 0xffffffff;

    receive() external payable  {
    }
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

**File:** fvm/evm/handler/coa/coa.go (L1-19)
```go
package coa

import (
	_ "embed"
	"encoding/hex"
)

var ContractDeploymentRequiredGas = uint64(723_000)

//go:embed coa_bytes.hex
var contractBytesInHex string

// ContractBytes is the compiled version of the coa smart contract.
var ContractBytes, _ = hex.DecodeString(contractBytesInHex)

// ContractABIJSON is the json string of ABI of the coa smart contract.
//
//go:embed coa_abi.json
var ContractABIJSON string
```
