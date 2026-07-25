### Title
Bridge Token Minter Role Can Be Added But Not Admin-Revoked, Permanently Granting Mint Privilege to a Compromised Bridge — (`contracts/libs/openzeppelin-contracts-v2/contracts/access/roles/MinterRole.sol`)

---

### Summary

The `MinterRole` contract inherited by Kaia's service-chain bridge token contracts (`ServiceChainToken` ERC-20, `ServiceChainNFT` ERC-721) exposes `addMinter(address)` callable by any existing minter, but provides no owner-callable `removeMinter(address)`. The only removal path is `renounceMinter()`, which requires the minter itself to initiate. Once a bridge contract address is granted the minter role, the token owner has no on-chain mechanism to revoke that privilege. If the bridge contract is later replaced, found buggy, or exploited, the old bridge address retains permanent, irrevocable minting rights over the bridged asset.

---

### Finding Description

`MinterRole.sol` defines the following public interface:

```solidity
function addMinter(address account) public onlyMinter { _addMinter(account); }
function renounceMinter() public { _removeMinter(msg.sender); }
// _removeMinter is internal — no external owner-callable removeMinter(address) exists
``` [1](#0-0) 

The standard bridge deployment flow, confirmed in multiple test files, is:

```go
token.connect(owner).addMinter(bridge.address)
``` [2](#0-1) [3](#0-2) 

After this call, `bridge.address` is permanently in the minter set. The token owner (`Ownable`) has no function to call `_removeMinter(bridge.address)`. The only escape is `bridge.renounceMinter()`, which requires the bridge contract itself to cooperate — impossible if the bridge is compromised or decommissioned.

`ERC20Mintable` (used by `ServiceChainToken`) inherits `MinterRole` directly and adds no `removeMinter`: [4](#0-3) 

The generated Go bindings for `ServiceChainToken` confirm only `AddMinter` and `RenounceMinter` exist — no `RemoveMinter` callable by the owner: [5](#0-4) [6](#0-5) 

---

### Impact Explanation

If the bridge contract at `bridge.address` is:
- **Replaced** by a new deployment (old address retains mint rights indefinitely)
- **Found to have a logic bug** that an attacker can trigger to call `mint`
- **Compromised** via its own owner key

...the attacker can call `mint(attacker, uint256.max)` on the token contract without restriction, inflating the bridged token supply without any corresponding locked collateral on the parent chain. This constitutes **unauthorized mint of bridged assets** — a direct match to the allowed impact gate.

---

### Likelihood Explanation

Bridge contracts are complex and have historically been replaced or upgraded. The scenario where an old bridge address retains minting rights after replacement is a realistic operational risk. Additionally, `addMinter` is callable by **any existing minter** (not just the owner), meaning a compromised bridge can itself add further minters before being detected: [7](#0-6) 

This compounds the one-way-street problem: not only can the owner not remove a minter, but any minter can proliferate the role.

---

### Recommendation

Add an owner-callable `removeMinter` to the bridge token contracts (or override `MinterRole` in `ServiceChainToken`/`ServiceChainNFT`):

```solidity
function removeMinter(address account) public onlyOwner {
    _removeMinter(account);
}
```

Additionally, restrict `addMinter` to `onlyOwner` rather than `onlyMinter` to prevent privilege escalation through the minter role itself.

---

### Proof of Concept

1. Deploy `ServiceChainToken` (inherits `ERC20Mintable` → `MinterRole`). Owner is `alice`.
2. Deploy `Bridge`. `alice` calls `token.addMinter(bridge.address)`.
3. `Bridge` is later found to have a reentrancy bug. `alice` deploys `Bridge2` and calls `token.addMinter(bridge2.address)`.
4. `alice` attempts to revoke `bridge.address` minter role. There is no `removeMinter(bridge.address)` on the token. `alice` cannot call `bridge.renounceMinter()` because `alice` is not the bridge contract's owner (or the bridge is already exploited/frozen).
5. Attacker exploits `bridge.address` and calls `bridge.handleERC20Transfer(...)` → internally calls `token.mint(attacker, 1e30)`. The call succeeds because `bridge.address` is still a valid minter. Unbacked tokens are minted to the attacker. [8](#0-7) [4](#0-3)

### Citations

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/access/roles/MinterRole.sol (L1-43)
```text
pragma solidity ^0.5.0;

import "../Roles.sol";

contract MinterRole {
    using Roles for Roles.Role;

    event MinterAdded(address indexed account);
    event MinterRemoved(address indexed account);

    Roles.Role private _minters;

    constructor () internal {
        _addMinter(msg.sender);
    }

    modifier onlyMinter() {
        require(isMinter(msg.sender), "MinterRole: caller does not have the Minter role");
        _;
    }

    function isMinter(address account) public view returns (bool) {
        return _minters.has(account);
    }

    function addMinter(address account) public onlyMinter {
        _addMinter(account);
    }

    function renounceMinter() public {
        _removeMinter(msg.sender);
    }

    function _addMinter(address account) internal {
        _minters.add(account);
        emit MinterAdded(account);
    }

    function _removeMinter(address account) internal {
        _minters.remove(account);
        emit MinterRemoved(account);
    }
}
```

**File:** node/sc/bridge_test.go (L573-577)
```go
	// Give minter role to bridge contract
	tx, err = erc721.AddMinter(bridgeAccount, bridgeAddr)
	assert.NoError(t, err)
	backend.Commit()
	assert.Nil(t, bind.CheckWaitMined(backend, tx))
```

**File:** node/sc/multi_bridge_test.go (L505-510)
```go
	// Give minter role to bridge contract
	opts = &bind.TransactOpts{From: acc.From, Signer: acc.Signer, GasLimit: DefaultBridgeTxGasLimit}
	tx, err = erc721.AddMinter(opts, info.bAddr)
	assert.NoError(t, err)
	info.sim.Commit()
	assert.NoError(t, bind.CheckWaitMined(info.sim, tx))
```

**File:** contracts/libs/openzeppelin-contracts-v2/contracts/token/ERC20/ERC20Mintable.sol (L12-24)
```text
contract ERC20Mintable is ERC20, MinterRole {
    /**
     * @dev See `ERC20._mint`.
     *
     * Requirements:
     *
     * - the caller must have the `MinterRole`.
     */
    function mint(address account, uint256 amount) public onlyMinter returns (bool) {
        _mint(account, amount);
        return true;
    }
}
```

**File:** contracts/bindings/testing/sc_erc20/sc_token.go (L1962-1981)
```go
// AddMinter is a paid mutator transaction binding the contract method 0x983b2d56.
//
// Solidity: function addMinter(address account) returns()
func (_ERC20Mintable *ERC20MintableTransactor) AddMinter(opts *bind.TransactOpts, account common.Address) (*types.Transaction, error) {
	return _ERC20Mintable.contract.Transact(opts, "addMinter", account)
}

// AddMinter is a paid mutator transaction binding the contract method 0x983b2d56.
//
// Solidity: function addMinter(address account) returns()
func (_ERC20Mintable *ERC20MintableSession) AddMinter(account common.Address) (*types.Transaction, error) {
	return _ERC20Mintable.Contract.AddMinter(&_ERC20Mintable.TransactOpts, account)
}

// AddMinter is a paid mutator transaction binding the contract method 0x983b2d56.
//
// Solidity: function addMinter(address account) returns()
func (_ERC20Mintable *ERC20MintableTransactorSession) AddMinter(account common.Address) (*types.Transaction, error) {
	return _ERC20Mintable.Contract.AddMinter(&_ERC20Mintable.TransactOpts, account)
}
```

**File:** contracts/bindings/testing/sc_erc20/sc_token.go (L2067-2086)
```go
// RenounceMinter is a paid mutator transaction binding the contract method 0x98650275.
//
// Solidity: function renounceMinter() returns()
func (_ERC20Mintable *ERC20MintableTransactor) RenounceMinter(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _ERC20Mintable.contract.Transact(opts, "renounceMinter")
}

// RenounceMinter is a paid mutator transaction binding the contract method 0x98650275.
//
// Solidity: function renounceMinter() returns()
func (_ERC20Mintable *ERC20MintableSession) RenounceMinter() (*types.Transaction, error) {
	return _ERC20Mintable.Contract.RenounceMinter(&_ERC20Mintable.TransactOpts)
}

// RenounceMinter is a paid mutator transaction binding the contract method 0x98650275.
//
// Solidity: function renounceMinter() returns()
func (_ERC20Mintable *ERC20MintableTransactorSession) RenounceMinter() (*types.Transaction, error) {
	return _ERC20Mintable.Contract.RenounceMinter(&_ERC20Mintable.TransactOpts)
}
```
