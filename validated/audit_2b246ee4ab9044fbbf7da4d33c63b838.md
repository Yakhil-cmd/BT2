### Title
Missing Access Control on `transfer_from_cronos_module` Allows Unauthorized CRC21 Token Drain from Module Escrow - (File: `contracts/src/ModuleCRC21.sol`)

---

### Summary

`ModuleCRC21.transfer_from_cronos_module` is the only module-restricted function in the contract that omits the `require(msg.sender == module_address)` guard present on every other privileged function. Any unprivileged caller can invoke it. The internal call to `transferFrom(module_address, addr, amount)` then executes with `msg.sender` equal to the attacker rather than `module_address`, causing DSToken's allowance check to apply. If `module_address` holds an allowance for the caller (or if `allowance[module_address][caller] == type(uint256).max`), the attacker can drain CRC21 tokens escrowed in `module_address` without authorization.

---

### Finding Description

**Bug class (from external report):** auth bypass caused by wrong `msg.sender` in an internal call, where the missing outer access-control guard is the root cause.

In `ModuleCRC21.sol`, every module-restricted function carries the guard:

```solidity
require(msg.sender == module_address);
``` [1](#0-0) 

`transfer_from_cronos_module` is the sole exception:

```solidity
function transfer_from_cronos_module(address addr, uint amount) public {
    transferFrom(module_address, addr, amount);
}
``` [2](#0-1) 

Compare with the corrected version in the integration-test contract `TestERC21Source.sol` and the production `ModuleCRC20Proxy.sol`, both of which include the guard:

```solidity
function transfer_from_cronos_module(address addr, uint amount) public {
    require(msg.sender == module_address);
    transfer(addr, amount);
}
``` [3](#0-2) [4](#0-3) 

**Why the internal call matters (the `msg.sender` mechanic):**

When the Cronos keeper calls `transfer_from_cronos_module` via `CallModuleCRC21`, the EVM message is sent with `From = types.EVMModuleAddress` (which equals `module_address`):

```go
msg := &core.Message{
    From: types.EVMModuleAddress,
    ...
}
``` [5](#0-4) 

Inside `transfer_from_cronos_module`, `msg.sender == module_address`. The internal call to `transferFrom(module_address, addr, amount)` therefore has `src == msg.sender`, so DSToken's allowance check is skipped — the keeper's path works correctly.

When an **attacker** calls `transfer_from_cronos_module` directly, `msg.sender == attacker`. DSToken's `transferFrom` then checks `allowance[module_address][attacker]`. If that allowance is non-zero (or `uint(-1)`), the transfer executes without any module authorization.

**Where `module_address` holds a balance:**

The keeper's `ConvertCoinFromNativeToCRC21` for source-coin denoms calls `transfer_from_cronos_module` to release escrowed CRC21 tokens held by `module_address`:

```go
// unlock crc tokens
_, err = k.CallModuleCRC21(ctx, contract, "transfer_from_cronos_module", sender, coin.Amount.BigInt())
``` [6](#0-5) 

`module_address` therefore accumulates a real CRC21 balance for every source-coin IBC conversion.

---

### Impact Explanation

**Critical** — Unauthorized transfer of CRC21 tokens from the module escrow account.

If `module_address` has approved any address (e.g., through a future keeper path, a reentrancy edge case, or a direct `approve` call made as `module_address`), an attacker can call `transfer_from_cronos_module(attacker, balance)` and drain the entire CRC21 escrow. This breaks the 1:1 accounting between native IBC vouchers and CRC21 tokens: native coins have already been burned on the Cosmos side, but the corresponding CRC21 tokens are stolen rather than delivered to the rightful owner, resulting in permanent loss of funds for users who initiated conversions.

Even without an existing allowance, the missing guard is a direct bypass of the module-account authorization model: the function is publicly callable by any unprivileged address, violating the invariant that only `module_address` may release escrowed tokens.

---

### Likelihood Explanation

The immediate exploit requires `module_address` to have a non-zero allowance for the attacker. The current keeper code does not issue `approve` calls. However:

1. The guard is structurally absent — any future keeper change that issues an `approve` from `module_address` immediately opens the drain path.
2. The function is already reachable by any unprivileged EVM caller today; no special role or key is needed.
3. All peer contracts (`ModuleCRC20Proxy`, `TestERC21Source`, `TestCRC20Proxy`) include the guard, confirming this omission is unintentional.

---

### Recommendation

Add the missing access-control guard to `transfer_from_cronos_module` in `ModuleCRC21.sol`, consistent with every other module-restricted function and with the corrected versions in sibling contracts:

```solidity
function transfer_from_cronos_module(address addr, uint amount) public {
    require(msg.sender == module_address);   // ADD THIS LINE
    transferFrom(module_address, addr, amount);
}
``` [2](#0-1) 

Alternatively, replace the `transferFrom` call with `unsafe_transfer(module_address, addr, amount)` (already defined in the same contract) and keep the guard, eliminating the allowance dependency entirely.

---

### Proof of Concept

```solidity
// Attacker steps (assuming module_address has approved attacker, e.g. via any future keeper path):
// 1. Deploy or obtain a reference to the ModuleCRC21 contract at `crc21`.
// 2. Confirm module_address holds a balance: crc21.balanceOf(module_address) > 0
// 3. Call directly — no role, no governance, no key needed:
crc21.transfer_from_cronos_module(attacker, crc21.balanceOf(module_address));
// 4. Attacker now holds tokens that were escrowed for legitimate IBC conversion users.
//    Native coins on the Cosmos side have already been burned; CRC21 tokens are stolen.
```

The call succeeds because `transfer_from_cronos_module` has no `require(msg.sender == module_address)` check. DSToken's `transferFrom` is the only gate, and it is bypassable whenever `allowance[module_address][attacker]` is non-zero — a condition the missing guard was supposed to make irrelevant.

### Citations

**File:** contracts/src/ModuleCRC21.sol (L36-49)
```text
    function mint_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        mint(addr, amount);
    }

    function burn_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        unsafe_burn(addr, amount);
    }

    function transfer_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        unsafe_transfer(addr, module_address, amount);
    }
```

**File:** contracts/src/ModuleCRC21.sol (L51-53)
```text
    function transfer_from_cronos_module(address addr, uint amount) public {
        transferFrom(module_address, addr, amount);
    }
```

**File:** integration_tests/contracts/contracts/TestERC21Source.sol (L51-54)
```text
	function transfer_from_cronos_module(address addr, uint amount) public {
		require(msg.sender == module_address);
		transfer(addr, amount);
	}
```

**File:** contracts/src/ModuleCRC20Proxy.sol (L56-59)
```text
    function transfer_from_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        crc20Contract.move(address(this), addr, amount);
    }
```

**File:** x/cronos/keeper/evm.go (L26-28)
```go
	msg := &core.Message{
		From:            types.EVMModuleAddress,
		To:              to,
```

**File:** x/cronos/keeper/evm.go (L125-129)
```go
		// unlock crc tokens
		_, err = k.CallModuleCRC21(ctx, contract, "transfer_from_cronos_module", sender, coin.Amount.BigInt())
		if err != nil {
			return err
		}
```
