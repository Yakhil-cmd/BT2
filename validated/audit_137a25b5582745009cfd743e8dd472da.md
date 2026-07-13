### Title
`ModuleCRC20Proxy.transfer_from_cronos_module` Unlocks from Wrong Address, Corrupting Bridge/IBC Reserve Accounting — (`contracts/src/ModuleCRC20Proxy.sol`)

---

### Summary

`ModuleCRC20Proxy.transfer_by_cronos_module` locks CRC20 tokens into `module_address`, but `transfer_from_cronos_module` attempts to release tokens from `address(this)` (the proxy itself). These are different addresses. The unlock path is permanently broken for the correct escrow, and any proxy balance accumulated from bridge/IBC operations is silently drained instead, corrupting the bridge reserve accounting.

---

### Finding Description

In `ModuleCRC21.sol`, the lock/unlock pair is symmetric — both use `module_address` as the escrow:

```solidity
// ModuleCRC21.sol
function transfer_by_cronos_module(address addr, uint amount) public {
    require(msg.sender == module_address);
    unsafe_transfer(addr, module_address, amount);   // locks INTO module_address
}
function transfer_from_cronos_module(address addr, uint amount) public {
    transferFrom(module_address, addr, amount);       // unlocks FROM module_address ✓
}
``` [1](#0-0) 

In `ModuleCRC20Proxy.sol`, the lock still targets `module_address`, but the unlock targets `address(this)` — the proxy contract — instead:

```

### Citations

**File:** contracts/src/ModuleCRC21.sol (L46-53)
```text
    function transfer_by_cronos_module(address addr, uint amount) public {
        require(msg.sender == module_address);
        unsafe_transfer(addr, module_address, amount);
    }

    function transfer_from_cronos_module(address addr, uint amount) public {
        transferFrom(module_address, addr, amount);
    }
```
