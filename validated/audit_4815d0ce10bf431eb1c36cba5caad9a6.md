### Title
Unprivileged Front-Running of `initialize()` on RewardSupplier Proxy Grants Infinite Token Approval to Attacker-Controlled Bridge — (`L1/starkware/solidity/interfaces/ProxySupport.sol`)

---

### Summary

The `initialize()` function in `ProxySupport.sol` has no caller access control beyond the `notCalledDirectly` modifier. Any unprivileged attacker can call `proxy.initialize(data)` before the legitimate deployer, supplying an attacker-controlled `bridge` address alongside legitimate other parameters. This causes `IERC20(realToken).approve(attackerBridge, type(uint256).max)` to execute in the proxy's storage context, permanently sets the bridge to the attacker's address (via `setAddressValueOnce`), and blocks all future legitimate initialization attempts.

---

### Finding Description

`ProxySupport.initialize()` is decorated only with `notCalledDirectly`:

```solidity
function initialize(bytes calldata data) external notCalledDirectly {
``` [1](#0-0) 

The `notCalledDirectly` modifier only prevents calling the function directly on the **implementation** contract — it does not restrict who can call `initialize()` through the **proxy**:

```solidity
modifier notCalledDirectly() {
    require(this_ != address(this), "DIRECT_CALL_DISALLOWED");
    _;
}
``` [2](#0-1) 

`this_` is the implementation address (set at construction time). When called via `delegatecall` through the proxy, `address(this)` becomes the proxy address, so the check passes for **any caller**.

The initialization branch has no governance or role check:

```solidity
} else {
    validateInitData(initData);
    initializeContractState(initData);
    initGovernance();
}
``` [3](#0-2) 

`isInitialized()` in `RewardSupplier` returns `mintDestination() != 0`, so a freshly deployed proxy (where `mintDestination` is 0) is vulnerable:

```solidity
function isInitialized() internal view override returns (bool) {
    return mintDestination() != 0;
}
``` [4](#0-3) 

`initializeContractState` calls `IERC20(token).approve(bridge, type(uint256).max)` and stores all values via `setXxxValueOnce`:

```solidity
setBridge(bridge);
setToken(token);
...
IERC20(token).approve(bridge, type(uint256).max);
``` [5](#0-4) 

The `setAddressValueOnce` / `setUintValueOnce` helpers revert with `"ALREADY_SET"` if the slot is non-zero:

```solidity
function setAddressValueOnce(string memory tag_, address value) internal {
    require(getAddressValue(tag_) == address(0x0), "ALREADY_SET");
    setAddressValue(tag_, value);
}
``` [6](#0-5) 

Once the attacker's initialization succeeds, all subsequent legitimate initialization attempts revert permanently.

---

### Impact Explanation

- The attacker supplies the real `token` address (STRK) and real `mintManager` address (both pass `isContract()`), but an attacker-controlled `bridge` contract.
- `IERC20(realSTRK).approve(attackerBridge, type(uint256).max)` executes in the proxy's context, granting the attacker's bridge unlimited allowance over the proxy's STRK balance.
- The stored `bridge` is permanently the attacker's address. Every subsequent `tick()` call mints real STRK to the proxy and then calls `attackerBridge.depositWithMessage(...)`, which the attacker controls and can use to drain all minted tokens.
- **Impact: Complete theft of all tokens ever minted by the RewardSupplier** — Critical.

---

### Likelihood Explanation

- Proxy deployment and initialization are separate transactions, creating a front-running window.
- The attacker only needs to deploy one malicious bridge contract (trivial) and monitor the mempool.
- No privileged access, leaked keys, or external dependency compromise is required.
- The attack is deterministic and locally testable.

---

### Recommendation

Add a governance/owner check to `initialize()` in `ProxySupport.sol`, or ensure the proxy contract itself gates `initialize()` to a trusted caller (e.g., the deployer or a governance address). Alternatively, deploy and initialize the proxy atomically in a single transaction to eliminate the front-running window.

---

### Proof of Concept

1. Deploy `attackerBridge` (any contract with a `depositWithMessage` function).
2. Observe the mempool for the legitimate `proxy.initialize(...)` transaction.
3. Front-run it by calling:
   ```solidity
   proxy.initialize(abi.encode(
       attackerBridge,   // bridge — attacker-controlled
       realSTRKToken,    // token — real STRK (isContract() passes)
       realMintManager,  // mintManager — real (isContract() passes)
       realMessaging,    // messagingContract
       realMintRequestSource,  // non-zero
       realMintDestination,    // non-zero (makes isInitialized() = true)
       realMintingCurve        // non-zero
   ));
   ```
4. Verify: `IERC20(realSTRKToken).allowance(proxy, attackerBridge) == type(uint256).max`.
5. Legitimate `initialize()` now reverts with `"ALREADY_SET"` on every storage setter.
6. Call `proxy.tick()` — tokens are minted to the proxy and forwarded to `attackerBridge`, which transfers them to the attacker.

### Citations

**File:** L1/starkware/solidity/interfaces/ProxySupport.sol (L38-38)
```text
    function initialize(bytes calldata data) external notCalledDirectly {
```

**File:** L1/starkware/solidity/interfaces/ProxySupport.sol (L58-63)
```text
        } else {
            // Contract was not initialized yet.
            validateInitData(initData);
            initializeContractState(initData);
            initGovernance();
        }
```

**File:** L1/starkware/solidity/interfaces/BlockDirectCall.sol (L17-20)
```text
    modifier notCalledDirectly() {
        require(this_ != address(this), "DIRECT_CALL_DISALLOWED");
        _;
    }
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L75-82)
```text
        setBridge(bridge);
        setToken(token);
        setMintManager(mintManager);
        setMessagingContract(messagingContract);
        setMintRequestSource(mintRequestSource);
        setMintDestination(mintDestination);
        setMintingCurve(mintingCurveContract);
        IERC20(token).approve(bridge, type(uint256).max);
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L85-87)
```text
    function isInitialized() internal view override returns (bool) {
        return mintDestination() != 0;
    }
```

**File:** L1/starkware/solidity/libraries/NamedStorage8.sol (L147-150)
```text
    function setAddressValueOnce(string memory tag_, address value) internal {
        require(getAddressValue(tag_) == address(0x0), "ALREADY_SET");
        setAddressValue(tag_, value);
    }
```
