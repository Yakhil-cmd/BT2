Let me trace the full call path before rendering a verdict.

**Key code facts gathered:**

`ProxySupport.initialize()` — the only access guard is `notCalledDirectly`: [1](#0-0) 

`notCalledDirectly` only blocks calls made directly to the implementation contract (where `address(this) == implementationAddress`). When called through the proxy via `delegatecall`, `address(this)` is the proxy address, so the modifier passes for **any caller**.

There is no `onlyGovernance`, `onlyAdmin`, or any other caller restriction on `initialize()`. [2](#0-1) 

`RewardSupplier.isInitialized()` returns `mintDestination() != 0`: [3](#0-2) 

`setMintDestination` uses `setUintValueOnce`, which reverts with `ALREADY_SET` if the slot is already non-zero — making the slot write permanent: [4](#0-3) [5](#0-4) 

`GovernanceStub._isGovernor` always returns `false` and `initGovernance` is a no-op — there is no governance layer in the implementation that could restrict `initialize()`: [6](#0-5) 

`tick()` unconditionally uses the stored `mintDestination()` as the L2 deposit target: [7](#0-6) 

---

### Title
Unguarded `initialize()` allows front-running to permanently redirect all minted staking rewards to an attacker-controlled L2 address — (`L1/starkware/solidity/upgrade/ProxySupportImpl.sol` / `L1/starkware/solidity/stake/RewardSupplier.sol`)

### Summary
`ProxySupport.initialize()` has no caller access control beyond `notCalledDirectly`, which only blocks direct calls to the implementation contract. Any unprivileged EOA can call `proxy.initialize(attackerData)` before the legitimate deployer, permanently setting `mintDestination` to an attacker-controlled L2 address. All subsequent `tick()` invocations will bridge newly minted staking rewards to that address.

### Finding Description
`ProxySupport.initialize()` is declared `external notCalledDirectly`. [1](#0-0) 

The `notCalledDirectly` modifier only prevents calling the bare implementation contract; it imposes no restriction on who may call through the proxy. There is no `onlyGovernance` or equivalent check.

When `isInitialized()` returns `false` (pre-initialization state, `mintDestination == 0`), the branch at lines 59–62 executes `validateInitData` then `initializeContractState` for any caller: [8](#0-7) 

`validateInitData` only checks that addresses are contracts and L2 values are non-zero — all conditions an attacker can satisfy by copying the legitimate addresses from the pending mempool transaction and substituting their own `mintDestination`: [9](#0-8) 

`setMintDestination` calls `setUintValueOnce`, making the write irreversible: [4](#0-3) 

After the attacker's call, `isInitialized()` returns `true`. The legitimate `initialize()` call hits the `if (isInitialized())` branch and reverts with `UNEXPECTED_INIT_DATA` because its `initData.length > 0`: [10](#0-9) 

### Impact Explanation
Every future call to `tick()` deposits minted reward tokens to `mintDestination()`: [7](#0-6) 

Since `mintDestination` is write-once and now points to the attacker's L2 address, **all protocol staking rewards minted in perpetuity are redirected to the attacker**. L2 stakers receive no rewards. This is permanent and unrecoverable without a proxy upgrade.

**Impact: High — Theft of unclaimed yield.**

### Likelihood Explanation
- The window is the gap between proxy deployment and the first `initialize()` transaction landing on-chain.
- The attacker only needs to watch the mempool and submit a higher-gas transaction with the same L1 addresses but a different `mintDestination`.
- No privileged access, no leaked keys, no external dependency — pure front-running on a public `external` function.
- Likelihood: **High**.

### Recommendation
Add a caller restriction to `ProxySupport.initialize()` so only the proxy admin/governor can invoke it:

```solidity
function initialize(bytes calldata data) external notCalledDirectly {
    require(_isGovernor(msg.sender), "ONLY_GOVERNANCE");
    ...
}
```

Alternatively, restrict initialization to the deployer address stored at construction time, or use a commit-reveal / constructor-time initialization pattern that eliminates the front-runnable window entirely.

### Proof of Concept
```solidity
// 1. Deploy proxy pointing to RewardSupplier implementation.
// 2. Before legitimate deployer calls initialize():
bytes memory attackerData = abi.encode(
    legitimateBridge,       // copied from pending tx
    legitimateToken,        // copied from pending tx
    legitimateMintManager,  // copied from pending tx
    legitimateMessaging,    // copied from pending tx
    legitimateMintReqSrc,   // copied from pending tx
    ATTACKER_L2_ADDRESS,    // attacker substitutes their own L2 address
    legitimateMintingCurve  // copied from pending tx
);
// Prepend EIC address slot (address(0)) as required by ProxySupport.initialize():
bytes memory initCalldata = abi.encodePacked(bytes32(0), attackerData);
proxy.initialize(initCalldata);  // succeeds — no caller check

// 3. Assert:
assert(RewardSupplier(proxy).mintDestination() == ATTACKER_L2_ADDRESS);

// 4. Legitimate initialize() now reverts with UNEXPECTED_INIT_DATA.
// 5. All tick() calls permanently bridge rewards to ATTACKER_L2_ADDRESS.
```

### Citations

**File:** L1/starkware/solidity/interfaces/ProxySupport.sol (L38-38)
```text
    function initialize(bytes calldata data) external notCalledDirectly {
```

**File:** L1/starkware/solidity/interfaces/ProxySupport.sol (L56-63)
```text
        if (isInitialized()) {
            require(initData.length == 0, "UNEXPECTED_INIT_DATA");
        } else {
            // Contract was not initialized yet.
            validateInitData(initData);
            initializeContractState(initData);
            initGovernance();
        }
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L31-49)
```text
    function validateInitData(bytes calldata data) internal view virtual override {
        require(data.length == 7 * 32, "ILLEGAL_DATA_SIZE");
        (
            address bridge,
            address token,
            address mintManager,
            address messagingContract,
            uint256 mintRequestSource,
            uint256 mintDestination,
            uint256 mintingCurveContract
        ) = abi.decode(data, (address, address, address, address, uint256, uint256, uint256));
        require(bridge.isContract(), "INVALID_BRIDGE_ADDRESS");
        require(token.isContract(), "INVALID_TOKEN_ADDRESS");
        require(mintManager.isContract(), "INVALID_MINT_MGR_ADDRESS");
        require(messagingContract.isContract(), "INVALID_MESSAGING_CONTRACT_ADDRESS");
        require(mintRequestSource != 0, "INVALID_MINT_REQ_SOURCE");
        require(mintDestination != 0, "INVALID_MINT_DESTINATION");
        require(mintingCurveContract != 0, "INVALID_MINTING_CURVE");
    }
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L85-87)
```text
    function isInitialized() internal view override returns (bool) {
        return mintDestination() != 0;
    }
```

**File:** L1/starkware/solidity/stake/RewardSupplier.sol (L126-131)
```text
            bridge().depositWithMessage{value: msgFee}(
                token(),
                amountToMint,
                mintDestination(),
                new uint256[](0)
            );
```

**File:** L1/starkware/solidity/stake/RewardSupplierStorage.sol (L80-82)
```text
    function setMintDestination(uint256 mintDestination_) internal {
        NamedStorage.setUintValueOnce(L2_MINT_DESTINATION_TAG, mintDestination_);
    }
```

**File:** L1/starkware/solidity/libraries/NamedStorage8.sol (L128-131)
```text
    function setUintValueOnce(string memory tag_, uint256 value) internal {
        require(getUintValue(tag_) == 0, "ALREADY_SET");
        setUintValue(tag_, value);
    }
```

**File:** L1/starkware/solidity/components/GovernanceStub.sol (L13-17)
```text
    function _isGovernor(
        address /*user*/
    ) internal pure override returns (bool) {
        return false;
    }
```
