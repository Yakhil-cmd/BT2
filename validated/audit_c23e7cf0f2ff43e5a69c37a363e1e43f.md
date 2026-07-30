### Title
Unprotected `initializeConfig` in `BridgeCommittee.sol` allows any unprivileged address to permanently brick the bridge config binding - (File: bridge/evm/contracts/BridgeCommittee.sol)

### Summary
The Ethereum-side `BridgeCommittee` contract exposes `initializeConfig(address _config)` as a public `external` function with no access control and no interface validation. It is guarded only by a one-time-set check (`address(config) == address(0)`), exactly mirroring the `BaseBridgeReceiver.localTimelock` bug class: a critical cross-contract binding can be set exactly once by *anyone*, to *any* address, with no verification that the target actually implements the expected interface, and with no recovery path if the wrong address is set.

### Finding Description [1](#0-0) 

```
function initializeConfig(address _config) external {
    require(address(config) == address(0), "BridgeCommittee: Config already initialized");
    config = IBridgeConfig(_config);
}
```

Unlike `initialize()` (protected by OpenZeppelin's `initializer` modifier, which can only run once during the atomic proxy-deployment transaction), `initializeConfig` has:
- No `onlyOwner`/`onlyCommittee`/access-control modifier.
- No `initializer` modifier tying it to the deployment transaction.
- No verification that `_config` implements `IBridgeConfig` (e.g., no ERC-165-style probe or sanity call).
- No way to ever reset `config` afterward — the only guard is "has it been set once," identical to the missing re-validation the external report flags for `TimeLock.admin`/`pendingAdmin`.

The deployment flow deploys `BridgeCommittee` and `BridgeConfig` as two *separate* transactions and only afterward calls `initializeConfig` in a third transaction, as shown in the deployment script: [2](#0-1) 

Between the `BridgeCommittee` proxy deployment and the legitimate `initializeConfig(address(bridgeConfig))` call, the `BridgeCommittee` proxy address is public and the pending call is visible in the mempool. Any unprivileged address can front-run this sequence and call `initializeConfig` first with an arbitrary address (a contract that doesn't implement `IBridgeConfig`, an EOA, or a malicious contract), permanently occupying the one-time slot before the legitimate config is ever bound.

`SuiBridge.sol` and `BridgeLimiter.sol` depend heavily on `committee.config()` (10 and 9 references respectively) for `tokenAddressOf`, decimal conversion, and price lookups used on every bridging operation. Once `config` is irreversibly bound to an invalid/malicious address, all downstream calls through `committee.config()` either revert (permanently) or return attacker-controlled data, with no governance-signed message able to fix it since there is no `updateConfig`/`setConfig` function gated behind `verifyMessageAndSignatures`.

### Impact Explanation
This matches the "permanent fund lock" / "harmful smart-contract behavior" High-impact class: once bricked, the Ethereum-side bridge contracts (`SuiBridge`, `BridgeLimiter`) cannot resolve token metadata/prices via `committee.config()`, permanently halting bridge transfer processing on that deployment and locking any assets already deposited in the vault pending claim, with committee signatures unable to remedy it because no signed "update config" path exists. If the attacker instead points `config` at a malicious contract they control (rather than merely an invalid one), they could return falsified `tokenAddressOf`/`tokenPriceOf` values, potentially corrupting limiter accounting or transfer validation used by the bridge — a path toward fund-theft-adjacent behavior.

### Likelihood Explanation
The attack requires only observing a public deployment transaction and quickly submitting a competing transaction to the same proxy address — a standard, cheap mempool front-run requiring no special privileges, keys, validator/authority status, or governance collusion. This is fully within the "unauthenticated caller / ordinary user" attacker model. The only mitigating factor is that this window exists solely during initial deployment (or during a future re-deployment of `BridgeCommittee` without the config already set), making exploitation opportunistic rather than continuously available — but any deployment run is trivially exploitable during that window.

### Recommendation
Bind `initializeConfig` to the same `initializer`/atomic-deployment guarantee as `initialize()` (e.g., merge config address into the `initialize()` call, or restrict `initializeConfig` to `onlyProxy` + a check that `msg.sender == address(this)` in the middle of a single deployment transaction). At minimum, add an owner/deployer-restricted access modifier, and validate that `_config` implements the expected interface (e.g., via a staticcall probe to a known view function) before binding it.

### Proof of Concept
1. Attacker monitors the mempool/chain for `Upgrades.deployUUPSProxy("BridgeCommittee.sol", ...)` confirming, yielding proxy address `P`.
2. Before the deployer's subsequent `committee.initializeConfig(address(bridgeConfig))` transaction lands, attacker submits `BridgeCommittee(P).initializeConfig(attackerControlledOrGarbageAddress)` with higher gas.
3. Attacker's transaction confirms first; `config` is now permanently set to the attacker's address (`address(config) == address(0)` check now fails for all future calls, including the legitimate deployer's).
4. Deployer's `initializeConfig` call reverts with "Config already initialized"; deployment cannot proceed with the intended config.
5. All subsequent `SuiBridge`/`BridgeLimiter` calls that route through `committee.config()` either permanently revert (DoS/fund lock for the whole bridge deployment) or return attacker-supplied data if the attacker deployed a matching malicious `IBridgeConfig` implementation.

### Citations

**File:** bridge/evm/contracts/BridgeCommittee.sol (L59-66)
```text
    /// @notice Initializes the contract with the provided parameters.
    /// @dev This function should be called directly after config deployment. The config contract address
    /// provided should be verified before bridging any assets.
    /// @param _config The address of the BridgeConfig contract.
    function initializeConfig(address _config) external {
        require(address(config) == address(0), "BridgeCommittee: Config already initialized");
        config = IBridgeConfig(_config);
    }
```

**File:** bridge/evm/script/deploy_bridge.s.sol (L174-178)
```text
        // initialize config in the bridge committee
        BridgeCommittee(bridgeCommittee).initializeConfig(address(bridgeConfig));
        BridgeCommittee committeeImplementation =
            BridgeCommittee(Upgrades.getImplementationAddress(bridgeCommittee));
        committeeImplementation.initializeConfig(address(bridgeConfig));
```
