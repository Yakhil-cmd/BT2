### Title
`BridgeCommittee.initializeConfig` can be front-run because it has no access control, allowing an attacker to permanently bind a malicious `BridgeConfig` to the Sui bridge committee - (File: `bridge/evm/contracts/BridgeCommittee.sol`)

### Summary
The Velodrome bug is a two-step, non-atomic "constructor linking" pattern: `Bribe` is deployed, and later `Gauge`'s constructor calls `Bribe.setGauge()`, which has no access control other than a one-time "already set" guard, so anyone can call it first and permanently break the linkage. Sui's own EVM bridge contracts contain the exact same anti-pattern in `BridgeCommittee.initializeConfig()`, which sets the `IBridgeConfig` reference used by the bridge committee, guarded only by `require(address(config) == address(0), ...)` with no `onlyOwner`/deployer check. [1](#0-0) 

### Finding Description
`BridgeCommittee.initialize()` sets up the committee members/stakes via the standard OZ `initializer` modifier (which is single-shot and safe). Separately, `initializeConfig(address _config)` binds the `IBridgeConfig` contract that the committee/bridge relies on for chain/token configuration. This function is `external`, callable by anyone, and is protected only by a check that `config` has not been set yet: [2](#0-1) 

The deployment script confirms this is a genuinely separate, non-atomic step: `BridgeCommittee` (and its implementation) is deployed and initialized in one transaction, `BridgeConfig` is deployed in another, and only afterward is `initializeConfig` invoked in a third, distinct broadcasted transaction: [3](#0-2) 

Because these are independent transactions from the deployer's EOA broadcast to a public mempool (Ethereum/EVM chain), and `initializeConfig` has no `onlyOwner`/deployer restriction, any unauthenticated third party observing the mempool between the `BridgeCommittee` deployment and the `initializeConfig` call can front-run with their own `_config` address. Once set, the guard `address(config) == address(0)` will forever prevent it from being corrected, exactly mirroring the `Bribe.setGauge` root cause: an unprivileged "set-once, no access control" linker function that is not atomic with the rest of deployment.

### Impact Explanation
If an attacker wins the race and binds a malicious `IBridgeConfig` implementation, the legitimate `BridgeCommittee`/bridge stack would be permanently pointed at attacker-controlled configuration data (token address mappings, decimals, supported chain IDs, etc., per `BridgeConfig.initialize` parameters seen in the deploy script). Depending on how downstream bridge logic (`SuiBridge`/`BridgeVault`/`BridgeLimiter`) consumes `config` for validating message payloads, token identities, and decimal conversions, this could enable message/asset misinterpretation on the EVM side of the bridge (e.g., wrong token/decimals mapping used when unlocking/minting bridged assets), which aligns with the in-scope Critical category "bridge message forgery or bridge governance or upgrade bypass that enables illegitimate mint or unlock." At minimum, it results in a permanently broken/unusable committee contract requiring full redeployment — a permanent fund lock / harmful contract behavior (High) outcome, matching the original report's "temporary system-breaking impact" classification but for Sui's own bridge deployment.

I was not able to fully trace, within tool budget, every downstream consumer of `BridgeCommittee.config` to confirm the exact value-accounting path from a forged config to an actual illegitimate mint/unlock; that dependency chain (`SuiBridge`/`BridgeVault` usage of `config`) should be verified to determine whether this rises to Critical (illegitimate mint/unlock) or is bounded to High/permanent-lock.

### Likelihood Explanation
Likelihood is contingent on real-world deployment practice: this is only exploitable during the bridge's one-time bootstrap deployment sequence on a public network, requires the attacker to observe the mempool and front-run a specific, low-frequency administrative transaction, and would need a well-funded/fast bot to win the race. This mirrors the "medium, requires unfortunate timing / one-time event" likelihood profile from the original Velodrome finding, but the consequence here touches core bridge configuration rather than a single Bribe/Gauge pair.

### Recommendation
Restrict `initializeConfig` to the contract owner/deployer (e.g. `onlyOwner` or `onlyRole(DEFAULT_ADMIN_ROLE)`), or fold the config address into the atomic `initialize()` initializer so it cannot be set in a separate, unauthenticated transaction — the same fix Velodrome ultimately applied by removing the non-atomic `setGauge` pattern.

### Proof of Concept
1. Deployer broadcasts `Upgrades.deployUUPSProxy("BridgeCommittee.sol", initialize(...))`, creating `bridgeCommittee` with `config == address(0)`.
2. An attacker monitoring the mempool sees this transaction land and, before the deployer's subsequent `initializeConfig` call is mined, submits `BridgeCommittee(bridgeCommittee).initializeConfig(attackerControlledConfig)` with higher gas.
3. The attacker's transaction is mined first; `config` is now permanently set to `attackerControlledConfig` because of the `address(config) == address(0)` one-time guard shown at [2](#0-1) .
4. The deployer's legitimate `initializeConfig(address(bridgeConfig))` call (line 175 of `deploy_bridge.s.sol`) now reverts, and the bridge stack is permanently misconfigured, requiring redeployment of `BridgeCommittee` (and any dependent contracts already pointed at it).

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

**File:** bridge/evm/script/deploy_bridge.s.sol (L124-178)
```text
        address bridgeCommittee = Upgrades.deployUUPSProxy(
            "BridgeCommittee.sol",
            abi.encodeCall(
                BridgeCommittee.initialize,
                (
                    deployConfig.committeeMembers,
                    committeeMemberStake,
                    uint16(deployConfig.minCommitteeStakeRequired)
                )
            ),
            opts
        );

        // deploy bridge config =====================================================================

        // convert token prices from uint256 to uint64
        uint64[] memory tokenPrices = new uint64[](deployConfig.tokenPrices.length);
        for (uint256 i; i < deployConfig.tokenPrices.length; i++) {
            tokenPrices[i] = uint64(deployConfig.tokenPrices[i]);
        }

        // convert Sui Decimals from uint256 to uint8
        uint8[] memory suiDecimals = new uint8[](deployConfig.suiDecimals.length);
        for (uint256 i; i < deployConfig.suiDecimals.length; i++) {
            suiDecimals[i] = uint8(deployConfig.suiDecimals[i]);
        }

        // convert Token Id from uint256 to uint8
        uint8[] memory tokenIds = new uint8[](deployConfig.tokenIds.length);
        for (uint256 i; i < deployConfig.tokenIds.length; i++) {
            tokenIds[i] = uint8(deployConfig.tokenIds[i]);
        }

        address bridgeConfig = Upgrades.deployUUPSProxy(
            "BridgeConfig.sol",
            abi.encodeCall(
                BridgeConfig.initialize,
                (
                    address(bridgeCommittee),
                    uint8(deployConfig.sourceChainId),
                    deployConfig.supportedTokens,
                    tokenPrices,
                    tokenIds,
                    suiDecimals,
                    supportedChainIds
                )
            ),
            opts
        );

        // initialize config in the bridge committee
        BridgeCommittee(bridgeCommittee).initializeConfig(address(bridgeConfig));
        BridgeCommittee committeeImplementation =
            BridgeCommittee(Upgrades.getImplementationAddress(bridgeCommittee));
        committeeImplementation.initializeConfig(address(bridgeConfig));
```
