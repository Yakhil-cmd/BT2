### Title
Unprotected `initializeConfig` in `BridgeCommittee` allows front-running to set a malicious `BridgeConfig` - (File: bridge/evm/contracts/BridgeCommittee.sol)

### Summary
The external bug report describes a contract whose "set initial pool address" function has no access control, letting anyone claim it immediately after deployment/instantiation. The equivalent pattern exists in Sui's Ethereum-side bridge contract `BridgeCommittee`: its `initializeConfig` function is a plain `external` function (not gated by `initializer`, `onlyOwner`, or any committee/owner check) that can be called by any address as long as `config` is still unset.

### Finding Description
`BridgeCommittee.initializeConfig` is defined as: [1](#0-0) 

```solidity
function initializeConfig(address _config) external {
    require(address(config) == address(0), "BridgeCommittee: Config already initialized");
    config = IBridgeConfig(_config);
}
```

Unlike `initialize()` in the same contract, which is guarded by the OpenZeppelin `initializer` modifier [2](#0-1) , `initializeConfig` has no modifier at all — no `initializer`, no owner check, no committee-signature verification (unlike privileged operations elsewhere in the bridge such as `upgradeWithSignatures`, which requires committee signatures via `verifyMessageAndSignatures` [3](#0-2) ).

The deployment flow deploys `BridgeCommittee` and `BridgeConfig` as two separate transactions, then calls `committee.initializeConfig(address(bridgeConfig))` in a third, later transaction [4](#0-3) . Between the `BridgeCommittee` deployment/first `initialize()` call and the subsequent `initializeConfig` call, the contract is on-chain with `config == address(0)` and is fully callable by anyone. Because `initializeConfig` performs only a "not yet set" check and no authorization check, any attacker monitoring the public mempool can front-run the legitimate deployer's `initializeConfig` transaction with their own call supplying a malicious `IBridgeConfig` address — permanently locking in the malicious config, since the check makes this a one-time, irreversible write.

This is the exact root-cause pattern described in the external report: "anyone can set the initial [pool/config] address by front-running immediately after deploy/instantiation," because only a "not yet initialized" guard exists rather than an owner/access-control gate.

### Impact Explanation
`BridgeConfig` governs supported tokens, their Sui-decimal conversion factors, and USD token prices used by `SuiBridge` to validate and size cross-chain token transfers and to enforce the daily rate-limiter checks. A malicious `BridgeConfig` set via a front-run of `initializeConfig` would let the attacker control which tokens are "supported," their decimal-conversion factors, and their prices for the entire lifetime of the bridge deployment (the check is one-shot and cannot be corrected after the fact). This is a bridge governance bypass: the attacker — not the legitimate deployer/committee — permanently controls the parameters that determine token amount conversions and limiter checks for the bridge, which is a precondition for illegitimate unlocks/mints of bridged assets on either side of the bridge. This matches the in-scope "bridge governance or upgrade bypass that enables illegitimate mint or unlock" Critical impact.

### Likelihood Explanation
Exploitation only requires observing a public, unauthenticated transaction (deployment of `BridgeCommittee`) and racing a single, cheap follow-up transaction before the operator's own `initializeConfig` call lands — a standard mempool front-running technique requiring no special privileges, consistent with the "unauthenticated caller / ordinary holder" attacker model in scope. The likelihood is somewhat mitigated in practice because deployment scripts typically bundle these calls close together and operators can use private relays/flashbots to avoid front-running, but the contract itself provides no on-chain protection against it, so the vulnerability is real and directly reachable by public input.

### Recommendation
Gate `initializeConfig` the same way `initialize()` is gated: use the OpenZeppelin `initializer` modifier (or restrict the call to `onlyOwner`/a deployer-controlled address, or fold the config address into the constructor/main `initialize()` call so it is set atomically in a single transaction rather than being left as a separately callable, unauthenticated setter). At minimum, add an `onlyOwner`-style check or bind the call to `msg.sender == <trusted deployer address>` to eliminate the front-running window.

### Proof of Concept
1. Deployer calls `Upgrades.deployUUPSProxy("BridgeCommittee.sol", initialize(...))`, publishing the `BridgeCommittee` proxy address on-chain (as in `deploy_bridge.s.sol` [5](#0-4) ).
2. Before the deployer's subsequent `committee.initializeConfig(address(bridgeConfig))` transaction is mined, an attacker observes the pending transaction in the mempool (or simply monitors the newly deployed `BridgeCommittee` address) and submits `committee.initializeConfig(address(attackerControlledConfig))` with higher gas.
3. Because `initializeConfig` only checks `address(config) == address(0)` [6](#0-5) , the attacker's call succeeds first, and the deployer's subsequent legitimate call reverts with `"BridgeCommittee: Config already initialized"` (as demonstrated in the test asserting this exact revert message [7](#0-6) ).
4. `config` is now permanently bound to the attacker-controlled `IBridgeConfig` contract, which is subsequently consulted by `SuiBridge` for token support/decimals/price checks, giving the attacker durable control over bridge economic parameters.

Note: I was not able to fully trace how `config` values feed into `SuiBridge`'s transfer-amount and limiter logic within the available index (the grep on `SuiBridge.sol` returned matches but the surrounding code context for `tokenSuiDecimalOf`/amount conversion was not retrievable through the tools available). A Devin session with full repository access would be needed to confirm the exact downstream mint/unlock arithmetic affected by a malicious config.

### Citations

**File:** bridge/evm/contracts/BridgeCommittee.sol (L30-34)
```text
    function initialize(address[] memory committee, uint16[] memory stake, uint16 minStakeRequired)
        external
        initializer
    {
        __CommitteeUpgradeable_init(address(this));
```

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

**File:** bridge/evm/contracts/utils/CommitteeUpgradeable.sol (L59-77)
```text
    function upgradeWithSignatures(bytes[] memory signatures, BridgeUtils.Message memory message)
        external
        nonReentrant
        verifyMessageAndSignatures(message, signatures, BridgeUtils.UPGRADE)
    {
        // decode the upgrade payload
        (address proxy, address implementation, bytes memory callData) =
            BridgeUtils.decodeUpgradePayload(message.payload);

        // verify proxy address
        require(proxy == address(this), "CommitteeUpgradeable: Invalid proxy address");

        // authorize upgrade
        _upgradeAuthorized = true;
        // upgrade contract
        upgradeToAndCall(implementation, callData);

        emit ContractUpgraded(message.nonce, proxy, implementation);
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

**File:** bridge/evm/test/BridgeCommitteeTest.t.sol (L55-59)
```text
    function testBridgeCommitteeInitializeConfig() public {
        vm.expectRevert(bytes("BridgeCommittee: Config already initialized"));
        // Initialize the committee with the config contract
        committee.initializeConfig(address(101));
    }
```
