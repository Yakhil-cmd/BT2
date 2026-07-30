# [C/H] Front-runnable, un-authenticated `BridgeCommittee.initializeConfig` permanently binds the bridge to an attacker-controlled `IBridgeConfig`

### Title
Unauthenticated, front-runnable `initializeConfig` allows permanent hijack of `BridgeConfig` binding, enabling attacker-controlled token/decimal/chain resolution and fund theft from the vault - (File: `bridge/evm/contracts/BridgeCommittee.sol`)

### Summary
This is the same root-cause class as the `RemoteOwner`/`RngAuctionRelayerRemoteOwner` report: a security-critical cross-contract binding is resolved via a "post-deploy wiring" call rather than atomically at construction, and the guard used to protect that wiring only checks "not yet set," not "set by the right party." In the external report, the flaw was a circular-dependency deadlock; in `sui--012`'s EVM bridge, the analogous flaw is worse — it is not a deadlock but an **exploitable front-run window**, because `initializeConfig` has no access control at all.

### Finding Description
`BridgeCommittee.initializeConfig` is `external` with no `onlyOwner`/role modifier, guarded only by a one-shot check: [1](#0-0) 

The deployment script deploys `BridgeCommittee` first, then deploys `BridgeConfig` separately, and only afterwards calls `initializeConfig` in a subsequent, non-atomic transaction: [2](#0-1) 

Because `BridgeCommittee.initialize` (which sets the committee membership) and `initializeConfig` (which binds the `IBridgeConfig` contract) are two separate, publicly callable transactions with no relation to each other, any unprivileged address can observe the `BridgeCommittee` proxy deployment/initialization on-chain and front-run the legitimate `initializeConfig(address(bridgeConfig))` call with their own `initializeConfig(maliciousConfig)`. Once `config` is non-zero, it can never be changed (`require(address(config) == address(0), ...)`), permanently binding the committee — and everything that depends on `committee.config()` — to the attacker's contract.

`committee.config()` is then trusted throughout `SuiBridge` for security-critical decisions: which ERC20 address corresponds to a `tokenID`, whether a token/chain is supported, and the Sui-side decimal conversion factor used to compute cross-chain amounts: [3](#0-2) [4](#0-3) [5](#0-4) 

With a malicious `IBridgeConfig`, the attacker fully controls `tokenAddressOf`, `tokenSuiDecimalOf`, `isTokenSupported`, `isChainSupported`, and `chainID()` — the exact set of values used to (a) resolve which token address the vault transfers out in `_transferTokensFromVault`, and (b) compute the `suiAdjustedAmount` emitted in `TokensDeposited`/used for cross-chain accounting in `bridgeERC20`/`bridgeETH`. This is a direct value-accounting break: the deposited real ERC20 amount and the amount reported cross-chain for minting/crediting purposes can be made arbitrarily inconsistent, and the resolved token address for withdrawal from the vault is attacker-chosen rather than the legitimate registered token.

### Impact Explanation
This matches the Critical impact bucket: bridge message forgery / bridge governance-config bypass enabling illegitimate mint or unlock, and unauthorized manipulation of value-accounting in the bridge's core transfer path. Because the corruption of `config` is **permanent and unrecoverable** (no reset path, no re-init), this is a one-shot, irreversible compromise of the whole bridge deployment achievable by any unprivileged EOA that merely races the deployment script's transactions.

### Likelihood Explanation
Deployment races/front-running of unauthenticated initializer calls are a well-known, mechanically simple attack (mempool-visible transactions, no special access needed) — same class of "unprotected initializer" issue the external report itself proposes fixing with an ownership/one-time-set gate, except here the guard that exists (`address(config) == address(0)`) is precisely the naive "set-once" pattern known to be unsafe against front-running when it lacks a caller-identity check. Likelihood is high in any deployment where `initializeConfig` is called in a transaction separate from `initialize`/proxy creation, which is exactly what `deploy_bridge.s.sol` does.

### Recommendation
- Restrict `initializeConfig` to a trusted deployer/owner (e.g., `onlyOwner`, `onlyProxyAdmin`, or verify `msg.sender == committee_deployer`) rather than relying solely on the "not yet set" check.
- Prefer binding `config` atomically inside `BridgeCommittee.initialize` (pass the pre-computed `BridgeConfig` address, using deterministic/CREATE2 addressing if a circular dependency truly exists), eliminating the separate, unauthenticated wiring step entirely.
- Add a defense-in-depth check that the caller of `initializeConfig` is the same address that deployed/owns the `BridgeCommittee` proxy.

### Proof of Concept
1. Deployer submits tx to deploy `BridgeCommittee` proxy and calls `BridgeCommittee.initialize(...)`.
2. Attacker monitors the mempool/chain, and as soon as the `BridgeCommittee` proxy address is known (deterministic via `CREATE`/`CREATE2` from a known deployer, or simply observed post-deployment before the deployer's next tx confirms), attacker calls `BridgeCommittee(bridgeCommittee).initializeConfig(attackerConfig)` with higher gas to front-run the legitimate `initializeConfig(bridgeConfig)` call in `deploy_bridge.s.sol` line 175.
3. `require(address(config) == address(0))` passes (first caller wins), setting `config = IBridgeConfig(attackerConfig)` permanently; the legitimate deployer's subsequent call reverts with `"BridgeCommittee: Config already initialized"`.
4. All subsequent calls to `SuiBridge.bridgeERC20`, `bridgeETH`, and `transferBridgedTokensWithSignatures` now resolve token addresses, decimals, and chain support from `attackerConfig`, letting the attacker manipulate emitted cross-chain amounts and vault token resolution to their benefit.

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

**File:** bridge/evm/contracts/SuiBridge.sol (L67-82)
```text
        IBridgeConfig config = committee.config();

        BridgeUtils.TokenTransferPayload memory tokenTransferPayload =
            BridgeUtils.decodeTokenTransferPayload(message.payload);

        // verify target chain ID is this chain ID
        require(
            tokenTransferPayload.targetChain == config.chainID(), "SuiBridge: Invalid target chain"
        );

        // convert amount to ERC20 token decimals
        uint256 erc20AdjustedAmount = BridgeUtils.convertSuiToERC20Decimal(
            IERC20Metadata(config.tokenAddressOf(tokenTransferPayload.tokenID)).decimals(),
            config.tokenSuiDecimalOf(tokenTransferPayload.tokenID),
            tokenTransferPayload.amount
        );
```

**File:** bridge/evm/contracts/SuiBridge.sol (L146-176)
```text
        IBridgeConfig config = committee.config();

        require(config.isTokenSupported(tokenID), "SuiBridge: Unsupported token");

        address tokenAddress = config.tokenAddressOf(tokenID);

        // check that the bridge contract has allowance to transfer the tokens
        require(
            IERC20(tokenAddress).allowance(msg.sender, address(this)) >= amount,
            "SuiBridge: Insufficient allowance"
        );

        // calculate old vault balance
        uint256 oldBalance = IERC20(tokenAddress).balanceOf(address(vault));

        // Transfer the tokens from the contract to the vault
        SafeERC20.safeTransferFrom(IERC20(tokenAddress), msg.sender, address(vault), amount);

        // calculate new vault balance
        uint256 newBalance = IERC20(tokenAddress).balanceOf(address(vault));

        // calculate the amount transferred
        uint256 amountTransfered = newBalance - oldBalance;

        // Adjust the amount
        uint64 suiAdjustedAmount = BridgeUtils.convertERC20ToSuiDecimal(
            IERC20Metadata(tokenAddress).decimals(),
            config.tokenSuiDecimalOf(tokenID),
            amountTransfered
        );

```

**File:** bridge/evm/contracts/SuiBridge.sol (L244-265)
```text
    function _transferTokensFromVault(
        uint8 sendingChainID,
        uint8 tokenID,
        address recipientAddress,
        uint256 amount
    ) private whenNotPaused limitNotExceeded(sendingChainID, tokenID, amount) {
        address tokenAddress = committee.config().tokenAddressOf(tokenID);

        // Check that the token address is supported
        require(tokenAddress != address(0), "SuiBridge: Unsupported token");

        // transfer eth if token type is eth
        if (tokenID == BridgeUtils.ETH) {
            vault.transferETH(payable(recipientAddress), amount);
        } else {
            // transfer tokens from vault to target address
            vault.transferERC20(tokenAddress, recipientAddress, amount);
        }

        // update amount bridged
        limiter.recordBridgeTransfers(sendingChainID, tokenID, amount);
    }
```
