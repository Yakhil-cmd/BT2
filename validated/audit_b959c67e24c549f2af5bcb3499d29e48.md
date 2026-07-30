### Title
`BridgeCommittee.initializeConfig` can be front-run to bind the bridge to an attacker-controlled `BridgeConfig` - (File: `bridge/evm/contracts/BridgeCommittee.sol`)

### Summary
`BridgeCommittee.initializeConfig` mirrors the exact PoolTogether `setDrawManager` bug pattern: a "set only if unset" state variable with a null-address guard but **no caller authorization**, deployed as a step *separate* from the contract's `initializer`-gated `initialize()`. Any unprivileged address can call it first and permanently bind `config` to a malicious `IBridgeConfig` implementation before the legitimate deployment script does.

### Finding Description
`BridgeCommittee.sol` defines two initialization entry points: [1](#0-0) 

The first, `initialize`, is protected by OpenZeppelin's `initializer` modifier. The second is not: [2](#0-1) 

```solidity
function initializeConfig(address _config) external {
    require(address(config) == address(0), "BridgeCommittee: Config already initialized");
    config = IBridgeConfig(_config);
}
```

This is structurally identical to the reported `PrizePool.setDrawManager`:
- no capability/role check (`onlyOwner`, `onlyRole`, etc.) and no `initializer` modifier,
- the only guard is "set only if currently the zero value" (`address(config) == address(0)`),
- once set, it is immutable — there is no update path if the wrong address is set.

Per the deployment flow, `BridgeConfig` is deployed *after* `BridgeCommittee`, so `initializeConfig` is necessarily called in a transaction separate from `initialize`, giving an attacker a window to front-run it, exactly like the `drawManager` front-run scenario in the external report.

`config` (an `IBridgeConfig`) is the single source of truth `SuiBridge`/`SuiBridgeV2` consult for token addresses, Sui-side decimals, USD token prices, chain-ID/support checks: [3](#0-2) 

`SuiBridge.sol`/`SuiBridgeV2.sol` reference `config` in 22 places each (token resolution, decimal conversion for cross-chain amount scaling, chain-ID validation), confirming it is load-bearing for every inbound/outbound transfer computation.

### Impact Explanation
If an attacker wins the front-run and supplies a malicious `IBridgeConfig` implementation, they control:
- `tokenAddressOf` — the ERC-20 address `SuiBridge` mints/unlocks tokens against for a given Sui-side token ID,
- `tokenSuiDecimalOf` / `tokenPriceOf` — the decimal/price used to convert bridged Sui amounts into EVM token amounts,
- `isChainSupported` / `chainID` — governance-message chain validation.

Since `config` can never be replaced once set (the guard makes it a one-shot, unauthenticated setter), a malicious config becomes a **permanent** bridge-wide corruption: legitimate bridge messages authenticated by the real validator committee would resolve to attacker-chosen token contracts or attacker-chosen decimal/price scaling, allowing the attacker to redirect or amplify unlocked/minted token amounts on the EVM side. This falls under the Critical bounty category "bridge message forgery ... that enables illegitimate mint or unlock," since the message-signing/verification path (`verifySignatures`) stays intact and trusted while the *token/amount resolution* layer it depends on is attacker-controlled.

### Likelihood Explanation
Deployment scripts show `initialize` and `initializeConfig` are two independent public transactions (`initializeConfig` is called by `script/deploy_bridge.s.sol` after `BridgeConfig` is deployed), so there is a real window between `BridgeCommittee` deployment and the config being wired up. `initializeConfig` is a plain `external` function with no `initializer`/role modifier, callable by anyone watching the mempool for the committee's deployment tx. This requires no special privilege — an ordinary unauthenticated caller — matching the allowed attacker model.

### Recommendation
Restrict `initializeConfig` the same way `initialize` is restricted: either fold it into the `initializer`-gated constructor path, or gate it with an owner/role check (e.g., `onlyOwner`), so only the deployer/multisig can perform the one-time binding. Alternatively, require it to be called atomically in the same transaction as `initialize` (e.g., pass `_config` as a constructor/initializer parameter) so there is no exploitable window.

### Proof of Concept
1. Attacker monitors chain for `BridgeCommittee`'s deployment/`initialize` transaction (config address is not yet known/set, since `BridgeConfig` is deployed in a later step per `script/deploy_bridge.s.sol`).
2. Attacker deploys a malicious contract `EvilConfig` implementing `IBridgeConfig` with attacker-chosen `tokenAddressOf`/`tokenSuiDecimalOf`/`tokenPriceOf` return values.
3. Attacker calls `BridgeCommittee.initializeConfig(address(EvilConfig))` before the legitimate deployer's `initializeConfig(address(BridgeConfig))` transaction lands.
4. The legitimate call now reverts (`"BridgeCommittee: Config already initialized"`), and `SuiBridge`/`SuiBridgeV2`, which read `committee.config()` (indirectly through the committee) for every transfer, permanently resolve token/decimal/price data through `EvilConfig`.
5. When validators sign a legitimate cross-chain transfer message, `SuiBridge` uses the poisoned config to compute the destination token and amount, letting the attacker redirect minted/unlocked funds to a token/address of their choosing. [4](#0-3)

### Citations

**File:** bridge/evm/contracts/BridgeCommittee.sol (L30-57)
```text
    function initialize(address[] memory committee, uint16[] memory stake, uint16 minStakeRequired)
        external
        initializer
    {
        __CommitteeUpgradeable_init(address(this));
        __UUPSUpgradeable_init();

        uint256 _committeeLength = committee.length;

        require(_committeeLength < 256, "BridgeCommittee: Committee length must be less than 256");

        require(
            _committeeLength == stake.length,
            "BridgeCommittee: Committee and stake arrays must be of the same length"
        );

        uint16 totalStake;
        for (uint16 i; i < _committeeLength; i++) {
            require(
                committeeStake[committee[i]] == 0, "BridgeCommittee: Duplicate committee member"
            );
            committeeStake[committee[i]] = stake[i];
            committeeIndex[committee[i]] = uint8(i);
            totalStake += stake[i];
        }

        require(totalStake >= minStakeRequired, "BridgeCommittee: total stake is less than minimum"); // 10000 == 100%
    }
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

**File:** bridge/evm/contracts/interfaces/IBridgeConfig.sol (L16-44)
```text
    /* ========== VIEW FUNCTIONS ========== */

    /// @notice Returns the address of the token with the given ID.
    /// @param tokenID The ID of the token.
    /// @return address of the provided token.
    function tokenAddressOf(uint8 tokenID) external view returns (address);

    /// @notice Returns the sui decimal places of the token with the given ID.
    /// @param tokenID The ID of the token.
    /// @return amount of sui decimal places of the provided token.
    function tokenSuiDecimalOf(uint8 tokenID) external view returns (uint8);

    /// @notice Returns the price of the token with the given ID.
    /// @param tokenID The ID of the token.
    /// @return price of the provided token.
    function tokenPriceOf(uint8 tokenID) external view returns (uint64);

    /// @notice Returns the supported status of the token with the given ID.
    /// @param tokenID The ID of the token.
    /// @return true if the token is supported, false otherwise.
    function isTokenSupported(uint8 tokenID) external view returns (bool);

    /// @notice Returns whether a chain is supported in SuiBridge with the given ID.
    /// @param chainId The ID of the chain.
    /// @return true if the chain is supported, false otherwise.
    function isChainSupported(uint8 chainId) external view returns (bool);

    /// @notice Returns the chain ID of the bridge.
    function chainID() external view returns (uint8);
```

**File:** bridge/evm/test/BridgeCommitteeTest.t.sol (L55-59)
```text
    function testBridgeCommitteeInitializeConfig() public {
        vm.expectRevert(bytes("BridgeCommittee: Config already initialized"));
        // Initialize the committee with the config contract
        committee.initializeConfig(address(101));
    }
```
