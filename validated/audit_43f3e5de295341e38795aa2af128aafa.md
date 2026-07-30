### Title
Irreversible token burn in `bridge::send_token` before destination-chain support is verified can permanently freeze user funds - (File: `crates/sui-framework/packages/bridge/sources/bridge.move`)

### Summary
The Sui Native Bridge's Sui→Ethereum transfer flow burns the user's coin on Sui *before* any guarantee that the Ethereum-side contract currently recognizes that token. If the token's on-chain configuration on the two sides has diverged (e.g., a token id/type is registered and burnable in `bridge::treasury` on Sui but not (or no longer) mapped to a non-zero address in the EVM `IBridgeConfig`), the user's coins are irrecoverably burned on Sui while the corresponding claim on Ethereum will permanently revert with `"SuiBridge: Unsupported token"`. There is no refund, cancel, or reclaim path in the Move module. This is the direct structural analog of the SKALE `TokenManagerERC20` bug: the origin chain commits the transfer irreversibly while the destination chain enforces a separate, independently-configurable support gate, and a mismatch between the two permanently strands the user's funds.

### Finding Description
`send_token<T>` (and `send_token_v2<T>`) build a `BridgeMessage` and immediately call `send_token_internal`, which burns the coin unconditionally as long as `chain_ids::is_valid_route` passes: [1](#0-0) [2](#0-1) 

`send_token_internal` only checks the bridge is not paused and that the chain route (chain-pair) is valid — it never checks whether the *specific token type/id* is currently supported on the destination chain: [3](#0-2) 

Once burned, the pending `BridgeRecord` must later be approved (`approve_token_transfer`) and claimed on the target chain. For the Sui→Ethereum direction, the actual claim happens on `SuiBridge.sol#transferBridgedTokensWithSignatures`, which independently checks whether the destination (Ethereum) side still recognizes the token: [4](#0-3) 

If `committee.config().tokenAddressOf(tokenID)` returns `address(0)` — which happens whenever the EVM-side token registry has not yet added, or has removed, support for that `tokenID` — the require reverts with `"SuiBridge: Unsupported token"`, and the transfer can never be completed. Nothing in `bridge.move` provides a refund/cancel/reclaim entry point for stuck `BridgeRecord`s, so the burned coin is gone permanently.

This exactly mirrors the SKALE report's structure:
- Origin side (Sui `send_token`) irreversibly commits the asset (burn) based on its own local view that the token is supported.
- Destination side (`SuiBridge.sol` / EVM token config) independently gates acceptance behind its own, separately-governed support flag (`isTokenSupported`/`tokenAddressOf`), analogous to `automaticDeploy`.
- A mismatch between the two configurations (achievable simply by asset/token governance rollout being asynchronous between chains, or a token being deprecated/de-listed on one side after being listed on the other) causes permanent fund loss for an ordinary, unprivileged user who merely called the public `send_token` entry function in good faith.

### Impact Explanation
This results in permanent loss of user funds (coins burned on Sui with no possibility of claim or refund on Ethereum), matching the "permanent fund lock" / "harmful smart-contract behavior" High/Medium impact tier. It is triggered purely by calling a public, unprivileged entry function (`send_token`/`send_token_v2`) — the attacker model here is just an ordinary bridge user, not a malicious admin, validator, or governance quorum; the loss is a direct consequence of the protocol's own missing cross-chain state-consistency check, not of a malicious actor's on-chain action.

### Likelihood Explanation
Token support state on the two independently-operated chains (Sui `treasury.supported_tokens` vs. EVM `IBridgeConfig`) is governed by separate signed system messages (`add_tokens_on_sui` vs. an EVM-side equivalent), so any lag, partial rollout, or de-listing between the two creates a real window in which `send_token` succeeds and burns funds on Sui while the corresponding claim on Ethereum is guaranteed to fail. No adversarial coordination is required — a routine, temporary desync during token onboarding/offboarding is sufficient, and the burn happens on the very first user transaction that hits the mismatched window.

### Recommendation
- Add a way to reclaim/refund a `BridgeRecord` that has been pending beyond a timeout without being claimed (e.g., allow the original sender to reclaim the coin from `token_transfer_records` if never claimed after a cooldown), mirroring the audit's suggested timelock/cache remediation.
- Consider maintaining a mirrored, committee-attested "destination supports token X" flag on Sui that `send_token` checks before burning, so unsupported-on-destination transfers are rejected at the source instead of silently bricking funds.
- Ensure token de-listing/relisting operations across the two chains are coordinated via a timelock so no in-flight transfer can land in an unsupported window.

### Proof of Concept
1. Token `T` is registered and supported for bridging in Sui's `bridge::treasury` (`add_new_token` executed via `execute_system_message`/`add_tokens_on_sui`), but the corresponding EVM `IBridgeConfig` for chain `X` has not yet added `T`'s `tokenID` (returns `address(0)` from `tokenAddressOf`), or has since removed it.
2. An ordinary user calls `bridge::send_token<T>(bridge, target_chain=X, target_address, coin, ctx)`. This passes `chain_ids::is_valid_route` (chain pair X is valid) and unconditionally burns the coin via `inner.treasury.burn(token)` in `send_token_internal` (`bridge.move:610-633`).
3. The bridge committee later signs the message; the user or relayer submits `SuiBridge.transferBridgedTokensWithSignatures` on Ethereum.
4. `_transferTokensFromVault` (`SuiBridge.sol:244-253`) reverts on `require(tokenAddress != address(0), "SuiBridge: Unsupported token")` — permanently, since the EVM contract logic can never succeed for this `tokenID` until governance updates its config (out of the user's control).
5. The user's coin is permanently gone: burned on Sui with no code path in `bridge.move` to reclaim it.

### Citations

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L218-256)
```text
public fun send_token<T>(
    bridge: &mut Bridge,
    target_chain: u8,
    target_address: vector<u8>,
    token: Coin<T>,
    ctx: &mut TxContext,
) {
    let inner = load_inner_mut(bridge);

    let bridge_seq_num = inner.get_current_seq_num_and_increment(message_types::token());
    let token_id = inner.treasury.token_id<T>();
    let token_amount = token.balance().value();
    assert!(target_address.length() == EVM_ADDRESS_LENGTH, EInvalidEvmAddress);
    assert!(token_amount > 0, ETokenValueIsZero);

    // create bridge message
    let message = message::create_token_bridge_message(
        inner.chain_id,
        bridge_seq_num,
        address::to_bytes(ctx.sender()),
        target_chain,
        target_address,
        token_id,
        token_amount,
    );

    inner.send_token_internal(target_chain, token, message);

    // emit event
    event::emit(TokenDepositedEvent {
        seq_num: bridge_seq_num,
        source_chain: inner.chain_id,
        sender_address: address::to_bytes(ctx.sender()),
        target_chain,
        target_address,
        token_type: token_id,
        amount: token_amount,
    });
}
```

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L610-633)
```text
fun send_token_internal<T>(
    inner: &mut BridgeInner,
    target_chain: u8,
    token: Coin<T>,
    message: BridgeMessage,
) {
    assert!(!inner.paused, EBridgeUnavailable);
    assert!(chain_ids::is_valid_route(inner.chain_id, target_chain), EInvalidBridgeRoute);

    // burn / escrow token, unsupported coins will fail in this step
    inner.treasury.burn(token);

    // Store pending bridge request
    inner
        .token_transfer_records
        .push_back(
            message.key(),
            BridgeRecord {
                message,
                verified_signatures: option::none(),
                claimed: false,
            },
        );
}
```

**File:** bridge/evm/contracts/SuiBridge.sol (L244-253)
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
```
