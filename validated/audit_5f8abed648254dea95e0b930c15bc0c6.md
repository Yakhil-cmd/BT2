### Title
Approved position NFT sales can be front-run by draining or leveraging the underlying lending account - (File: contracts/position-nft/src/contract.rs)

### Summary
A position NFT approval authorizes transfer of the token, but does not escrow or freeze the collateral/debt represented by that token. Between approval and marketplace settlement, the seller can still call `Controller::withdraw` or `Controller::borrow`, extract value from the same account, and let the NFT sale complete. The buyer receives the same token id but an economically impaired account.

### Finding Description
Every controller account is identified by the position NFT token id, and the controller resolves account authority dynamically through `owner_of` rather than caching an owner. [1](#0-0)  The NFT contract exports the standard OpenZeppelin `approve`, `approve_for_all`, `transfer`, and `transfer_from` interface without adding a sale lock or escrow around the controller account. [2](#0-1) 

The controller still treats the current NFT holder as fully authorized while the token is merely approved for a marketplace. `process_withdraw` authenticates the caller, loads the account, accepts the current owner or delegate, and pays the requested collateral to `to` or the caller. [3](#0-2)  Similarly, `borrow` is exposed for an owner/delegate and pays borrowed assets to `to` or the caller. [4](#0-3) 

Because settlement is keyed only by `token_id`, an approved marketplace transfer does not commit to the account's supply and debt state. The transferred token still carries the account, including both collateral and debt. [5](#0-4)  Tests confirm that an approved operator can move the token and that the approval is cleared only after the transfer. [6](#0-5) 

### Impact Explanation
A buyer can pay the agreed market price for a position NFT after the seller has already extracted most of its backing or added substantial debt. For example, an account advertised as holding 1,000 USDC and zero debt can be changed into an account holding 100 USDC and 900 USDC-equivalent debt before `transfer_from` executes. The NFT transfer still succeeds because the seller retained ownership and the approval remained live.

The seller keeps both the withdrawn/borrowed assets and the sale proceeds, while the buyer receives a materially different obligation than the observed account state implied. This is theft of buyer funds or permanent impairment of the purchased account. If the seller fully empties the account, `cleanup_account_if_empty` can burn the NFT instead, causing the sale to fail and creating the same non-escrow invalidation pattern as the source finding. [7](#0-6) 

### Likelihood Explanation
The sequence requires only ordinary unprivileged calls already exposed by the protocol:

1. Seller calls `PositionNft::approve(marketplace, token_id, live_until_ledger)`.
2. Before marketplace settlement, seller calls `Controller::borrow` or `Controller::withdraw` on the same `account_id`.
3. Marketplace calls `PositionNft::transfer_from(spender, seller, buyer, token_id)` while the approval is still live.
4. Buyer receives `token_id == account_id`, including its changed collateral and debt.

No privileged role, leaked key, oracle manipulation, or protocol invariant failure is needed. The seller only needs to remain the NFT owner until settlement and preserve enough collateral/debt state to satisfy the controller's post-operation checks. Any marketplace that prices the NFT from controller views without an atomic lock-and-transfer mechanism is exposed.

### Recommendation
Do not treat a standard NFT approval as a commitment to the current controller account state. Add an explicit sale/escrow mode that, while active, blocks owner- or delegate-initiated `withdraw`, `borrow`, `multiply`, `swap_collateral`, `swap_debt`, `repay_debt_with_collateral`, `flash_position`, and delegate changes for the account.

A settlement payload should also bind the trade to an expected account-state commitment, such as the exact supply map, debt map, spoke, mode, market indexes, and expiration ledger. The buyer-side settlement path should revalidate that commitment atomically before or during the NFT transfer. At minimum, marketplaces should transfer the NFT only through a dedicated protocol sale entrypoint that snapshots and freezes the account state atomically.

### Proof of Concept
```rust
// Initial state:
// - Alice owns account_id == token_id.
// - The account has 1,000 USDC supply and no debt.
// - Marketplace is approved to move the NFT.

// 1. Alice authorizes the marketplace sale.
position_nft.approve(
    alice,
    marketplace,
    token_id,
    live_until_ledger,
);

// 2. Alice front-runs the marketplace settlement.
//    The account remains solvent, so the borrow succeeds.
controller.borrow(
    alice,
    account_id,
    vec![(usdc_key, 900_0000000)],
    Some(alice),
);

// 3. Marketplace settles the previously observed sale.
position_nft.transfer_from(
    marketplace,
    alice,
    buyer,
    token_id,
);

// Result:
// - buyer owns token_id/account_id;
// - the account still has approximately 1,000 USDC supply,
//   but now also has approximately 900 USDC debt;
// - Alice keeps the 900 USDC borrow plus the buyer's payment.
```

The same pattern works with `Controller::withdraw` when the account's remaining debt permits it. If withdrawal empties the account completely, the controller deletes the account and burns the NFT, making the approved `transfer_from` fail because the token no longer exists.

### Citations

**File:** contracts/position-nft/src/contract.rs (L1-5)
```rust
//! Lending-position NFT: one token per controller account, and the token id is
//! the account id. The token owner (`owner_of`) is the account owner.
//! Mint, burn and upgrade are controller-only; `renew` is permissionless. The
//! rest is the stock OpenZeppelin non-fungible interface with a custom
//! `token_uri`.
```

**File:** contracts/position-nft/README.md (L39-41)
```markdown
Transferring the token transfers the whole position. Nothing in the controller
changes on transfer: the next controller call resolves the new holder and
accepts it. Collateral and debt both move with the token.
```

**File:** contracts/position-nft/README.md (L56-65)
```markdown
Inherited from the OpenZeppelin `NonFungibleToken` trait, exported unchanged:

| Call | Signature | Caller | Does |
| --- | --- | --- | --- |
| `balance` | `fn balance(e: &Env, account: Address) -> u32` | Anyone | Number of positions held by `account` |
| `owner_of` | `fn owner_of(e: &Env, token_id: u32) -> Address` | Anyone | Current holder; panics `NonExistentToken` if never minted or burned |
| `transfer` | `fn transfer(e: &Env, from: Address, to: Address, token_id: u32)` | `from` must authorize | Moves the position to `to` |
| `transfer_from` | `fn transfer_from(e: &Env, spender: Address, from: Address, to: Address, token_id: u32)` | `spender` must authorize and be `from`, approved for the token, or an operator for `from` | Moves the position to `to` |
| `approve` | `fn approve(e: &Env, approver: Address, approved: Address, token_id: u32, live_until_ledger: u32)` | `approver` must authorize and be the owner or an operator | Grants `approved` the right to move that one position until `live_until_ledger` |
| `approve_for_all` | `fn approve_for_all(e: &Env, owner: Address, operator: Address, live_until_ledger: u32)` | `owner` must authorize | Makes `operator` able to move every position `owner` holds until `live_until_ledger`; `0` revokes |
```

**File:** contracts/controller/src/positions/supply.rs (L140-158)
```rust
pub(crate) fn process_withdraw(
    env: &Env,
    caller: &Address,
    account_id: u64,
    withdrawals: &Vec<HubPayment>,
    to: Option<Address>,
) -> Vec<HubPayment> {
    validation::require_authorized_caller(env, caller);

    let mut account = storage::get_account(env, account_id);
    require_owner_or_delegate(env, account_id, caller, &account.owner);

    let recipient = to.unwrap_or_else(|| caller.clone());
    let mut cache = Context::new(env);
    require_external_recipient(env, &mut cache, &recipient);
    let aggregated = payments::aggregate_payments(env, withdrawals, payments::ZeroLeg::MeansAll);

    let paid = settle_withdraw(env, &mut account, &recipient, &aggregated, &mut cache);
    let _ = enforce_post_pool_solvency(env, &mut cache, &mut account);
```

**File:** contracts/controller/src/lib.rs (L104-115)
```rust
    /// Borrows against `account_id`'s collateral, paying `to` or the caller.
    /// Requires owner or delegate authorization and post-borrow solvency.
    #[when_not_paused]
    fn borrow(
        env: Env,
        caller: Address,
        account_id: u64,
        borrows: Vec<(HubAssetKey, i128)>,
        to: Option<Address>,
    ) {
        positions::process_borrow(&env, &caller, account_id, &borrows, to);
    }
```

**File:** contracts/position-nft/src/test.rs (L135-158)
```rust
#[test]
fn approved_operator_can_transfer_and_approval_is_cleared() {
    // Pins stock OZ approval semantics (`approve`, `transfer_from`).
    let env = Env::default();
    env.mock_all_auths();
    let (_controller, client) = setup(&env);
    let owner = Address::generate(&env);
    let operator = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_id = client.mint(&owner);

    let live_until = env.ledger().sequence() + 1_000;
    client.approve(&owner, &operator, &token_id, &live_until);
    assert_eq!(client.get_approved(&token_id), Some(operator.clone()));

    // The approved operator, not the owner, authorizes the transfer.
    client.transfer_from(&operator, &owner, &recipient, &token_id);

    assert_eq!(client.owner_of(&token_id), recipient);
    assert_eq!(client.balance(&owner), 0u32);
    assert_eq!(client.balance(&recipient), 1u32);
    // Approval does not carry over to the new owner.
    assert_eq!(client.get_approved(&token_id), None);
}
```

**File:** contracts/controller/src/account.rs (L157-169)
```rust
/// Deletes all account entries and burns its NFT atomically. Account deletion
/// must use this path to preserve the NFT/account existence invariant.
pub(crate) fn remove_account_and_burn_nft(env: &Env, account_id: u64) {
    storage::remove_account_entry(env, account_id);
    let nft = storage::get_position_nft(env);
    nft_burn_call(env, &nft, account_id);
}

/// Deletes the account and burns its NFT when both position maps are empty.
pub(crate) fn cleanup_account_if_empty(env: &Env, account: &Account, account_id: u64) {
    if account.is_empty() {
        remove_account_and_burn_nft(env, account_id);
    }
```
