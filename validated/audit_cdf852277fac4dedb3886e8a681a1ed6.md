### Title
Position NFT seller can frontrun a sale and drain the account's collateral before transfer - (File: contracts/position-nft/src/contract.rs)

### Summary
A lending account is exactly one transferable position NFT (`account_id == token_id`), and the controller resolves the acting owner live via `owner_of` on every owner-gated call [1](#0-0) . Because ownership moves only at the moment the NFT transfer executes, a seller who has listed a position NFT for sale retains full control of the account — including `withdraw` and `borrow` — until the buyer's purchase transaction executes. The seller can frontrun the sale with a `withdraw`/`borrow` that extracts the collateral the buyer thought they were acquiring, exactly the honeypot pattern of the Footium report.

### Finding Description
The controller stores no owner; it calls `owner_of(account_id)` live for authorization [2](#0-1) . `transfer`/`transfer_from` are stock OpenZeppelin NFT methods requiring only the holder's auth [3](#0-2) , and moving the token atomically moves collateral and debt [4](#0-3) . `controller::withdraw` is gated to the current NFT owner/delegate and only checks post-withdrawal solvency (LTV cover and HF >= 1, plus the min-borrow floor when debt remains) [5](#0-4) .

Attack path, reachable by a single unprivileged address:

1. Seller supplies attractive collateral into account `A` (e.g. via `supply`), and lists position NFT `A` on a marketplace or agrees an off-chain sale priced against the account's collateral.
2. Buyer's purchase transaction is observed before it executes.
3. Seller submits `controller::withdraw(caller=seller, account_id=A, withdrawals=[(asset, 0)], to=seller)` — amount `0` is the full-balance sentinel [6](#0-5)  — and/or `borrow` up to the HF boundary, draining the account's realizable value.
4. `position-nft::transfer`/marketplace `transfer_from` then executes and the buyer receives NFT `A` carrying little or no net collateral (empty account, or a debt-laden account at HF ~= 1 ready to be liquidated).

The protocol tests confirm the semantics: the old owner loses authority only *after* the transfer lands (`old_owner_is_rejected_after_transfer`) [7](#0-6) , and ownership is read live so a transfer mid-sequence revokes authority for the next leg [8](#0-7) . Nothing binds the account's financial state to the sale: no timelock, no collateral snapshot, no escrow invariant.

### Impact Explanation
Theft of user funds: the buyer pays a price agreed against the account's collateral and receives a drained position. For an account with no debt the seller extracts 100% of supplied collateral; for a levered account the seller can `borrow`/`withdraw` down to the HF = 1 boundary, leaving the buyer an account that is immediately liquidation-bait. The loss equals the purchase price minus the residual (possibly negative, since debt also transfers) position value.

### Likelihood Explanation
Requires only that positions are sold OTC or through any marketplace/aggregator that does not atomically verify post-sale collateral — the NFT is designed to be moved by "wallets, indexers, and marketplaces with no protocol-specific tooling" [9](#0-8) . The seller needs no privilege and no cooperation: `withdraw` is the standard owner path, and the frontrun is a single extra transaction. This is the same trust gap as the Footium issue — the valuable state attached to the token is mutable by the seller up to the instant of transfer — so it materializes wherever position NFTs are traded on value-bearing accounts. Severity: Medium (theft bounded by the sale price; requires a victim buying a position NFT rather than attacking arbitrary users).

### Recommendation
Mitigation is mostly at the settlement layer, but protocol-side options exist:

- Document explicitly that buying a position NFT is unsafe unless the sale atomically re-verifies account state; provide a view such as `get_health_factor`/`get_account_positions` plus a bundled "buy-with-checks" entrypoint (e.g. an escrow contract that asserts collateral/debt maps and HF in the same transaction that calls `transfer_from`).
- Optionally support a seller-initiated lock/escrow mode on the NFT (or a controller-side `transfer_with_min_collateral` guard) so a listing can freeze `withdraw`/`borrow`/strategy verbs until the sale completes or is cancelled — the analog of the recommended ERC-721 timelock.
- Buyers can partially self-protect today by purchasing only through a contract that performs `owner_of` + position checks and `transfer_from` atomically.

### Proof of Concept
Conceptual sequence against deployed contracts:

```text
// Setup
controller.supply(seller, 0, spoke, [(key(USDC), 1_000_000e7)]);  // creates account A, mints NFT A to seller
// marketplace: seller approves marketplace contract for token A; buyer submits buy

// Frontrun (seller, still owner_of(A)):
controller.withdraw(seller, A, [(key(USDC), 0)], seller);        // 0 = full balance
// optional: controller.borrow(seller, A, [(key(XLM), max)], seller) to HF ≈ 1

// Buyer's tx executes:
position_nft.transfer_from(marketplace, seller, buyer, A);       // buyer now owns drained A
// controller.get_account_positions(A) -> empty/near-zero collateral
// buyer's payment is unrecoverable
```

Every step uses only documented unprivileged entrypoints (`supply`, `withdraw`, `borrow`, `transfer_from`) and the live `owner_of` authorization model.

### Citations

**File:** contracts/position-nft/README.md (L3-9)
```markdown
Ownership record for lending accounts. Every controller account is exactly one
token in this collection, and the token id is the account id. The controller
stores no owner address for an account; it calls `owner_of(account_id)` on this
contract every time it needs to know who may act on a position. A lending
position is therefore an ordinary transferable non-fungible token (NFT), so
wallets, indexers, and marketplaces can read and move it with no
protocol-specific tooling.
```

**File:** contracts/position-nft/README.md (L29-41)
```markdown
| any owner check (`try_account_owner`) | `owner_of(token_id)` | Live lookup; the owner is never cached in controller storage |
| `renew_account` | `renew(token_id)` | Lifts the token's `Owner` entry and its holder's `Balance` entry to the protocol's per-user window |
| `upgrade_position_nft` | `upgrade(hash)` | Owner-gated Wasm upgrade |

`account_id == token_id`. The controller widens `u32` to `u64` on mint and
narrows back with `u32::try_from` on every other call; an id above `u32::MAX`
can never have been minted, so it resolves to `AccountNotFound`. Account id `0`
is the controller's "create a new account" sentinel, so the constructor
consumes token id 0 and the first real position is id 1.

Transferring the token transfers the whole position. Nothing in the controller
changes on transfer: the next controller call resolves the new holder and
accepts it. Collateral and debt both move with the token.
```

**File:** contracts/position-nft/README.md (L62-64)
```markdown
| `transfer` | `fn transfer(e: &Env, from: Address, to: Address, token_id: u32)` | `from` must authorize | Moves the position to `to` |
| `transfer_from` | `fn transfer_from(e: &Env, spender: Address, from: Address, to: Address, token_id: u32)` | `spender` must authorize and be `from`, approved for the token, or an operator for `from` | Moves the position to `to` |
| `approve` | `fn approve(e: &Env, approver: Address, approved: Address, token_id: u32, live_until_ledger: u32)` | `approver` must authorize and be the owner or an operator | Grants `approved` the right to move that one position until `live_until_ledger` |
```

**File:** docs/reference/endpoints.md (L51-51)
```markdown
Ordinary payment lists sum duplicate markets in first-appearance order and reject negative amounts. `supply`, `borrow` and `repay` reject zero. In `withdraw`, zero means the full balance and overrides positive amounts for the same market. Flash-position declaration lists reject duplicates.
```

**File:** docs/reference/endpoints.md (L55-55)
```markdown
After pool accounting, `borrow`, `withdraw` and the six account strategies require LTV-weighted collateral to cover debt and health factor (HF) to be at least 1. If debt remains, LTV-weighted collateral must also meet the minimum-borrow floor. Ordinary `supply` and `repay` skip these checks; repayment loads debt positions only. Liquidation uses separate admission and sizing rules. See [formulas](formulas.md) for the calculations.
```

**File:** tests/test-harness/tests/controller/position_nft.rs (L67-79)
```rust
#[test]
fn old_owner_is_rejected_after_transfer() {
    let mut t = LendingTest::new().with_market(usdc_preset()).build();
    t.supply(ALICE, "USDC", 1_000.0);
    let account_id = t.account_id(ALICE);
    t.nft_transfer(ALICE, BOB, account_id);

    // ALICE's registered account id still points at the transferred account;
    // an owner-gated withdraw must now fail NotAuthorized.
    let raw = f64_to_i128(100.0, t.resolve_market("USDC").decimals);
    let result = t.try_withdraw_raw(ALICE, "USDC", raw);
    assert_contract_error(result, errors::NOT_AUTHORIZED);
}
```

**File:** tests/test-harness/tests/composition/nft_transfer_between_legs.rs (L1-30)
```rust
//! GH-11. Ownership is read live from the NFT, so a transfer between two legs
//! of one script revokes the runner's authority on the next leg.

use crate::helpers::{liquidate_op, supply_op, withdraw_op};
use common::types::SeizeMode;
use script_runner::{NftTransferOp, Op, LAST_CREATED};
use soroban_sdk::{vec, Vec};
use test_harness::{assert_contract_error, errors, usd, LendingTest, ALICE, BOB};

const U: i128 = 10_000_000;

#[test]
fn a_withdraw_after_an_in_script_transfer_is_rejected() {
    let mut t = LendingTest::new().standard_two_asset_dust_disabled();
    let runner = t.deploy_script_runner();
    t.fund_runner(&runner, "USDC", 1_000 * U);
    let bob = t.get_or_create_user(BOB);
    let ops: Vec<Op> = vec![
        &t.env,
        supply_op(&t, 0, "USDC", 1_000 * U),
        Op::NftTransfer(NftTransferOp {
            to: bob,
            token_id: LAST_CREATED,
        }),
        withdraw_op(&t, LAST_CREATED, "USDC", 1, None),
    ];
    assert_contract_error(
        t.run_script(&runner, &ops).map(|_| ()),
        errors::NOT_AUTHORIZED,
    );
```
