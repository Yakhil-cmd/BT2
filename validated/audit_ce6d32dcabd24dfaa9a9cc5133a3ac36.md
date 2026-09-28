### Title
Position NFT can be transferred to a contract that cannot authorize, permanently freezing the entire lending position - (File: contracts/position-nft/src/contract.rs)

### Summary
The `PositionNft` contract exports the stock OpenZeppelin `NonFungibleToken::transfer` / `transfer_from` implementation with no check that `to` is an address capable of producing authorization on Stellar (`require_auth` / `__check_auth`). Because a position NFT is the sole ownership record for a controller account (`account_id == token_id`), transferring it to a contract address that cannot authenticate permanently locks all collateral and control of the account.

### Finding Description
The controller stores no owner; every owner-gated verb (`supply`, `withdraw`, `borrow`, `repay`, `add_delegate`, etc.) resolves the live holder through `owner_of(token_id)` and requires that holder's authorization (see `contracts/position-nft/README.md`: "The controller stores no owner address for an account; it calls `owner_of(account_id)` on this contract every time it needs to know who may act on a position"). `PositionNft` implements `NonFungibleToken` with `type ContractType = Enumerable` and overrides only `token_uri`; `transfer` and `transfer_from` are the stock OZ exports, which move `Owner(token_id)` to any `Address` with no validation of the recipient [1](#0-0) . On Soroban there is no receiver callback, but the asymmetry is the same as the ERC-721 `transferFrom` bug class: a plain contract `Address` can be set as owner even though only addresses that can satisfy `require_auth()` (accounts, or contracts implementing `__check_auth`/exposing callable entrypoints for invoker auth) can ever act. A contract that merely holds the token and exposes no path to authorize `position_nft.transfer` or a controller call can never move it again.

The protocol already acknowledges the stranded-funds class elsewhere: `borrow`/`withdraw` reject the pool and controller as `to` recipients with `INVALID_FLASHLOAN_RECEIVER` because "the controller holds funds no balance-delta measurement can ever claim" [2](#0-1) . No equivalent guard exists on the NFT side for arbitrary contract recipients.

### Impact Explanation
Permanent freezing of funds: all collateral held by the account and the ability to repay, withdraw, delegate, or renew become unreachable. `renew_account`/permissionless `renew(token_id)` can still extend TTLs and liquidators can still act if the position goes underwater, but a solvent position's collateral is locked forever — the owner entry points at an address that can never authorize. Since the token also carries the debt, if the position later becomes liquidatable, collateral is seizable by liquidators but the residue still accrues to a dead owner.

### Likelihood Explanation
Any unprivileged holder can call `position_nft.transfer(from, to, token_id)` or `transfer_from` (owner/operator-approved) with `to` set to an arbitrary contract address — e.g., a smart wallet without a generic auth path, a multisig/DAO contract, an exchange custody contract, or the controller/pool itself. No privileged action, oracle state, or racing condition is needed; a single mistaken or poorly-informed transfer triggers it. This mirrors the original report's severity (Medium): it requires a user-level mistake but the loss is total and unrecoverable.

### Recommendation
In `PositionNft`, override `transfer` and `transfer_from` (or wrap `Base::update`) to reject `to` addresses that cannot act: at minimum reject the protocol's own contract addresses (controller, pools, the NFT itself) the same way `withdraw` rejects pool/controller recipients, and preferably reject contract addresses entirely unless they implement a known interface (e.g., require `to` to be a classic account, or expose a `safe_transfer` variant that calls a receiver hook/`__check_auth` probe). Document the residual risk for arbitrary contract recipients.

### Proof of Concept
```rust
// Env with standard two-asset market; ALICE holds account `id` with collateral.
let mut t = LendingTest::new().standard_two_asset().build();
t.supply(ALICE, "USDC", 10_000.0);
let id = t.account_id(ALICE);
let alice = t.get_or_create_user(ALICE);

// A contract with no entrypoint that can call position_nft.transfer
// and no __check_auth implementation.
let sink = t.env.register(SomeContractWithoutNftHandling, ());

// Stock OZ transfer accepts any Address; no receiver capability check.
position_nft_client.transfer(&alice, &sink, &u32::try_from(id).unwrap());
assert_eq!(position_nft_client.owner_of(&u32::try_from(id).unwrap()), sink);

// Every owner-gated controller verb now fails: `sink.require_auth()` inside
// try_account_owner cannot be satisfied by a contract lacking __check_auth.
let res = t.ctrl_client().try_withdraw(&sink, &id, &legs, &None);
// -> InvokeError / auth failure; collateral is frozen permanently.
// position_nft.transfer(&sink, ...) equally cannot be authorized.
```
Supporting code: `contracts/position-nft/src/contract.rs:131-173` (stock `NonFungibleToken`/`NonFungibleEnumerable` impls with no recipient validation), `contracts/position-nft/README.md` (owner-of-is-account-owner invariant).

### Citations

**File:** contracts/position-nft/src/contract.rs (L131-133)
```rust
#[contractimpl(contracttrait)]
impl NonFungibleToken for PositionNft {
    type ContractType = Enumerable;
```

**File:** tests/test-harness/tests/controller/recipient_is_protocol_contract.rs (L1-5)
```rust
//! GH-17. A borrow or withdraw addressed to the pool or the controller
//! strands the tokens: the pool debits cash without its balance moving, and
//! the controller holds funds no balance-delta measurement can ever claim.
//! Both recipients are rejected before any transfer, with the same error the
//! flash-position receiver check uses.
```
