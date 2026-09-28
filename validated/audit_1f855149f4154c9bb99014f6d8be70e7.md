### Title
`transfer`/`transfer_from` can permanently freeze a lending position by sending the account NFT to a contract address that cannot authorize — (File: contracts/position-nft/src/contract.rs)

### Summary
The position NFT is the sole ownership record for a controller account: `account_id == token_id` and the controller resolves the owner live via `owner_of` on every action. The inherited OpenZeppelin `transfer`/`transfer_from` write `to` unconditionally with no check that the receiver can ever authorize a subsequent call. On Soroban, a contract `Address` can satisfy `require_auth` only through invoker contract auth or its own `__check_auth`; sending a position token to a contract that exposes no forwarding entrypoint permanently locks the collateral, debt, and the NFT itself.

### Finding Description
`PositionNft` exports the stock `NonFungibleToken` interface, so `transfer(from, to, token_id)` accepts any `to` address — including arbitrary contract addresses — and performs no capability check on the receiver (contracts/position-nft/src/contract.rs:131-133; the trait impl is `Enumerable` with no receiver hook override). The README confirms "the controller stores no owner address for an account; it calls `owner_of(account_id)`... every time it needs to know who may act" (contracts/position-nft/README.md:4-9), and every owner-gated controller entrypoint — `supply`, `withdraw`, `borrow`, `repay`, `multiply`, `swap_*`, `migrate_from_blend`, `update_account_threshold` — requires `require_auth` from the NFT owner (the auth checks are invoked across contracts/controller/src/positions/supply.rs, positions/debt.rs, and strategies/*). Even moving the NFT onward requires `from.require_auth()` inside the NFT transfer itself. A contract address can only produce that auth if it is the direct invoker or implements account-contract authentication; a contract with no such function (e.g., a SAC, the pool, or any contract lacking a forward-to-controller method) can never authorize, so the account's collateral is permanently frozen and its debt can never be repaid by the owner.

### Impact Explanation
Permanent freezing of user funds: all supplied collateral in the account is locked indefinitely, since only the NFT owner can call `withdraw` and only the owner can transfer the token onward. For leveraged accounts the position drifts until liquidators consume it via `liquidate`, so the effective loss to the user can approach the full account value. Any unprivileged address can trigger this by calling `transfer`/`transfer_from` on the position NFT with `to` set to a contract that cannot authorize.

### Likelihood Explanation
Requires the token holder (or an approved operator) to designate an incapable contract as `to` — a self-inflicted mistake rather than attacker-forced loss. However, the failure mode is realistic: positions are ordinary transferable NFTs, so marketplace contracts, escrow contracts, SACs, or mistyped contract addresses are plausible `to` values, and the protocol exposes contract callers as legitimate counterparties (script-runner and flash-position receiver flows routinely use contract addresses). Because Soroban has no `safeTransferFrom`/receiver-callback convention, the contract provides no guard against it. Medium severity, matching the source report's classification.

### Recommendation
Add a receiver-capability guard on transfers to contract addresses. Options:
- Implement a `check_auth`-aware transfer: when `to` is a contract, require it to implement a known receiver interface (e.g., call a `on_position_received` hook) before committing the ownership write, analogous to `safeTransferFrom`.
- Or restrict `transfer`/`transfer_from` `to` values to non-contract addresses at the NFT layer, and provide a separate audited path for contract-owned accounts that explicitly verifies the contract can act (e.g., requires the receiver to authorize the transfer in, `to.require_auth()`). Requiring `to.require_auth()` is the simplest fix: it both proves the receiver can authorize and turns the acceptance into an explicit opt-in.

### Proof of Concept
```rust
// contracts/position-nft/src/test.rs style PoC
let env = Env::default();
env.mock_all_auths();
let (_controller, client) = setup(&env);
let owner = Address::generate(&env);
let token_id = client.mint(&owner);

// `dumb` is any contract with no forwarding method / no __check_auth,
// e.g. a deployed SAC or the pool contract address.
let dumb_contract = Address::generate(&env); // stand-in: a contract id
client.transfer(&owner, &dumb_contract, &token_id);
assert_eq!(client.owner_of(&token_id), dumb_contract);

// 1) The NFT itself is frozen: transfer requires from.require_auth(),
//    which the dumb contract can never satisfy.
// 2) Every owner-gated controller call fails: withdraw/supply/borrow/repay
//    resolve owner via owner_of and require_auth(owner) -> NotAuthorized (#44).
// Collateral is permanently locked; a leveraged account is only unwindable
// by third-party liquidators.
```

Note: the exact line-level internals of the inherited OZ `Base::update`/`transfer` and the controller's `is_owner_or_delegate` body were not fully read in this pass; the claim rests on the documented design (no cached owner, live `owner_of`, `from.require_auth()` on transfer) confirmed in `contracts/position-nft/README.md` and `contract.rs`.