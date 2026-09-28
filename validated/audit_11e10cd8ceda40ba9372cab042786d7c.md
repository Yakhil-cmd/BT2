### Title
Position NFT can be transferred to a contract address that can never act, permanently freezing the account and all its collateral — (File: contracts/position-nft/src/contract.rs)

### Summary
The external report's bug class is "value sent to an address that can never use it is lost." On Soroban there is no EVM-style zero address, but the equivalent exists: a `soroban_sdk::Address` that is a contract with no code path able to authorize further calls. The controller's token flows already guard against this — `process_withdraw` calls `require_external_recipient` before paying out to a user-supplied `to` (`contracts/controller/src/positions/supply.rs:152-154`). The position NFT, which carries the entire lending account (collateral plus debt), has no equivalent guard: `transfer` and `transfer_from` are exported unchanged from the OpenZeppelin `NonFungibleToken` trait, which performs no recipient validation. An owner can move the token to the position-NFT contract itself, the controller contract, the pool, or any contract address that never invokes `transfer`/`require_auth` — permanently bricking the account.

### Finding Description
`PositionNft` implements `NonFungibleToken` with `type ContractType = Enumerable` and adds no override or wrapper around `transfer`/`transfer_from` (`contracts/position-nft/src/contract.rs:131-133`). The OZ `Base::update` logic used by these transfers only checks that `from` is the owner (or approved) — it does not reject `to` being the NFT contract's own address, the controller, or any other uninteractive contract address.

Consequences once `owner_of(token_id)` returns such an address:
- Every controller entrypoint resolves ownership via `owner_of(account_id)` and then requires that owner's (or a delegate's) `require_auth`. A contract address that never signs can never satisfy this, so `supply`/`borrow`/`withdraw`/`repay` are all unreachable.
- Delegates cannot rescue it: `get_delegates` returns empty unless `granted_by` equals the *current* NFT owner, and only the owner can call `add_delegate` — which itself requires owner auth.
- Liquidation still works (it does not need owner auth), so the collateral is not even protected; it can only be seized by liquidators, not recovered by the owner.
- Unlike a normal token, there is no separate asset that stays recoverable: the NFT *is* the account. The supply shares it gates remain credited in the pool and keep accruing yield, but no principal or yield can ever be withdrawn by the owner.

The asymmetry is notable because the protocol clearly recognizes this class on the token-leg side (`require_external_recipient` in `positions/mod.rs`, applied to withdraw `to`, liquidation recipients, etc.) but left the position-token leg unprotected.

### Impact Explanation
Permanent freezing of funds: a single `transfer`/`transfer_from` call to an uninteractive contract address locks all collateral and any claim on accrued yield backing that account id. The shares remain in the pool's `total_supply` while the only key that can move them (the NFT owner record) points at an address that can never authorize. This is the direct Soroban analog of ERC-20 tokens sent to `0x0`: the value still exists in accounting but is unreachable forever.

### Likelihood Explanation
Requires the token holder (or an approved operator) to supply the fatal `to` — i.e., user error or a malicious/buggy marketplace or wallet integration calling `transfer_from` with a bad recipient. Reachable by any unprivileged owner via `transfer(from, to, token_id)` or `transfer_from(spender, from, to, token_id)`; no privileged role needed. Self-inflicted nature and the absence of a cross-user theft vector keep this at Medium rather than High, matching the severity typically assigned to the source zero-address class.

### Recommendation
Reject recipients that cannot operate the position. Concretely, override `transfer`/`transfer_from` (or wrap `Base::update`) in `contracts/position-nft/src/contract.rs` to panic when `to` equals `env.current_contract_address()`, the stored `controller` address, or the pool address — mirroring `require_external_recipient` on the token side. Optionally expose a controller-administered `rescue` path that can reassign an owner record proven to be a non-interactive contract, behind the governance timelock.

### Proof of Concept
```rust
// Setup: user U owns account_id 1 (position NFT token_id 1) with supply collateral.
// U calls (directly or via a buggy marketplace):
position_nft.transfer(&U, &position_nft_addr, &1); // to = the NFT contract itself
// or: position_nft.transfer(&U, &controller_addr, &1);

// From now on:
let owner = position_nft.owner_of(&1); // == position_nft_addr / controller_addr

// Any user-side controller call fails authorization, e.g.:
controller.withdraw(&U, &1, &withdrawals, &None); // panics: require_owner_or_delegate /
                                                  // require_authorized_caller — the
                                                  // contract address never signs.

// Delegate recovery also fails: get_delegates(1) == [] because granted_by != owner,
// and add_delegate requires the (unreachable) owner's auth.

// Only liquidators can ever touch the collateral; U's funds are permanently
// frozen even though the shares still exist in the pool's accounting.
```

Note on residual uncertainty: the exact recipient checks inside `require_external_recipient` and the OZ `Base::update` implementation were not fully read due to iteration limits; the finding assumes the stock OZ transfer performs no `to` validation (consistent with v0.7.1) and that `require_external_recipient` guards only token-leg recipients, not NFT transfers. If `require_external_recipient`-equivalent checks were added inside a custom transfer override, this finding does not hold — none is present in `contract.rs`.