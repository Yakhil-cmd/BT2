## Title
`InitializeWithPermission.creator` can be set to the zero address, permanently freezing pool-creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
The pattern flagged in the external report ("a fee/recipient address parameter is never checked against `address(0)`") is fixed for `AmmConfig.protocol_owner`/`fund_owner` in `update_config.rs`, which explicitly calls `require_keys_neq!(new_owner, Pubkey::default())` and `require_keys_neq!(new_fund_owner, Pubkey::default())`. However, the same class of bug is still present, unfixed, on the `creator` account of the permissioned pool-creation instruction, which becomes the immutable `pool_creator` fee recipient for the life of the pool.

### Finding Description
`InitializeWithPermission` declares:
```rust
/// CHECK: creator of pool
pub creator: UncheckedAccount<'info>,
``` [1](#0-0) 

`creator` is an `UncheckedAccount` with no `constraint`, no signer requirement, and no zero-address check — unlike the fixed setters in `update_config.rs` that use `require_keys_neq!(new_owner, Pubkey::default())`. The value is passed straight into `pool_state.initialize(...)` as `pool_creator`:
```rust
pool_state.initialize(
    ctx.bumps.authority,
    liquidity,
    open_time,
    ctx.accounts.creator.key(),
    ...
``` [2](#0-1) 

and stored permanently in `PoolState.pool_creator`:
```rust
self.pool_creator = pool_creator.key();
``` [3](#0-2) 

`pool_creator` is never validated again and is the sole authority accepted for creator-fee collection:
```rust
#[account(mut, address = pool_state.load()?.pool_creator)]
pub creator: Signer<'info>,
``` [4](#0-3) 

and for the permissionless variant, which also builds an ATA using `creator` as authority without any zero check:
```rust
#[account(address = pool_state.load()?.pool_creator)]
pub creator: UncheckedAccount<'info>,
...
associated_token::authority = creator,
``` [5](#0-4) 

No zero-address guard exists anywhere on the `creator` parameter path; a `grep` for `Pubkey::default` across the codebase shows it is only checked in `update_config.rs` and `states/oracle.rs`, confirming the omission for pool creation.

### Impact Explanation
Anyone calling `initialize_with_permission` (any account holding a valid `Permission` PDA for their own key, an unprivileged, permissionless-to-reach role in this scope) can pass `Pubkey::default()` (the Solana system-owned all-zero pubkey, with no known private key) as `creator`. This is recorded immutably as `PoolState.pool_creator`. All subsequent creator fees accrued by swaps against this pool accumulate in `pool_state.creator_fees_token_0/1` but can never be collected: `collect_creator_fee` requires a `Signer` equal to `pool_creator` (impossible, since no key controls `address(0)`), and `collect_creator_fee_permissionless` would try to mint tokens/ATA to the zero address, permanently locking those fees inside the pool vaults. This is a permanent freezing of protocol/user-attributable funds (the creator-fee share of every swap), satisfying the "permanent freezing of funds" impact bar.

### Likelihood Explanation
Reaching `initialize_with_permission` requires only a valid `Permission` account (seeded by the caller's own pubkey) — this is the intended entry point for permissioned pool creation and is reachable in a single transaction with attacker-chosen `creator` account data. No other check on the codebase rejects `Pubkey::default()` for this field, so the likelihood of triggering this (accidentally or maliciously) is high, and it is directly analogous to the exact bug class described in the external report (a fee-recipient/owner-style address field is settable to `address(0)` without reverting).

### Recommendation
Add an explicit check in `InitializeWithPermission` (or in `initialize_with_permission`) rejecting `creator.key() == Pubkey::default()`, mirroring the `require_keys_neq!(new_owner, Pubkey::default())` guard already used in `update_config.rs` for `protocol_owner`/`fund_owner`.

### Proof of Concept
1. Attacker obtains/creates a `Permission` PDA for their own `payer` key via `create_permission_pda` (or is otherwise entitled to call the permissioned path).
2. Attacker calls `initialize_with_permission`, supplying `creator = Pubkey::default()` (the all-zero system pubkey) as the `creator` account — no constraint rejects this.
3. `pool_state.initialize(...)` stores `pool_creator = Pubkey::default()` permanently in the new `PoolState`.
4. As swaps occur against the pool, `update_fees` accrues `creator_fees_token_0`/`creator_fees_token_1` normally.
5. Any attempt to call `collect_creator_fee` fails because no wallet can sign as `address(0)`; `collect_creator_fee_permissionless` cannot meaningfully deliver funds to `address(0)` either. The accrued creator fees remain stuck in `token_0_vault`/`token_1_vault` forever.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L26-27)
```rust
    /// CHECK: creator of pool
    pub creator: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L357-372)
```rust
    pool_state.initialize(
        ctx.bumps.authority,
        liquidity,
        open_time,
        ctx.accounts.creator.key(),
        ctx.accounts.amm_config.key(),
        ctx.accounts.token_0_vault.key(),
        ctx.accounts.token_1_vault.key(),
        &ctx.accounts.token_0_mint,
        &ctx.accounts.token_1_mint,
        ctx.accounts.lp_mint.key(),
        ctx.accounts.lp_mint.decimals,
        ctx.accounts.observation_state.key(),
        creator_fee_on,
        true,
    );
```

**File:** programs/cp-swap/src/states/pool.rs (L151-152)
```rust
        self.amm_config = amm_config.key();
        self.pool_creator = pool_creator.key();
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L11-13)
```rust
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L17-20)
```rust
    /// The pool creator that receives the collected creator fees
    /// CHECK: the address is constrained to the `pool_creator` recorded in `pool_state`
    #[account(address = pool_state.load()?.pool_creator)]
    pub creator: UncheckedAccount<'info>,
```
