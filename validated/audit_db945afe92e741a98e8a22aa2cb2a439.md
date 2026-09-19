### Title
Permissionless pool creation allows duplicate pools for the same token pair/config, enabling pool spoofing - ([File: programs/cp-swap/src/instructions/initialize.rs])

### Summary
`initialize()` and `initialize_with_permission()` are meant to create one canonical pool per `(amm_config, token_0_mint, token_1_mint)` tuple, whose uniqueness is normally guaranteed by deriving `pool_state` as a PDA from those exact seeds. However, the underlying `create_pool()` helper allows `pool_state` to be *any* system-owned account as long as it is a transaction signer, bypassing the canonical PDA. This lets any unprivileged caller create an unlimited number of duplicate pools for the same token pair and config, each with independent vaults, LP mint, and reserves — mirroring the reported "no duplicate check" bug class from the `Dispatcher.add()` report.

### Finding Description
The `Initialize` accounts struct documents the intended pool address as the PDA derived from `POOL_SEED`, `amm_config`, `token_0_mint`, `token_1_mint`, but also allows "Or random account: must be signed by cli": [1](#0-0) 

The actual enforcement is in `create_pool()`, which only requires the account to be system-owned, and if it is not the expected PDA, merely requires it to be a signer — it never rejects the call if a pool for that same `(amm_config, token_0_mint, token_1_mint)` already exists at the canonical PDA: [2](#0-1) 

Because `creator` is an arbitrary signer ("Address paying to create the pool. Can be anyone"), any user can repeatedly call `initialize` (or `initialize_with_permission`) supplying a fresh keypair as `pool_state` instead of the canonical PDA, and the instruction will happily create a brand-new, fully independent pool (its own vaults, LP mint, observation state, reserves) for a token pair that already has a canonical pool: [3](#0-2) 

There is no registry or check ensuring only one pool per `(amm_config, token_0, token_1)` combination can exist; uniqueness is only "soft-enforced" for the PDA path, and completely bypassed for the random-signer path.

### Impact Explanation
Duplicate pools for the same token pair/config fragment liquidity and, more importantly, enable pool spoofing: an attacker can create a look-alike pool (same token_0/token_1 mints, same amm_config) with skewed/manipulated reserves and induce integrators, off-chain indexers, or unsuspecting users (who locate pools by scanning `PoolState` fields rather than re-deriving the canonical PDA) into swapping or depositing into the attacker-controlled duplicate. Because the attacker fully controls the fake pool's initial reserves and can be the first depositor, they can extract value from users who interact with the wrong pool believing it to be canonical, and legitimate LPs are misled about the "true" pool for a pair. This aligns with the Medium-severity impact described in the source report (confusion/errors in pool identification leading to interacting with the wrong pool).

### Likelihood Explanation
Reachable in a single permissionless transaction: any signer can call `initialize` with a fresh, self-generated keypair as `pool_state` (as explicitly supported by the client helper's `random_pool_id` parameter), no special privileges or state are required beyond normal pool-creation prerequisites (valid mints, `amm_config.disable_create_pool == false`). [4](#0-3) 

### Recommendation
Before allowing pool creation via the non-PDA path, verify that no canonical pool already exists for the given `(amm_config, token_0_mint, token_1_mint)` (e.g., check that the PDA account is uninitialized/empty), or restrict the random-`pool_state` path to a privileged/admin signer intended for migration tooling only, rather than any arbitrary user. Alternatively, remove the random-account bypass entirely and always require `pool_state` to be the canonical PDA.

### Proof of Concept
1. Attacker (or anyone) calls `initialize` for `token_0_mint`/`token_1_mint` under `amm_config` using the canonical PDA — a legitimate pool `P1` is created.
2. Attacker calls `initialize` again for the identical `token_0_mint`/`token_1_mint`/`amm_config`, but this time supplies a freshly generated keypair `K` as `pool_state` and signs with it (satisfying `require_eq!(pool_account_info.is_signer, true)` in `create_pool`).
3. `create_pool` allocates a new `PoolState` at `K`, distinct from the canonical PDA `P1`, with its own vaults/LP mint/reserves — a duplicate pool `P2` for the same pair now exists.
4. Attacker seeds `P2` with minimal/skewed liquidity and promotes it (e.g., via a fake frontend, or by publishing `P2`'s address) as "the" pool for this token pair, to swap/deposit victims into `P2` instead of `P1`, capturing value via unfavorable pricing or as sole LP.

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-24)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L39-50)
```rust
    /// CHECK: Initialize an account to store the pool state
    /// PDA account:
    /// seeds = [
    ///     POOL_SEED.as_bytes(),
    ///     amm_config.key().as_ref(),
    ///     token_0_mint.key().as_ref(),
    ///     token_1_mint.key().as_ref(),
    /// ],
    ///
    /// Or random account: must be signed by cli
    #[account(mut)]
    pub pool_state: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L364-403)
```rust
pub fn create_pool<'info>(
    payer: &AccountInfo<'info>,
    pool_account_info: &AccountInfo<'info>,
    amm_config: &AccountInfo<'info>,
    token_0_mint: &AccountInfo<'info>,
    token_1_mint: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
) -> Result<AccountLoad<'info, PoolState>> {
    if pool_account_info.owner != &system_program::ID {
        return err!(ErrorCode::NotApproved);
    }

    let (expect_pda_address, bump) = Pubkey::find_program_address(
        &[
            POOL_SEED.as_bytes(),
            amm_config.key().as_ref(),
            token_0_mint.key().as_ref(),
            token_1_mint.key().as_ref(),
        ],
        &crate::id(),
    );

    if pool_account_info.key() != expect_pda_address {
        require_eq!(pool_account_info.is_signer, true);
    }

    token::create_or_allocate_account(
        &crate::id(),
        payer.to_account_info(),
        system_program.to_account_info(),
        pool_account_info.clone(),
        &[
            POOL_SEED.as_bytes(),
            amm_config.key().as_ref(),
            token_0_mint.key().as_ref(),
            token_1_mint.key().as_ref(),
            &[bump],
        ],
        PoolState::LEN,
    )?;
```

**File:** client/src/instructions/amm_instructions.rs (L46-59)
```rust
    let pool_account_key = if random_pool_id.is_some() {
        random_pool_id.unwrap()
    } else {
        Pubkey::find_program_address(
            &[
                POOL_SEED.as_bytes(),
                amm_config_key.to_bytes().as_ref(),
                token_0_mint.to_bytes().as_ref(),
                token_1_mint.to_bytes().as_ref(),
            ],
            &program.id(),
        )
        .0
    };
```
