### Title
Front-running of permissionless `initialize()` to seize `pool_creator` role and DoS the intended pool deployer - (File: `programs/cp-swap/src/instructions/initialize.rs`)

### Summary
`initialize()` derives the pool's identity (`pool_state` PDA) purely from `(amm_config, token_0_mint, token_1_mint)` and lets the caller become `pool_creator` with no restriction on who may call it. Because the mint-pair/config tuple is public before the transaction lands (visible in the mempool), an attacker can front-run a legitimate user's `initialize()` call with the same mint pair and config, race to create the deterministic pool PDA first, and both steal the `pool_creator` fee-collection rights and permanently deny the original submitter's transaction, which fails atomically because the PDA account is no longer owned by the System Program.

### Finding Description
The `pool_state` PDA is derived deterministically from `amm_config`, `token_0_mint`, and `token_1_mint`: [1](#0-0) . `create_pool()` computes this same expected PDA and only allows a different account address if it is separately signer-provided ("random" pool); otherwise it must match the deterministic PDA: [2](#0-1) . The account creation step in `create_pool()` first requires the target account be owned by the System Program: [3](#0-2) .

`initialize()`'s `creator` field is any `Signer` — "Address paying to create the pool. Can be anyone" — with no allow-list or permission check gating who can call it: [4](#0-3) . The caller who successfully lands this instruction is recorded as the pool's `pool_creator` via `pool_state.initialize(...)`: [5](#0-4) . That `pool_creator` field is later the sole authority permitted to withdraw the pool's `creator_fees_token_0/1` in `collect_creator_fee`, constrained via `address = pool_state.load()?.pool_creator`: [6](#0-5) .

This is directly analogous to the referenced Yield Cauldron `vaultID` front-running bug: there, the user-chosen `vaultID` was the contested identifier that an attacker could front-run in the mempool to seize ownership and DoS the original submitter's transaction. Here, the contested identifier is the deterministic `(amm_config, token_0_mint, token_1_mint)` tuple used to derive `pool_state`. Anyone can observe a pending `initialize()` transaction for a not-yet-existing mint pair in the mempool, extract the exact `token_0_mint`/`token_1_mint`/`amm_config` triple (all public inputs, not secrets), and submit their own `initialize()` call for that exact triple with higher priority fee. The attacker's transaction lands first, creates the pool PDA, and becomes `pool_creator`. The original victim's transaction then fails at the `pool_account_info.owner != &system_program::ID` check in `create_pool()` because the account is now owned by the cp-swap program, reverting the victim's entire transaction (including their intended initial liquidity deposit).

### Impact Explanation
Because only one pool PDA can ever exist for a given `(amm_config, token_0_mint, token_1_mint)` triple, this griefing is permanent and not merely a timing nuisance: the legitimate/original deployer can never create "their" canonical pool for that pair under that config again — the identity is now permanently owned by the attacker. The attacker additionally acquires exclusive, unauthorized rights to collect any accrued `pool_creator` fees for that pool going forward (a real, ongoing financial benefit taken from the rightful pool deployer, who intended to earn creator fees from a pool they funded/initialized). This satisfies "unauthorized privileged effect" (illegitimate acquisition of the `pool_creator` role and its fee-collection rights) combined with denial of the legitimate user's ability to ever deploy that specific canonical pool.

### Likelihood Explanation
Likelihood is low-to-moderate: it requires an attacker to actively monitor the mempool for `initialize()` transactions and win a priority-fee race, gaining nothing directly except the ability to later collect creator fees on a pool they didn't fund with meaningful liquidity (they can initialize with minimal `init_amount_0`/`init_amount_1`). The attack is cheap (attacker pays only pool-creation costs) and repeatable against any new pool launch that uses default (non-"random") pool derivation, making it attractive against valuable upcoming pool launches (e.g., anticipated new token listings) rather than a broad, indiscriminate threat.

### Recommendation
Consider one or more of:
- Require the `initialize()` caller to be the same account that will be recorded as `pool_creator`, and additionally support/encourage the "random" pool_state signer path (already present in the code, see `random_pool_id` in `client/src/instructions/amm_instructions.rs`) as the default so pool identity is not derivable/front-runnable ahead of time.
- Add a commit-reveal or a permit-style signature scheme binding a specific deployer to a specific mint pair before the deterministic PDA is created, analogous to the Cauldron fix of moving `vaultID` assignment out of user control.
- Alternatively, decouple `pool_creator` fee rights from "whoever successfully lands the `initialize()` transaction" so front-running the PDA creation confers no financial benefit (e.g., tie creator-fee eligibility to `amm_config`-level allow-listing as already partially done in `initialize_with_permission` via the `Permission` PDA at `programs/cp-swap/src/instructions/initialize_with_permission.rs` lines 153-161).

### Proof of Concept
1. Alice constructs an `initialize()` transaction for a new token pair `(mintA, mintB)` under `amm_config` index 0, intending to be `pool_creator` and later collect creator fees.
2. Alice broadcasts the transaction; it sits in the mempool, exposing `mintA`, `mintB`, and `amm_config` as plaintext instruction data/accounts.
3. Eve observes the pending transaction, extracts `(amm_config, mintA, mintB)`, and independently derives the same `pool_state` PDA using the same seeds as `create_pool()` (`programs/cp-swap/src/instructions/initialize.rs:376-384`).
4. Eve submits her own `initialize()` call for the identical `(amm_config, mintA, mintB)` triple with a higher priority fee (and minimal `init_amount_0/1`), landing before Alice's transaction.
5. Eve's transaction succeeds: `create_pool()` sees `pool_account_info.owner == system_program::ID` (fresh account), creates the PDA, and `pool_state.initialize(...)` records Eve as `pool_creator`.
6. Alice's transaction now executes against the same PDA address; `create_pool()`'s check `pool_account_info.owner != &system_program::ID` fails because the account is now owned by the cp-swap program, and the whole transaction reverts with `ErrorCode::NotApproved`.
7. Alice can never create the canonical pool for `(amm_config, mintA, mintB)` again; Eve permanently holds `pool_creator` and can call `collect_creator_fee`/`collect_creator_fee_permissionless` to claim any future creator fees on that pool.

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-25)
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

**File:** programs/cp-swap/src/instructions/initialize.rs (L344-359)
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
        CreatorFeeOn::BothToken,
        false,
    );
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L372-388)
```rust
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
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L10-13)
```rust
pub struct CollectCreatorFee<'info> {
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,
```
