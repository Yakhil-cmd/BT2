This confirms the analog. The `pool_state` PDA for `initialize` is fully deterministic — derived only from `[POOL_SEED, amm_config, token_0_mint, token_1_mint]` [1](#0-0) , and the `creator` signer is an arbitrary, unprivileged, attacker-controlled account whose key is permanently written into `pool_state.pool_creator` [2](#0-1) . That `pool_creator` field is later trusted as the sole authority allowed to withdraw accumulated creator fees via `CollectCreatorFee`'s `address = pool_state.load()?.pool_creator` constraint [3](#0-2) . This is a direct analog to the `PerpOwnable.transferPerpOwner` bug class: a single, front-runnable, unauthenticated call that permanently assigns a privileged role tied to an on-chain resource.

### Title
Permanent theft of pool-creator fee rights via front-running the unauthenticated `initialize` instruction - (File: programs/cp-swap/src/instructions/initialize.rs)

### Summary
The `initialize` instruction creates a new CP-swap pool for a given `(amm_config, token_0_mint, token_1_mint)` triple and writes the calling `creator` signer's pubkey into `PoolState.pool_creator`, an address that is later granted permanent, exclusive rights to withdraw accumulated creator-fee earnings. Because the pool's PDA address is fully deterministic and the `creator` account is an arbitrary unprivileged signer with no allow-list or commit-reveal protection, an attacker monitoring the mempool can front-run a legitimate deployer's `initialize` transaction with their own `creator` key (and their own choice of initial price ratio / fee model), permanently capturing the pool-creator role for that token pair before the legitimate deployer's account (a system-owned, one-time-writable PDA) can ever be initialized.

### Finding Description
`create_pool` derives the pool PDA solely from `POOL_SEED`, `amm_config`, `token_0_mint`, and `token_1_mint` [1](#0-0) , and allocates the account via `create_or_allocate_account`, which will fail if the account already exists/is owned by the program. Since Solana account creation is atomic within a landed transaction, and mempool ordering can be manipulated with priority fees, any unprivileged party who observes a pending `initialize` transaction targeting a specific `(config, token0, token1)` pair can submit a competing transaction with a higher priority fee that creates the *same* PDA first, using themselves as the `creator` signer [4](#0-3) . Once landed, `pool_state.initialize(...)` permanently records the attacker's key as `ctx.accounts.creator.key()` in `PoolState.pool_creator` [2](#0-1) , and the legitimate deployer's original transaction reverts because the PDA is no longer system-owned/uninitialized. The `pool_creator` field is subsequently the sole trust anchor for `CollectCreatorFee`, which requires `creator.address == pool_state.load()?.pool_creator` [3](#0-2)  before releasing `creator_fees_token_0`/`creator_fees_token_1` accumulated in the vaults [5](#0-4) . There is no mechanism to transfer or reclaim `pool_creator` after initialization, so this capture is permanent and irreversible for the life of the pool — precisely analogous to the `PerpOwnable.transferPerpOwner` front-run described in the report, where a one-shot unauthenticated ownership assignment can be hijacked by any observer of the mempool.

### Impact Explanation
Once an attacker's key is embedded as `pool_creator`, they permanently and exclusively control withdrawal of all accumulated creator fees for that pool for as long as it exists, redirecting future creator-fee revenue away from the legitimate project/token pair deployer to the attacker with no recourse — meeting the "unauthorized privileged effect" / theft-of-funds bar, since creator fees continuously accrue from real trader swap activity and are only withdrawable by whoever holds `pool_creator`. This can be repeated for every new token pair a project attempts to launch, effectively permanently locking legitimate creators out of fee revenue for their own pools.

### Likelihood Explanation
The attack requires only observing a pending `initialize` transaction in the mempool (the token mints and `amm_config` are visible in the transaction) and resubmitting an equivalent instruction with a higher priority fee, using the attacker's own `creator` signer and creator-fee-account settings — no privileged role, special build feature, or off-chain component is needed. This is straightforward, low-cost, and directly reachable from a single attacker-submitted transaction, matching the "Low difficulty" rating given to the analogous EVM finding.

### Recommendation
Decouple pool creation from `pool_creator` assignment: require the `initialize`/`initialize_with_permission` instructions to authenticate the intended creator through a value that cannot be substituted by an unrelated front-runner (e.g., derive/validate the creator PDA relationship from a value committed by the legitimate deployer beforehand, or bind pool creation permission to `Permission` PDAs the way `initialize_with_permission` already does for permissioned pools, rather than allowing an arbitrary unauthenticated `creator` signer through the permissionless `initialize` path). At minimum, document that `initialize` is inherently front-runnable and that `pool_creator` assignment races the mempool, and provide a governance-controlled path to reassign or dispute a hijacked `pool_creator`.

### Proof of Concept
1. Alice constructs and broadcasts an `initialize` transaction for `token_0_mint`/`token_1_mint` under `amm_config` X, with herself as `creator`, expecting to become `pool_state.pool_creator`.
2. Eve observes this pending transaction in the mempool, sees the `(amm_config, token_0_mint, token_1_mint)` tuple (all public), and constructs an identical `initialize` call using her own `creator` keypair, `creator_token_0`/`creator_token_1` accounts, and arbitrary `init_amount_0`/`init_amount_1` ratio, submitted with a higher priority fee.
3. Eve's transaction lands first; `create_pool` successfully allocates the deterministic pool PDA [6](#0-5) , and `pool_state.initialize(...)` records Eve's key as `pool_creator`.
4. Alice's transaction now fails on-chain because the pool PDA is already initialized (owned by the program, not `system_program`), per the `pool_account_info.owner != &system_program::ID` check [7](#0-6) .
5. From then on, only Eve can call `collect_creator_fee` to withdraw accumulated `creator_fees_token_0`/`creator_fees_token_1` from every swap that trades this pair, permanently and irrevocably diverting creator-fee revenue from Alice to Eve.

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-24)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
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

**File:** programs/cp-swap/src/instructions/initialize.rs (L364-409)
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

    Ok(AccountLoad::<PoolState>::try_from_unchecked(
        &crate::id(),
        &pool_account_info,
    )?)
}
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L10-13)
```rust
pub struct CollectCreatorFee<'info> {
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-122)
```rust
pub fn collect_creator_fee(ctx: Context<CollectCreatorFee>) -> Result<()> {
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    let creator_fees_token_0 = pool_state.creator_fees_token_0;
    let creator_fees_token_1 = pool_state.creator_fees_token_1;
    if creator_fees_token_0 == 0 && creator_fees_token_1 == 0 {
        return err!(ErrorCode::NoFeeCollect);
    }

    let signer_seeds: &[&[u8]] = &[crate::AUTH_SEED.as_bytes(), &[ctx.bumps.authority]];

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.creator_token_0.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        ctx.accounts.token_0_program.to_account_info(),
        creator_fees_token_0,
        ctx.accounts.vault_0_mint.decimals,
        &[signer_seeds],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.creator_token_1.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        ctx.accounts.token_1_program.to_account_info(),
        creator_fees_token_1,
        ctx.accounts.vault_1_mint.decimals,
        &[signer_seeds],
    )?;

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```
