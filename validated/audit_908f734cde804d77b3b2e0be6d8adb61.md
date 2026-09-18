`enable_creator_fee` is only set once, in `PoolState::initialize`, and there is no admin/creator instruction found that toggles it afterward — it is fixed for the lifetime of the pool. [1](#0-0) 

### Title
Permissionless `initialize` front-runs `initialize_with_permission`, permanently disabling creator fees for a pool - (File: `programs/cp-swap/src/instructions/initialize.rs`, `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
Both the fully-permissionless `initialize` instruction and the permissioned `initialize_with_permission` instruction derive the exact same canonical `pool_state` PDA from `[POOL_SEED, amm_config, token_0_mint, token_1_mint]`. `initialize` hardcodes `enable_creator_fee = false` while `initialize_with_permission` sets `enable_creator_fee = true` and lets the caller choose `creator_fee_on`. Since anyone can call `initialize` for any `(amm_config, token_0_mint, token_1_mint)` triple, an attacker can pre-create the canonical pool before the intended permissioned creator does, permanently locking the pool into "creator fee disabled," analogous to the reported Launchpad pair pre-creation issue.

### Finding Description
`create_pool` (shared by both instructions) allocates the pool PDA using seeds `[POOL_SEED, amm_config, token_0_mint, token_1_mint]`, and fails with `NotApproved`/an "already in use" condition if that PDA is already initialized: [2](#0-1) 

The unprivileged `initialize` instruction calls `pool_state.initialize(...)` with `CreatorFeeOn::BothToken` and `enable_creator_fee = false` hardcoded, regardless of caller intent: [3](#0-2) 

The permissioned `initialize_with_permission` instruction (gated by a `Permission` PDA tied to the payer) instead sets `enable_creator_fee = true` and a caller-supplied `creator_fee_on`: [4](#0-3) 

Because both instructions target the identical pool PDA for a given `(amm_config, token_0_mint, token_1_mint)` triple, and there is no restriction preventing a non-permissioned account from calling `initialize` first, an attacker can "squat" on that PDA. Once `initialize` succeeds, `getPair`-equivalent state (the pool account itself, now owned by the program) is locked, and the intended permissioned creator's later call to `initialize_with_permission` for the same mints/config fails because the PDA already exists — exactly mirroring the `GTELaunchpadV2PairFactory.createPair` pre-creation bug where a canonical pair is locked in with zeroed hooks by a non-privileged caller.

`enable_creator_fee` is read at swap time to decide whether creator fees accrue at all (used together with `creator_fee_on`/`is_creator_fee_on_input`), and it is never mutated after `PoolState::initialize` — no toggle instruction exists in the codebase: [5](#0-4) 

### Impact Explanation
Any market a project intends to launch through the permissioned/creator-fee-enabled path can be permanently downgraded to "no creator fee" by a single, cheap, unprivileged `initialize` call for the same `(amm_config, token_0_mint, token_1_mint)` triple before the legitimate creator transacts. This is a permanent, irreversible loss of the intended creator-fee revenue stream for that pool (the `pool_creator` field and `creator_fees_token_0/1` accounting will never accrue anything beyond the default protocol/fund fee split), since `initialize_with_permission` cannot be re-run against an already-initialized PDA and `enable_creator_fee` cannot be toggled later.

### Likelihood Explanation
Likelihood is high: no token transfers or approvals of significant size are strictly required (the attacker only needs to fund a trivial minimum liquidity amount to pass `CurveCalculator::validate_supply`), no special permission is needed to call `initialize`, and the attacker only needs to know/guess the `amm_config`, `token_0_mint`, and `token_1_mint` a project intends to use, which are generally public/predictable ahead of a token launch.

### Recommendation
Restrict pool creation for token pairs that are meant to use the permissioned/creator-fee flow so that a non-privileged `initialize` call cannot pre-empt the canonical PDA — e.g., check the `Permission` account (or an equivalent flag on `amm_config`) inside `initialize` and reject/redirect creation for configs reserved for permissioned pools, or unify the two code paths so that `enable_creator_fee`/`creator_fee_on` are determined by a value that cannot be front-run (such as requiring the `Permission` PDA to exist for the payer in both instructions, with `initialize` deriving the same fee treatment whenever the payer holds a valid permission).

### Proof of Concept
1. A project intends to launch token pair `(mintA, mintB)` under `amm_configX` via `initialize_with_permission`, expecting `enable_creator_fee = true`.
2. Before the project's launch transaction lands, an attacker submits `initialize(amm_configX, mintA, mintB, minimal_amount_0, minimal_amount_1, open_time)` as an ordinary unprivileged signer — no `Permission` account is required for this path. [6](#0-5) 
3. `create_pool` succeeds because the PDA `[POOL_SEED, amm_configX, mintA, mintB]` was still owned by the system program; `pool_state.initialize(...)` is called with `CreatorFeeOn::BothToken` and `enable_creator_fee = false`.
4. The project later submits `initialize_with_permission` for the same `(amm_configX, mintA, mintB)`; `create_pool` fails because `pool_account_info.owner` is no longer `system_program::ID`. [7](#0-6) 
5. The canonical pool now permanently has `enable_creator_fee = false`; the project's creator fee revenue stream from this market is unrecoverable for the pool's lifetime.

### Citations

**File:** programs/cp-swap/src/states/pool.rs (L134-178)
```rust
    pub fn initialize(
        &mut self,
        auth_bump: u8,
        lp_supply: u64,
        open_time: u64,
        pool_creator: Pubkey,
        amm_config: Pubkey,
        token_0_vault: Pubkey,
        token_1_vault: Pubkey,
        token_0_mint: &InterfaceAccount<Mint>,
        token_1_mint: &InterfaceAccount<Mint>,
        lp_mint: Pubkey,
        lp_mint_decimals: u8,
        observation_key: Pubkey,
        creator_fee_on: CreatorFeeOn,
        enable_creator_fee: bool,
    ) {
        self.amm_config = amm_config.key();
        self.pool_creator = pool_creator.key();
        self.token_0_vault = token_0_vault;
        self.token_1_vault = token_1_vault;
        self.lp_mint = lp_mint.key();
        self.token_0_mint = token_0_mint.key();
        self.token_1_mint = token_1_mint.key();
        self.token_0_program = *token_0_mint.to_account_info().owner;
        self.token_1_program = *token_1_mint.to_account_info().owner;
        self.observation_key = observation_key;
        self.auth_bump = auth_bump;
        self.lp_mint_decimals = lp_mint_decimals;
        self.mint_0_decimals = token_0_mint.decimals;
        self.mint_1_decimals = token_1_mint.decimals;
        self.lp_supply = lp_supply;
        self.protocol_fees_token_0 = 0;
        self.protocol_fees_token_1 = 0;
        self.fund_fees_token_0 = 0;
        self.fund_fees_token_1 = 0;
        self.open_time = open_time;
        self.recent_epoch = Clock::get().unwrap().epoch;
        self.creator_fee_on = creator_fee_on.to_u8();
        self.enable_creator_fee = enable_creator_fee;
        self.padding1 = [0u8; 6];
        self.creator_fees_token_0 = 0;
        self.creator_fees_token_1 = 0;
        self.padding = [0u64; 28];
    }
```

**File:** programs/cp-swap/src/states/pool.rs (L253-261)
```rust
    pub fn is_creator_fee_on_input(&self, direction: TradeDirection) -> Result<bool> {
        let fee_on = CreatorFeeOn::from_u8(self.creator_fee_on)?;
        Ok(match (fee_on, direction) {
            (CreatorFeeOn::BothToken, _) => true,
            (CreatorFeeOn::OnlyToken0, TradeDirection::ZeroForOne) => true,
            (CreatorFeeOn::OnlyToken1, TradeDirection::OneForZero) => true,
            _ => false,
        })
    }
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L182-247)
```rust
pub fn initialize(
    ctx: Context<Initialize>,
    init_amount_0: u64,
    init_amount_1: u64,
    mut open_time: u64,
) -> Result<()> {
    let mint0_associated_is_initialized = support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_0_mint,
    )?;
    let mint1_associated_is_initialized = support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_1_mint,
    )?;
    if !(is_supported_mint(&ctx.accounts.token_0_mint, mint0_associated_is_initialized).unwrap()
        && is_supported_mint(&ctx.accounts.token_1_mint, mint1_associated_is_initialized).unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
    }

    if ctx.accounts.amm_config.disable_create_pool {
        return err!(ErrorCode::NotApproved);
    }
    let block_timestamp = clock::Clock::get()?.unix_timestamp as u64;
    if open_time <= block_timestamp {
        open_time = block_timestamp + 1;
    }
    // due to stack/heap limitations, we have to create redundant new accounts ourselves.
    create_token_account(
        &ctx.accounts.authority.to_account_info(),
        &ctx.accounts.creator.to_account_info(),
        &ctx.accounts.token_0_vault.to_account_info(),
        &ctx.accounts.token_0_mint.to_account_info(),
        &ctx.accounts.system_program.to_account_info(),
        &ctx.accounts.token_0_program.to_account_info(),
        &[
            POOL_VAULT_SEED.as_bytes(),
            ctx.accounts.pool_state.key().as_ref(),
            ctx.accounts.token_0_mint.key().as_ref(),
            &[ctx.bumps.token_0_vault][..],
        ],
    )?;

    create_token_account(
        &ctx.accounts.authority.to_account_info(),
        &ctx.accounts.creator.to_account_info(),
        &ctx.accounts.token_1_vault.to_account_info(),
        &ctx.accounts.token_1_mint.to_account_info(),
        &ctx.accounts.system_program.to_account_info(),
        &ctx.accounts.token_1_program.to_account_info(),
        &[
            POOL_VAULT_SEED.as_bytes(),
            ctx.accounts.pool_state.key().as_ref(),
            ctx.accounts.token_1_mint.key().as_ref(),
            &[ctx.bumps.token_1_vault][..],
        ],
    )?;

    let pool_state_loader = create_pool(
        &ctx.accounts.creator.to_account_info(),
        &ctx.accounts.pool_state.to_account_info(),
        &ctx.accounts.amm_config.to_account_info(),
        &ctx.accounts.token_0_mint.to_account_info(),
        &ctx.accounts.token_1_mint.to_account_info(),
        &ctx.accounts.system_program.to_account_info(),
    )?;
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
