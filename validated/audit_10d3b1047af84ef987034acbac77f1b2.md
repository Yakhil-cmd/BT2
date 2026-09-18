Confirmed: `pool_creator` is set once in `PoolState::initialize` at pool creation and is never updatable afterward, and `collect_creator_fee`/`collect_creator_fee_permissionless` gate the payout strictly on `pool_state.pool_creator`. This confirms the front-running analog is valid and has concrete, permanent impact.

### Title
Attacker Can Front-Run Permissionless Pool Initialization to Permanently Steal `pool_creator` Rights and Future Creator Fees - (File: programs/cp-swap/src/instructions/initialize.rs)

### Summary
`initialize` (and `initialize_with_permission`) is fully permissionless: "Address paying to create the pool. Can be anyone" [1](#0-0) . The pool account is a deterministic PDA derived only from `amm_config`, `token_0_mint`, and `token_1_mint` [2](#0-1) , and whoever's transaction lands first becomes the permanent `pool_creator` for that exact config/pair combination via `pool_state.initialize(...)` [3](#0-2) . There is no mechanism anywhere in the program to change `pool_creator` after creation, and the PDA can never be re-initialized once occupied (identical bug class to the report: a permissionless registration call whose deterministic identifier, once claimed by anyone, cannot be reused or reassigned, permanently locking out the intended party).

### Finding Description
`pool_creator` is recorded once at pool creation time and is immutable for the lifetime of the pool [4](#0-3) . All future creator-fee payouts are gated strictly on this address in both `collect_creator_fee` (`address = pool_state.load()?.pool_creator`) [5](#0-4)  and `collect_creator_fee_permissionless`, where the ATA recipient is likewise constrained to `pool_state.load()?.pool_creator` [6](#0-5) .

Because the pool PDA is deterministic and derivable by anyone from public inputs (`amm_config`, `token_0_mint`, `token_1_mint`), and `initialize`/`initialize_with_permission` accept any `creator`/`payer` without checking who "should" be creating the pool for that pair, an attacker who observes a pending `initialize` transaction in the mempool for a given `amm_config`+token pair can front-run it with their own `initialize` call using the same PDA, arbitrary `init_amount_0`/`init_amount_1`, and themselves as `creator`. Once the PDA is initialized, the legitimate party's transaction fails (the `pool_state`/`lp_mint`/`observation_state` accounts use Anchor `init`, which reverts if the account already exists), and there is no instruction to later replace or migrate `pool_creator`.

### Impact Explanation
The attacker permanently and irrevocably becomes the `pool_creator` of the canonical pool PDA for that token pair and config, granting them an unauthorized privileged effect: exclusive rights to collect all future `creator_fees_token_0`/`creator_fees_token_1` accrued from every subsequent swap through that pool via `collect_creator_fee`/`collect_creator_fee_permissionless` [7](#0-6) . Legitimate project teams intending to launch and monetize a pool for their token lose this revenue stream permanently, with no recovery path, matching the "unauthorized privileged effect" bar.

### Likelihood Explanation
Any pending `initialize`/`initialize_with_permission` transaction is visible in the mempool prior to confirmation, and the PDA seeds are fully public and computable in advance from `AmmConfig` + both mint addresses [2](#0-1) . No special privilege, signature, or non-default configuration is required by the attacker — only submitting a competing `initialize` transaction with a slightly higher priority fee, making this practically exploitable for any anticipated pool launch.

### Recommendation
Require an explicit, pre-committed authorization for canonical pool creation (e.g., only allow the `amm_config` owner/fund_owner, or a specific expected `creator` pubkey stored ahead of time, to initialize a pool for a given PDA), or allow `pool_creator` to be reassigned/verified against an off-chain-agreed value before any creator fees can be collected. Alternatively, bind pool creation rights to a commit-reveal scheme so the intended creator's identity cannot be front-run.

### Proof of Concept
1. Project team prepares an `initialize` transaction for `token_0_mint`/`token_1_mint` under `amm_config` index 0, intending to become `pool_creator`.
2. Attacker monitors the mempool, computes the same `pool_state` PDA via `[POOL_SEED, amm_config, token_0_mint, token_1_mint]` [2](#0-1) .
3. Attacker submits their own `initialize` call with a higher fee/priority, using their own wallet as `creator` and arbitrary `init_amount_0`/`init_amount_1`.
4. Attacker's transaction lands first; `pool_state.initialize(...)` sets `pool_creator = attacker` [3](#0-2) .
5. The legitimate team's `initialize` transaction reverts because the `pool_state`/`lp_mint`/`observation_state` PDAs are already initialized.
6. From then on, every swap's creator-fee accrual is only claimable by the attacker via `collect_creator_fee`/`collect_creator_fee_permissionless`, permanently diverting the intended project's fee revenue.

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L21-24)
```rust
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

**File:** programs/cp-swap/src/instructions/initialize.rs (L376-384)
```rust
    let (expect_pda_address, bump) = Pubkey::find_program_address(
        &[
            POOL_SEED.as_bytes(),
            amm_config.key().as_ref(),
            token_0_mint.key().as_ref(),
            token_1_mint.key().as_ref(),
        ],
        &crate::id(),
    );
```

**File:** programs/cp-swap/src/states/pool.rs (L326-351)
```rust
    pub fn update_fees(
        &mut self,
        protocol_fee: u64,
        fund_fee: u64,
        creator_fee: u64,
        direction: TradeDirection,
    ) -> Result<()> {
        if !self.enable_creator_fee {
            require_eq!(creator_fee, 0)
        }
        let is_creator_fee_on_input = self.is_creator_fee_on_input(direction)?;
        match direction {
            TradeDirection::ZeroForOne => {
                self.protocol_fees_token_0 = self
                    .protocol_fees_token_0
                    .checked_add(protocol_fee)
                    .unwrap();
                self.fund_fees_token_0 = self.fund_fees_token_0.checked_add(fund_fee).unwrap();

                if is_creator_fee_on_input {
                    self.creator_fees_token_0 =
                        self.creator_fees_token_0.checked_add(creator_fee).unwrap();
                } else {
                    self.creator_fees_token_1 =
                        self.creator_fees_token_1.checked_add(creator_fee).unwrap();
                }
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L11-13)
```rust
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-118)
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
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L17-20)
```rust
    /// The pool creator that receives the collected creator fees
    /// CHECK: the address is constrained to the `pool_creator` recorded in `pool_state`
    #[account(address = pool_state.load()?.pool_creator)]
    pub creator: UncheckedAccount<'info>,
```
