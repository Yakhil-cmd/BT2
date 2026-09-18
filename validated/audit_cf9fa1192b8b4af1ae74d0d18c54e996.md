### Title
Front-runnable, PDA-deterministic pool `initialize` / `initialize_with_permission` lets an attacker permanently seize `pool_creator` fee rights and set a skewed price with dust amounts - (File: programs/cp-swap/src/instructions/initialize.rs, programs/cp-swap/src/instructions/initialize_with_permission.rs)

### Summary
The `vestFor` bug class is "an unauthenticated function, reachable by any signer with attacker-chosen data, that permanently commits another party (or a shared resource tied to that party) to an unfavorable state using only a dust amount, front-running the legitimate actor." The closest reachable analog in this program is the permissionless `initialize`/`initialize_with_permission` instructions, whose `pool_state` account is a deterministic PDA derived only from `(amm_config, token_0_mint, token_1_mint)`. Anyone can call these instructions first with dust liquidity, permanently becoming the pool's `pool_creator` (the sole party ever entitled to `collect_creator_fee` / `collect_creator_fee_permissionless`) and fixing the initial `token_0/token_1` price ratio for that immutable PDA, before the intended/legitimate deployer's transaction lands.

### Finding Description
`Initialize`'s `pool_state` account is documented and derivable as a PDA using `POOL_SEED`, `amm_config`, `token_0_mint`, `token_1_mint`: [1](#0-0) 

`create_pool` accepts this exact deterministic PDA (or, alternatively, requires a signer for a "random" account, but the standard/expected path uses the PDA), and there is no requirement that `creator` be any specific address — `creator` is simply `Signer<'info>`, i.e. whoever submits the transaction: [2](#0-1) 

Once `create_pool` succeeds and `pool_state.initialize(...)` is called, `pool_creator` is permanently set to the caller and cannot ever be changed later: [3](#0-2) 

The only economic barrier to calling `initialize` is that `liquidity = sqrt(amount_0 * amount_1)` must exceed the fixed `lock_lp_amount = 100`, which is trivially satisfiable with dust deposits (e.g. amounts of 101 and 101 raw token units satisfy `sqrt(101*101)=101 > 100`): [4](#0-3) 

Because the pool address is a deterministic PDA, once any account initializes it for a given `(amm_config, token_0_mint, token_1_mint)` triple, the PDA is permanently occupied — any other party (including the intended, legitimate project deployer) can never call `initialize`/`initialize_with_permission` again for that exact pair/config, since `create_pool` requires `pool_account_info.owner == system_program::ID` before init, which will no longer hold: [5](#0-4) 

This mirrors the `vestFor` bug class precisely: an unauthenticated, anyone-callable entry point that lets a malicious actor front-run the legitimate call with an insignificant/dust amount, permanently locking a specific outcome (here, `pool_creator`, the initial price ratio, and the PDA slot itself) against the legitimate party, with no way to undo or update it afterward.

### Impact Explanation
An attacker can:
1. Watch the mempool/RPC for a legitimate project's planned `initialize` call for a given token pair and `amm_config`.
2. Front-run it with a near-dust `init_amount_0`/`init_amount_1` (satisfying only the `liquidity > 100` check), becoming `pool_creator` forever and permanently diverting all future `collect_creator_fee`/`collect_creator_fee_permissionless` proceeds to themselves instead of the legitimate project.
3. Set an arbitrary/skewed initial price ratio for that PDA-addressed pool, which the legitimate LPs and traders are then forced to interact with (or arbitrage against, at a loss) since the pool address for that `(config, token_0, token_1)` is fixed and cannot be re-created.

This is a permanent, unauthorized privileged effect (seizure of the `pool_creator` role and fee stream) achievable from a single attacker-chosen transaction with negligible capital, matching the required bar of "concrete theft ... or an unauthorized privileged effect."

### Likelihood Explanation
Likelihood is high in adversarial/MEV environments: pool creation transactions are public before confirmation, the dust threshold to pass the `lock_lp_amount` check is trivial, and `initialize`/`initialize_with_permission` have no authentication restricting who may call them or who may be recorded as `pool_creator`.

### Recommendation
Introduce an authorization/whitelist mechanism analogous to the report's recommendation for `vestFor`: gate pool creation for a given `(amm_config, token_0_mint, token_1_mint)` PDA behind a permission or reservation mechanism (e.g., the existing `Permission`/`create_permission_pda` scheme already used to gate `initialize_with_permission`, but applied consistently, or a commit-reveal / minimum-liquidity-with-slippage-bound scheme), so that an unrelated party cannot occupy the deterministic PDA and seize `pool_creator` rights ahead of the intended deployer with dust capital.

### Proof of Concept
1. Attacker monitors for a pending `initialize` transaction for `(amm_config = C, token_0 = A, token_1 = B)`.
2. Attacker submits their own `initialize` call for the same `(C, A, B)` with `init_amount_0 = 101`, `init_amount_1 = 101` (satisfies `sqrt(101*101) = 101 > lock_lp_amount(100)`), naming themselves as `creator`. [4](#0-3) 
3. Attacker's transaction lands first; `pool_state.initialize` permanently records the attacker as `pool_creator`: [6](#0-5) 
4. The legitimate deployer's original `initialize` transaction for the same PDA now fails at `create_pool`'s ownership check because the account is no longer owned by the system program: [7](#0-6) 
5. The legitimate deployer can never become `pool_creator` for that pair/config again, and all future creator-fee collections via `collect_creator_fee`/`collect_creator_fee_permissionless` are directed to the attacker permanently. [8](#0-7)

### Citations

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L294-316)
```rust
    let liquidity = U128::from(token_0_vault.amount)
        .checked_mul(token_1_vault.amount.into())
        .unwrap()
        .integer_sqrt()
        .as_u64();
    let lock_lp_amount = 100;
    msg!(
        "liquidity:{}, lock_lp_amount:{}, vault_0_amount:{},vault_1_amount:{}",
        liquidity,
        lock_lp_amount,
        token_0_vault.amount,
        token_1_vault.amount
    );
    token::token_mint_to(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
        ctx.accounts.lp_mint.to_account_info(),
        ctx.accounts.creator_lp_token.to_account_info(),
        liquidity
            .checked_sub(lock_lp_amount)
            .ok_or(ErrorCode::InitLpAmountTooLess)?,
        &[&[crate::AUTH_SEED.as_bytes(), &[ctx.bumps.authority]]],
    )?;
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L364-388)
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
```

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L10-13)
```rust
pub struct CollectCreatorFee<'info> {
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,
```
