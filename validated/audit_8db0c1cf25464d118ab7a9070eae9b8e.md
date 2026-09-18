### Title
Permissionless `initialize` pool creation with deterministic PDA seeds enables front-running of the `pool_creator` role and diversion of creator trading fees - (File: `programs/cp-swap/src/instructions/initialize.rs`)

### Summary
The `initialize` instruction can be called by any unprivileged signer and derives the `pool_state` PDA deterministically from `amm_config`, `token_0_mint`, and `token_1_mint`, all of which are public inputs. The caller who successfully lands the `initialize` transaction becomes the permanent `pool_creator`, entitled to collect all future creator trading fees via `collect_creator_fee`. An attacker observing a pending `initialize` transaction in the mempool can front-run it with an identical set of deterministic accounts and higher priority fee, seizing the `pool_creator` role for that token pair before the legitimate deployer's transaction lands.

### Finding Description
`Initialize` only requires `creator: Signer<'info>` — no whitelist, allowlist, or authorization check is applied before pool creation [1](#0-0) . The `pool_state` account, though declared `UncheckedAccount`, is created through `create_pool` using seeds derived purely from `amm_config`, `token_0_mint`, and `token_1_mint` [2](#0-1) , matching the documented PDA derivation `[POOL_SEED, amm_config, token_0_mint, token_1_mint]` used by the client [3](#0-2) .

Whoever's `initialize` transaction succeeds first becomes `pool_creator` and permanently owns the right to collect creator fees, enforced by an `address` constraint tying the `creator` signer in `CollectCreatorFee` to `pool_state.load()?.pool_creator` [4](#0-3) . Because the PDA address is fully determined by public token mints and the `amm_config` account (also public), an attacker can precompute the exact same accounts a legitimate project intends to use and submit a competing `initialize` transaction with a higher priority fee. If the attacker's transaction lands first, the `pool_state` PDA is created under their `pool_creator`, and the legitimate creator's later transaction fails because the PDA (and associated LP mint / observation state PDAs, also seeded by `pool_state.key()`) already exists [5](#0-4) .

This mirrors the CoreFactory `createProject` front-running issue: an unprivileged, permissionless creation function whose resulting "ownership" (here, `pool_creator`) is determined solely by transaction ordering, allowing an attacker to seize that role ahead of the intended party.

### Impact Explanation
The attacker does not steal already-deposited principal (the attacker must supply their own initial liquidity to `initialize`), so this differs from the original report's "withdraw paymentToken you never deposited" scenario. However, the attacker permanently captures the `pool_creator` role for that canonical token-pair pool, diverting all subsequent `creator_fees_token_0`/`creator_fees_token_1` revenue that would otherwise accrue to the legitimate project deployer via `collect_creator_fee` [6](#0-5) . For pools with a `creator_fee_on` configuration this constitutes an unauthorized privileged effect and an ongoing revenue-theft vector against the legitimate pool creator, satisfying a Medium classification (unauthorized privileged effect / accounting diversion) rather than Critical/High since user/LP principal is not directly frozen or stolen.

### Likelihood Explanation
Likelihood is moderate: it requires the attacker to (a) observe a pending `initialize` transaction (mempool/RPC visibility, common on Solana validators/blockhash-based simulation), (b) hold enough of both tokens to satisfy the minimum liquidity/supply validation in `CurveCalculator::validate_supply`, and (c) win the priority-fee race. This is realistic for any anticipated/announced token launch where the deployer's intent (token mints, config index) is known in advance.

### Recommendation
- Allow the intended creator to reserve or pre-commit the `pool_state` PDA (e.g., via a separate authorization/whitelist step gated by `AmmConfig` admin, similar to `initialize_with_permission`'s `Permission` PDA check) before permissionless liquidity seeding is possible.
- Alternatively, decouple `pool_creator` fee entitlement from "whoever calls `initialize` first" by requiring an explicit, signed designation of the intended creator address that can be verified independently of transaction ordering.
- Consider requiring `random_pool_id` (a fresh signer-provided keypair) rather than the fully deterministic PDA path for creator-fee-bearing pools, removing the ability for an attacker to precompute the exact colliding accounts.

### Proof of Concept
1. A legitimate project prepares an `initialize` transaction for `token_0_mint`/`token_1_mint` under a known `amm_config_index`, deriving `pool_state`, `lp_mint`, `token_0_vault`, `token_1_vault`, and `observation_state` PDAs exactly as done in `initialize_pool_instr` [7](#0-6) .
2. The transaction (or its account list) becomes visible to an attacker prior to confirmation.
3. The attacker independently computes the same deterministic PDAs (public inputs: token mints + amm_config) and submits their own `initialize` call with the same accounts, their own token balances for `init_amount_0`/`init_amount_1`, and a higher priority fee.
4. The attacker's transaction lands first; `create_pool` initializes `pool_state` with the attacker as `pool_creator` [8](#0-7) .
5. The legitimate project's `initialize` transaction fails (PDA already initialized).
6. Going forward, only the attacker (matching `pool_state.load()?.pool_creator`) can call `collect_creator_fee` to claim accumulated creator trading fees from that canonical pool [4](#0-3) , permanently diverting that revenue stream away from the intended creator.

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L65-78)
```rust
    /// pool lp mint
    #[account(
        init,
        seeds = [
            POOL_LP_MINT_SEED.as_bytes(),
            pool_state.key().as_ref(),
        ],
        bump,
        mint::decimals = 9,
        mint::authority = authority,
        payer = creator,
        mint::token_program = token_program,
    )]
    pub lp_mint: Box<InterfaceAccount<'info, Mint>>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L240-248)
```rust
    let pool_state_loader = create_pool(
        &ctx.accounts.creator.to_account_info(),
        &ctx.accounts.pool_state.to_account_info(),
        &ctx.accounts.amm_config.to_account_info(),
        &ctx.accounts.token_0_mint.to_account_info(),
        &ctx.accounts.token_1_mint.to_account_info(),
        &ctx.accounts.system_program.to_account_info(),
    )?;
    let pool_state = &mut pool_state_loader.load_init()?;
```

**File:** client/src/instructions/amm_instructions.rs (L40-91)
```rust
    let amm_config_index = 0u16;
    let (amm_config_key, __bump) = Pubkey::find_program_address(
        &[AMM_CONFIG_SEED.as_bytes(), &amm_config_index.to_be_bytes()],
        &program.id(),
    );

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

    let (authority, __bump) = Pubkey::find_program_address(&[AUTH_SEED.as_bytes()], &program.id());
    let (token_0_vault, __bump) = Pubkey::find_program_address(
        &[
            POOL_VAULT_SEED.as_bytes(),
            pool_account_key.to_bytes().as_ref(),
            token_0_mint.to_bytes().as_ref(),
        ],
        &program.id(),
    );
    let (token_1_vault, __bump) = Pubkey::find_program_address(
        &[
            POOL_VAULT_SEED.as_bytes(),
            pool_account_key.to_bytes().as_ref(),
            token_1_mint.to_bytes().as_ref(),
        ],
        &program.id(),
    );
    let (lp_mint_key, __bump) = Pubkey::find_program_address(
        &[
            POOL_LP_MINT_SEED.as_bytes(),
            pool_account_key.to_bytes().as_ref(),
        ],
        &program.id(),
    );
    let (observation_key, __bump) = Pubkey::find_program_address(
        &[
            OBSERVATION_SEED.as_bytes(),
            pool_account_key.to_bytes().as_ref(),
        ],
        &program.id(),
    );
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
