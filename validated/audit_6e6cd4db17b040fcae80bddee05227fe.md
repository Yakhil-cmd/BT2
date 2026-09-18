### Title
Permissionless pool creation can be frontrun to poison the initial price of a token pair - (File: programs/cp-swap/src/instructions/initialize.rs)

### Summary
`initialize` and `initialize_with_permission` allow any signer to create a pool for a given `(amm_config, token_0_mint, token_1_mint)` triple, with the pool's PDA address deterministically derived from those three inputs. [1](#0-0)  Because the caller who creates the pool also freely chooses `init_amount_0`/`init_amount_1` (the values that set the pool's initial constant-product price), and because the `creator` field is explicitly documented as "Can be anyone," an attacker who observes a pending legitimate pool-creation transaction in the mempool can frontrun it and claim the deterministic PDA first, seeding the pool with an arbitrarily skewed price.

### Finding Description
`create_pool` derives the pool PDA from `POOL_SEED`, `amm_config`, `token_0_mint`, and `token_1_mint`, and only requires `is_signer` if the caller-supplied `pool_state` account does not match the expected PDA — meaning the canonical, discoverable PDA path is the default and fully permissionless for any signer paying the create. [2](#0-1)  The `creator`/`payer` in both `Initialize` and `InitializeWithPermission` is just `Signer<'info>` with no restriction on who it can be, and the same deterministic seed set is used, so the first transaction to land for a given `(config, token_0, token_1)` combination is the only one that can ever succeed — any later attempt to `init` the same PDA fails. [3](#0-2) 

The initial LP liquidity and thus the pool's starting exchange rate is computed purely from whatever `init_amount_0`/`init_amount_1` the pool-creating transaction transfers in — `liquidity = sqrt(vault_0.amount * vault_1.amount)`, with no dependency on any external price oracle or fair-market check beyond `CurveCalculator::validate_supply`. [4](#0-3)  This means the party who wins the race to create the pool for a given mint pair fully controls the initial token_0/token_1 ratio.

This mirrors the bug class from the referenced report: a resource that is guaranteed to be unique per key (a Lens "handle," here a "(amm_config, token_0_mint, token_1_mint)" pool) can be claimed by whoever's transaction lands first, and any pending transaction attempting to create/claim it is visible and frontrunnable in the public mempool.

### Impact Explanation
Any legitimate user who broadcasts an `initialize`/`initialize_with_permission` transaction intending to bootstrap a pool for a specific token pair at a fair price can be frontrun by an attacker who submits the same instruction first (with the same `amm_config`, `token_0_mint`, `token_1_mint`, hence the same deterministic pool PDA) but with a deliberately skewed `init_amount_0`/`init_amount_1` ratio. Because the pool PDA and its constant-product curve state are now permanently seeded with this skewed ratio, all subsequent participants (the original creator's own deposit/swap transactions, or unrelated later users who query on-chain or off-chain UIs and interact with what they assume to be the canonical, fairly priced pool for that pair) trade or deposit against a manipulated exchange rate. The attacker can then extract value via arbitrage swaps against their own mispriced pool (`swap_base_input`/`swap_base_output`), effectively stealing value from any counterparties who trade at the skewed rate before it corrects. The original victim's own pool-creation transaction also fails outright (the PDA already exists), wasting their transaction fee and forcing them to either abandon the pair or use the attacker-controlled pool.

### Likelihood Explanation
Pool-creation transactions for high-demand token pairs are easily identifiable in the mempool (they call a known instruction with visible `token_0_mint`/`token_1_mint`/`amm_config` arguments), and since both `initialize` and `initialize_with_permission` are open to any signer with no allow-list or commit/reveal step, replicating the exact instruction with different `init_amount_0`/`init_amount_1` values is trivial and cheap for a searcher/bot monitoring for new-pair creation, making this readily exploitable whenever a new, valuable trading pair is being launched.

### Recommendation
Introduce a commit/reveal or private-relay pathway for initial pool seeding, or decouple the deterministic PDA claim from the price-setting step (e.g., require the initial deposit ratio to be validated against an oracle or capped deviation, or allow a grace period during which only the original committer can finalize the price). At minimum, document this as an inherent frontrunning risk so integrators know to use private transaction relays (e.g., Jito bundles) when creating pools for valuable pairs.

### Proof of Concept
1. Victim `V` prepares a transaction calling `initialize(amm_config, token_0_mint=A, token_1_mint=B, init_amount_0=1_000_000, init_amount_1=1_000_000)` intending a 1:1 price, and broadcasts it.
2. Attacker `M` observes this pending transaction (same `amm_config`/`token_0_mint`/`token_1_mint` are visible), and submits their own `initialize` call for the identical `(amm_config, A, B)` triple but with `init_amount_0=1_000_000_000, init_amount_1=1` (an extreme skew), with a higher priority fee so it lands first.
3. `create_pool` derives the same PDA for `M`'s transaction (seeds depend only on `amm_config`/mints, not on the caller) and succeeds, permanently claiming the pool at the skewed ratio. [5](#0-4) 
4. `V`'s original transaction now fails since the PDA is already initialized.
5. `M` immediately calls `swap_base_input`/`swap_base_output` against the mispriced pool to arbitrage against any user who deposits/swaps at the skewed rate before it converges to market price, extracting value from those counterparties.

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-50)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,

    /// Which config the pool belongs to.
    pub amm_config: Box<Account<'info, AmmConfig>>,

    /// CHECK:
    /// pool vault and lp mint authority
    #[account(
        seeds = [
            crate::AUTH_SEED.as_bytes(),
        ],
        bump,
    )]
    pub authority: UncheckedAccount<'info>,

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L292-316)
```rust
    CurveCalculator::validate_supply(token_0_vault.amount, token_1_vault.amount)?;

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
