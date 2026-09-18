### Title
Permissionless pool `initialize` can be front-run to hijack `pool_creator` status and steal all future creator-fee revenue - (File: `programs/cp-swap/src/instructions/initialize.rs`)

### Summary
The Solidity report flags that `Unitas.initialize` is callable by anyone and can be front-run to seize a privileged role. The analogous instruction in this program is `initialize` (pool creation), where the `creator` account is an arbitrary signer with no access control beyond being able to fund the pool, and the caller is permanently recorded as `pool_creator` in `PoolState`, which the program treats as a privileged, fee-earning role for the lifetime of the pool.

### Finding Description
`Initialize` accepts `creator: Signer<'info>` with no allow-list or ownership check, and the pool PDA is deterministically derived only from `amm_config`, `token_0_mint`, and `token_1_mint`: [1](#0-0) 

Because the PDA address for a given token pair is fully predictable off-chain, any legitimate deployer's `initialize` transaction (or even just their intent to create a pool for a specific mint pair, observable via mempool/RPC submission) can be raced by an attacker submitting an equivalent `initialize` transaction with the attacker set as `creator`, tiny `init_amount_0`/`init_amount_1`, and their own token accounts. Whoever lands first claims the PDA and is written into `PoolState` as `pool_creator`: [2](#0-1) 

`pool_creator` is not a cosmetic field — it is the sole authority permitted to withdraw accumulated `creator_fees_token_0`/`creator_fees_token_1` via `collect_creator_fee`, enforced by an `address =` constraint against `pool_state.load()?.pool_creator`: [3](#0-2) 

Since the legitimate project's intended pool for that mint pair can never be created afterward at the canonical PDA (an `init` constraint will simply fail on the already-initialized account), the attacker permanently and irrevocably owns the creator-fee stream for that trading pair.

### Impact Explanation
This is a concrete, permanent theft of user/protocol funds: the attacker becomes the sole beneficiary of `creator_fees_token_0`/`creator_fees_token_1` accrued from all future swaps on that pool for as long as it exists, siphoning fees that should belong to the legitimate token issuer. It also permanently denies the legitimate deployer their intended pool address (a freezing/denial effect on the intended pair), since the PDA can only be initialized once. The attacker's cost is trivial (minimum `init_amount_0`/`init_amount_1` liquidity plus rent), so the attack is cheap and repeatable across any mint pair the attacker anticipates will be popular.

### Likelihood Explanation
`initialize` is a fully permissionless, single-instruction call reachable directly from an unprivileged wallet with attacker-chosen accounts, requiring no special timing beyond ordinary transaction-ordering/front-running (a well-known and practically exploitable capability on Solana via priority fees/leader targeting). Any project publicly announcing or preparing a new token-pair pool is exposed the moment its mint addresses (and therefore its deterministic pool PDA) become known.

### Recommendation
Bind pool creation to an authorized party for the intended token pair, e.g. by requiring `token_0_mint`/`token_1_mint` mint or freeze authority to match the `creator`, or by using `initialize_with_permission` (already present in the codebase at `programs/cp-swap/src/instructions/initialize_with_permission.rs`) as the default/enforced path for pairs where creator-fee rights matter, rather than leaving the permissionless `initialize` path as the only option for claiming `pool_creator` status. Alternatively, decouple `pool_creator`/fee rights from "whoever calls `initialize` first" and make it settable/transferable by a governance-controlled or mint-authority-verified process.

### Proof of Concept
1. Attacker monitors for a new token mint pair `(token_0_mint, token_1_mint)` intended for a pool by a legitimate project (e.g., observed in a pending `initialize` transaction, or simply predicted from a newly deployed token's mint address).
2. Attacker computes the deterministic pool PDA using the same seeds as `client/src/instructions/amm_instructions.rs` (`POOL_SEED`, `amm_config`, `token_0_mint`, `token_1_mint`): [4](#0-3) 
3. Attacker submits their own `initialize` instruction first (with higher priority fee to win the race), supplying minimal `init_amount_0`/`init_amount_1` and their own wallet as `creator`.
4. `create_pool` succeeds because the PDA is still owned by the system program at that point, and `pool_state.initialize(...)` records the attacker as `pool_creator`: [5](#0-4) 
5. The legitimate deployer's subsequent `initialize` call for the same PDA fails (`init` constraint rejects a non-system-owned/existing account).
6. All future swaps on this pool accrue creator fees exclusively claimable by the attacker via `collect_creator_fee`, which checks `address = pool_state.load()?.pool_creator`.

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-37)
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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L9-14)
```rust
#[derive(Accounts)]
pub struct CollectCreatorFee<'info> {
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,

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
