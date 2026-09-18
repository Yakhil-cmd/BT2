## Analysis

The reported bug class — an unauthenticated, first-writer-wins registration function that lets an attacker front-run a legitimate caller and lock in a privileged role tied to a deterministic identifier, for the cost of a minimal amount of funds — has a direct analog in this program's permissionless pool-creation flow.

### Title
Front-runnable, permissionless `initialize`/`initialize_with_permission` lets an attacker seize the `pool_creator` role for any token pair with minimal capital, permanently redirecting creator fees and DoS-ing the legitimate deployer - (File: `programs/cp-swap/src/instructions/initialize.rs`, `programs/cp-swap/src/instructions/create_pool` in the same file)

### Summary
`initialize()` (and `initialize_with_permission()`) create the `pool_state` account at a fully deterministic PDA derived only from `amm_config`, `token_0_mint`, and `token_1_mint` [1](#0-0) , and any signer can call it as `creator` [2](#0-1) . Whoever's transaction lands first is permanently recorded as `pool_state.pool_creator` [3](#0-2) , and all subsequent attempts to create the same-PDA pool fail because `create_pool` requires the account to still be system-program owned [4](#0-3) .

### Finding Description
This mirrors the report's root cause exactly: a state-mutating entrypoint reachable by anyone, keyed by a deterministic, attacker-predictable identifier (there `batchMerkleRoot`, here the `(amm_config, token_0_mint, token_1_mint)` tuple), with no minimum-stake/authentication check strong enough to stop trivial front-running:

- `create_pool()` computes the expected PDA from public inputs (`amm_config`, `token_0_mint`, `token_1_mint`) and only requires the account to be system-owned; it does not check who invoked the instruction [5](#0-4) .
- `pool_state.initialize()` unconditionally stores `msg.sender`-equivalent (`ctx.accounts.creator.key()`) as `pool_creator` [6](#0-5) .
- The only economic gate is `CurveCalculator::validate_supply(token_0_vault.amount, token_1_vault.amount)`, which enforces basic non-zero/overflow-safety on the deposited amounts [7](#0-6)  — not a meaningful minimum liquidity threshold that would deter griefing, analogous to the original report's "1 wei is enough" defect.
- Once set, `pool_creator` is a permanently privileged role: `collect_creator_fee()` restricts fee withdrawal to `address = pool_state.load()?.pool_creator` [8](#0-7) , and `collect_creator_fee_permissionless()` sends all accrued creator fees to that same recorded address regardless of who calls it [9](#0-8) . Fees accumulate on every swap via `update_fees()` [10](#0-9) .

An attacker monitoring the mempool for a legitimate project's pool-creation transaction (same `token_0_mint`/`token_1_mint`/`amm_config`) can submit their own `initialize` call with a minimal token deposit and higher priority fee, front-running the legitimate creator. The attacker's transaction succeeds first, permanently claims `pool_creator` for that token pair's PDA, and the legitimate deployer's transaction reverts because the PDA is no longer system-owned (`ErrorCode::NotApproved`) — the exact "task already submitted" DoS pattern from the report, except the attacker also inherits open-ended, ongoing creator-fee revenue diverted away from the legitimate project.

### Impact Explanation
This is a permanent unauthorized privileged effect: the attacker becomes the sole address entitled to withdraw `creator_fees_token_0`/`creator_fees_token_1` for that pool for its entire lifetime, and there is no mechanism to reassign or dispute `pool_creator` after initialization. This constitutes ongoing theft of fee revenue that should accrue to the legitimate pool creator, plus a denial-of-service on the legitimate deployer's ability to ever create that specific pool (their transaction permanently reverts once the PDA is claimed).

### Likelihood Explanation
Highly likely for any pool with anticipated significant volume: the PDA (`POOL_SEED`, `amm_config`, `token_0_mint`, `token_1_mint`) is fully computable off-chain by anyone before the legitimate creation transaction lands, mint addresses are typically known/public ahead of a pool launch (e.g. announced token contracts), and the attack costs only a minimal token deposit satisfying `validate_supply` plus a competitive transaction fee/priority fee to win the race.

### Recommendation
Do not let an unauthenticated caller permanently and irrevocably become `pool_creator` for a pool whose PDA is fully predictable from public inputs. Options include: requiring a substantial minimum initial liquidity/deposit tied to `create_pool_fee` economics, allowing an authorized/allow-listed initializer for the `amm_config` in question, or decoupling the "first funder" role from the ongoing "fee recipient" role so front-running only costs the attacker gas rather than granting a persistent revenue stream.

### Proof of Concept
1. Legitimate project builds and submits `initialize(token_0_mint=X, token_1_mint=Y, amm_config=C, init_amount_0, init_amount_1, open_time)` for their token pair.
2. Attacker observes the pending transaction (public mempool / RPC), derives the same `pool_state` PDA using `POOL_SEED, C, X, Y`, and submits their own `initialize` call with a minimal `init_amount_0`/`init_amount_1` (just enough to pass `CurveCalculator::validate_supply`) and a higher priority fee.
3. Attacker's transaction lands first: `create_pool()` succeeds since the PDA is still system-owned [11](#0-10) ; `pool_state.initialize()` records the attacker as `pool_creator` [12](#0-11) .
4. The legitimate project's `initialize` transaction now reverts with `ErrorCode::NotApproved` since the PDA is program-owned.
5. As users swap on the pool, `update_fees()` accrues `creator_fees_token_0/1` [10](#0-9) , and only the attacker (recorded `pool_creator`) can direct these fees via `collect_creator_fee`/`collect_creator_fee_permissionless` to their own token accounts [8](#0-7) .

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L21-24)
```rust
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

**File:** programs/cp-swap/src/instructions/initialize.rs (L292-298)
```rust
    CurveCalculator::validate_supply(token_0_vault.amount, token_1_vault.amount)?;

    let liquidity = U128::from(token_0_vault.amount)
        .checked_mul(token_1_vault.amount.into())
        .unwrap()
        .integer_sqrt()
        .as_u64();
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

**File:** programs/cp-swap/src/states/pool.rs (L134-152)
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
```

**File:** programs/cp-swap/src/states/pool.rs (L326-368)
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
            }
            TradeDirection::OneForZero => {
                self.protocol_fees_token_1 = self
                    .protocol_fees_token_1
                    .checked_add(protocol_fee)
                    .unwrap();
                self.fund_fees_token_1 = self.fund_fees_token_1.checked_add(fund_fee).unwrap();
                if is_creator_fee_on_input {
                    self.creator_fees_token_1 =
                        self.creator_fees_token_1.checked_add(creator_fee).unwrap();
                } else {
                    self.creator_fees_token_0 =
                        self.creator_fees_token_0.checked_add(creator_fee).unwrap();
                }
            }
        };
        Ok(())
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L10-13)
```rust
pub struct CollectCreatorFee<'info> {
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
