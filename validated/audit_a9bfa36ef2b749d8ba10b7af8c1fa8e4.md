### Title
Permissionless `initialize` pool creation is front-runnable, letting an attacker seize the canonical `pool_creator` role and steal all future creator-fee revenue for a token pair - ([File: programs/cp-swap/src/instructions/initialize.rs])

### Summary
The permissionless `initialize` instruction derives the pool's address deterministically from `amm_config`, `token_0_mint`, and `token_1_mint`, and unconditionally records whichever signer submits the transaction as `pool_creator`, a role that is never transferable and perpetually entitled to collect the pool's accumulated creator fees.

### Finding Description
`create_pool` derives the canonical `pool_state` PDA solely from `AMM_CONFIG_SEED`-derived `amm_config`, `token_0_mint`, and `token_1_mint`: [1](#0-0) 

Because the seeds contain nothing tied to the transaction sender, any observer of a pending `initialize` transaction in the mempool can extract `(amm_config, token_0_mint, token_1_mint)` and resubmit an equivalent transaction with higher priority fee, deriving the identical `pool_state` PDA. Whoever's transaction lands first wins the account creation; the legitimate creator's transaction then fails because the PDA is already initialized.

The `initialize` handler unconditionally sets `pool_creator` to whichever account signed as `creator`, with no relationship enforced to any prior intent, project, or the token mints themselves: [2](#0-1) [3](#0-2) 

`pool_creator` is a permanent field written once at `initialize()` and is never updated elsewhere in the codebase (no admin instruction exists to change it). It is the sole authority permitted to withdraw the pool's `creator_fees_token_0`/`creator_fees_token_1`, both in the permissioned collection path and the permissionless one: [4](#0-3) [5](#0-4) 

Creator fees accrue continuously on every swap through that pool via `update_fees`: [6](#0-5) 

This is structurally the same bug class as the referenced `registerCode` finding: a permissionless, front-runnable registration call binds a valuable, non-transferable privilege (referral-code ownership / here, pool-creator fee rights) to whichever address wins the race for a deterministic, attacker-predictable identifier, rather than to the intended party.

Note: `initialize` does allow the caller to instead supply a `random_pool_id` (a fresh signer-controlled keypair) as an alternative to the deterministic PDA, which lets a legitimate creator sidestep PDA squatting if they are aware of the race risk. However, most tooling/UX (see `client/src/instructions/amm_instructions.rs` and the test helpers) defaults to the deterministic PDA path, so this mitigation is opt-in rather than the default behavior.

### Impact Explanation
An attacker who front-runs `initialize` for a specific `(amm_config, token_0_mint, token_1_mint)` triple only needs to supply the minimum initial liquidity required by the curve to pass `initialize`'s liquidity checks. In exchange, they permanently capture:
- The `pool_creator` role and all future creator-fee revenue accrued from every swap routed through that canonical pool, for the pool's entire lifetime, with no way for the legitimate/intended market maker to reclaim it.
- Denial of the deterministic pool address to the legitimate creator, forcing them onto the less-discoverable `random_pool_id` path or a different `amm_config`.

This is a real, ongoing diversion of protocol-designated fee revenue (an unauthorized privileged effect / fee-ledger accounting harm) reachable from a single attacker-submitted transaction with attacker-chosen accounts, matching the "unauthorized privileged effect" acceptance criterion. Severity is Medium: it requires the attacker to commit real capital (the initial liquidity) and mempool visibility/priority-fee competition, and the deterministic-PDA squatting can be avoided by using `random_pool_id`, which caps the blast radius compared to a zero-cost griefing attack.

### Likelihood Explanation
Exploitation requires monitoring the mempool for `initialize` transactions targeting a specific, presumably valuable token pair (e.g., a new project's official pool) and out-bidding it with a higher priority fee — a standard, low-cost MEV/front-running technique on Solana. Likelihood is moderate: it is economically justified only for token pairs expected to generate meaningful swap volume, which naturally limits the attacker's target set but does not eliminate the risk for popular launches.

### Recommendation
- Bind `pool_creator` to a value that cannot be freely chosen by whoever wins the PDA race — e.g., require the pool's expected creator to be a pre-registered account (via a permission/commitment PDA similar to `initialize_with_permission`'s `PERMISSION_SEED` scheme) before the deterministic-PDA `initialize` path is permitted for that token pair.
- Alternatively, default client tooling to `random_pool_id` for creator-fee-sensitive pools so the deterministic, front-runnable PDA is not the common path, and clearly document the front-running risk of the deterministic PDA path.
- Consider adding an admin-gated `update_pool_creator` recovery mechanism for cases where squatting is proven, though this reintroduces trust assumptions and should be a last resort.

### Proof of Concept
1. Alice (a project team) prepares an `initialize` transaction for her token pair `(mint0, mint1)` under the public `amm_config` at index 0, intending to become `pool_creator` and later earn creator fees via `collect_creator_fee`.
2. Bob observes Alice's transaction in the mempool, computes the same deterministic `pool_state` PDA using `Pubkey::find_program_address([POOL_SEED, amm_config, mint0, mint1])` (see `create_pool` at [7](#0-6) ), and submits his own `initialize` call with the same mints/config and a higher priority fee, supplying the minimal `init_amount_0`/`init_amount_1` needed to pass validation.
3. Bob's transaction lands first; `create_pool` succeeds for Bob's `pool_state` PDA, and `pool_state.initialize(...)` records `pool_creator = Bob` ( [8](#0-7) ).
4. Alice's identical transaction fails because the PDA account already exists/is initialized.
5. From then on, every swap through this canonical pool accrues creator fees to `creator_fees_token_0`/`creator_fees_token_1` ( [6](#0-5) ), which only Bob (as `pool_creator`) can withdraw via `collect_creator_fee`/`collect_creator_fee_permissionless` ( [4](#0-3)  and [5](#0-4) ), permanently diverting revenue away from Alice.

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L240-251)
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

    let mut observation_state = ctx.accounts.observation_state.load_init()?;
    observation_state.pool_id = ctx.accounts.pool_state.key();
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L376-388)
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

    if pool_account_info.key() != expect_pda_address {
        require_eq!(pool_account_info.is_signer, true);
    }
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

**File:** programs/cp-swap/src/states/pool.rs (L326-352)
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
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L9-13)
```rust
#[derive(Accounts)]
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
