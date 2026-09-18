## Title
Missing address validation on `creator` in `InitializeWithPermission` permanently locks creator-fee funds - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` accepts an arbitrary, unchecked `creator` account and stores it directly as `pool_state.pool_creator`, exactly the pattern flagged in the referenced report (an admin/caller-supplied recipient address used without any validity check). Unlike `initialize.rs`, where `creator` is a `Signer` (and thus inherently a real, key-holding account), here `creator` is a plain `UncheckedAccount` that is never required to sign, never checked against `Pubkey::default()`, and never checked to be a valid, controllable address.

### Finding Description
In `InitializeWithPermission`, the `creator` field has no ownership/signer/non-default constraint: [1](#0-0) 

This value is passed straight into `PoolState::initialize`, which stores it verbatim as `pool_creator`: [2](#0-1) [3](#0-2) 

`pool_creator` is subsequently the sole recipient of the pool's accumulated creator fees, reachable via both the creator-gated `collect_creator_fee` and the fully permissionless `collect_creator_fee_permissionless`: [4](#0-3) [5](#0-4) 

Both collection paths derive an associated token account keyed to `pool_creator` and transfer the fees there — if `pool_creator` is `Pubkey::default()` (or any other address with no reachable owning key), the ATA is a valid, initializable PDA, so the transfer succeeds mechanically, but nobody can ever control or move the tokens out of it. Compare this to `set_new_protocol_owner`/`set_new_fund_owner` in `update_config.rs`, which the codebase itself already guards with `require_keys_neq!(new_owner, Pubkey::default())`: [6](#0-5) 

No equivalent check exists for `creator` in `initialize_with_permission.rs`, so the same class of bug (unvalidated fee-recipient address) that the report calls out for `RubiconFeeController.feeRecipient` is present here.

### Impact Explanation
Every swap through a pool created this way accrues a `creator_fee_rate` share of the trade fee into `creator_fees_token_0` / `creator_fees_token_1` inside `pool_state`. If `pool_creator` is set to `Pubkey::default()` or any other address nobody controls, those accrued fees are permanently locked inside the pool's vaults — they can be transferred out (mechanically, via the permissionless collector) into an unrecoverable ATA, but never spent or reclaimed by anyone. This is a genuine, if narrow, permanent loss of value that is siphoned from every trader who pays the creator-fee portion of the trade fee on that pool, matching the "fees being misdirected or lost" impact described in the analog report.

### Likelihood Explanation
The caller of `initialize_with_permission` must hold a pre-created `Permission` PDA, so this is not open to a fully anonymous attacker, but it is not admin-only either — it's exercised by whatever accounts the protocol has approved as permissioned pool creators, and the `creator` field they supply is entirely unconstrained and independent of the signing `payer`. A misconfigured/malicious permissioned caller (or simple integration error) can set `creator` to `Pubkey::default()` or any unreachable address with a single transaction, with no on-chain check preventing it.

### Recommendation
Add an explicit check that `creator.key() != Pubkey::default()` (and consider requiring `creator` to be a `Signer`, or at minimum validating it is not a non-owned/system-only sentinel address) before calling `PoolState::initialize`, mirroring the `require_keys_neq!` pattern already used for `protocol_owner`/`fund_owner` in `update_config.rs`.

### Proof of Concept
1. Obtain a `Permission` PDA (approved caller) and call `initialize_with_permission` with `creator = Pubkey::default()`.
2. `pool_state.pool_creator` is set to the zero address; the pool is created and trading proceeds normally.
3. As swaps occur, `creator_fees_token_0/1` accumulate per the pool's `creator_fee_rate`.
4. Anyone calls `collect_creator_fee_permissionless`; the ATA derived for `authority = Pubkey::default()` is created and the accrued fees are transferred into it.
5. Because no private key exists for `Pubkey::default()`, the transferred tokens are permanently unrecoverable — a real, on-chain, irreversible loss of the creator-fee portion of every trade on that pool.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L26-27)
```rust
    /// CHECK: creator of pool
    pub creator: UncheckedAccount<'info>,
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

**File:** programs/cp-swap/src/states/pool.rs (L134-153)
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

**File:** programs/cp-swap/src/instructions/admin/update_config.rs (L63-73)
```rust
fn set_new_protocol_owner(amm_config: &mut Account<AmmConfig>, new_owner: Pubkey) -> Result<()> {
    require_keys_neq!(new_owner, Pubkey::default());
    #[cfg(feature = "enable-log")]
    msg!(
        "amm_config, old_protocol_owner:{}, new_owner:{}",
        amm_config.protocol_owner.to_string(),
        new_owner.key().to_string()
    );
    amm_config.protocol_owner = new_owner;
    Ok(())
}
```
