### Title
`initialize_with_permission` lets the caller set `pool_creator` to an uncontrolled address (including `Pubkey::default()`), permanently freezing creator fees - (File: programs/cp-swap/src/instructions/initialize_with_permission.rs)

### Summary
`InitializeWithPermission::creator` is declared as an `UncheckedAccount` with no signer requirement and no zero/validity check. Its key is written directly into `PoolState.pool_creator` via `pool_state.initialize(...)`. Because `enable_creator_fee` is hard-coded to `true` for this path, the pool immediately starts accruing `creator_fees_token_0/1`, but if `creator` is set to an address nobody controls (e.g. `Pubkey::default()`, which is numerically identical to the System Program ID), those accrued fees become permanently unrecoverable. This is the direct analog of the reported `LibOwnable._setAdmin` bug class: a critical "owner/authority" field is populated from unvalidated attacker-controlled input with no zero-address guard, silently disabling functionality gated on that role.

### Finding Description
In `initialize_with_permission.rs`, `creator` is only constrained as an `UncheckedAccount`: [1](#0-0) 

It is used, unchecked, as the `pool_creator` when initializing pool state: [2](#0-1) 

`enable_creator_fee` is hard-coded `true` in this instruction (unlike `initialize.rs`, which passes `false`), so the pool starts accumulating creator fees from the first swap: [3](#0-2) 

`pool_creator` is later relied upon by both fee-collection paths:
- `collect_creator_fee` requires the caller to be a `Signer` whose address equals `pool_creator`: [4](#0-3) 
- `collect_creator_fee_permissionless` lets anyone trigger the transfer, but funds are always routed into an ATA whose authority is the unvalidated `creator`/`pool_creator` address: [5](#0-4) [6](#0-5) 

If `pool_creator == Pubkey::default()` (the all-zero pubkey, which is also the System Program's address), there is no corresponding keypair, so `collect_creator_fee`'s signer constraint can never be satisfied. `collect_creator_fee_permissionless` will still succeed (no signer check on `creator`), creating a legitimate ATA whose `authority` is the System Program address and transferring the accrued fees there — an account no one can ever move funds out of.

### Impact Explanation
Creator fees swept out of the pool vaults land in a token account nobody controls, permanently locking those funds (a subset of LP/pool funds carved out specifically as "creator fees"). This is a concrete, permanent freezing of funds triggered from a single instruction call with attacker-chosen account data, matching the required impact bar (permanent freezing of user/LP funds).

### Likelihood Explanation
Anyone who is granted (or reuses) a `Permission` PDA to call `initialize_with_permission` can pass any pubkey — including `Pubkey::default()` — as `creator`, either by mistake (e.g., client bug defaulting to zero) or maliciously to permanently burn future creator fees for that pool (e.g. to grief or as part of a token-launch scheme where the deployer doesn't want reclaimable fees). No special privilege beyond the ability to call this already-reachable instruction is required.

### Recommendation
Add an explicit check in `initialize_with_permission` (and any other instruction that assigns `pool_creator`) rejecting `Pubkey::default()` (and ideally requiring `creator` to be a signer or otherwise attested address), analogous to the `require_keys_neq!(new_owner, Pubkey::default())` checks already present in `update_config.rs`: [7](#0-6) 

### Proof of Concept
1. Obtain a `Permission` PDA for `payer` (via the admin-gated `create_permission_pda`, or use any already-permissioned account).
2. Call `initialize_with_permission` with `creator = Pubkey::default()` (System Program ID) and `creator_fee_on` set to any variant; `enable_creator_fee` is forced `true` internally.
3. Perform swaps against the pool so that `creator_fees_token_0/1` accumulate in `PoolState`.
4. Call `collect_creator_fee` — it always fails, since no keypair can sign as `Pubkey::default()`.
5. Call `collect_creator_fee_permissionless`, passing `creator = Pubkey::default()` (matches the `address` constraint against `pool_state.pool_creator`). The instruction succeeds, creating an ATA owned by the System Program address and transferring the creator fees into it.
6. The tokens in that ATA can never be withdrawn by anyone, permanently freezing those funds.

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

**File:** programs/cp-swap/src/states/pool.rs (L118-126)
```rust
    /// Creator fee collect mode
    /// 0: both token_0 and token_1 can be used as trade fees. It depends on what the input token is when swapping
    /// 1: only token_0 as trade fee
    /// 2: only token_1 as trade fee
    pub creator_fee_on: u8,
    pub enable_creator_fee: bool,
    pub padding1: [u8; 6],
    pub creator_fees_token_0: u64,
    pub creator_fees_token_1: u64,
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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L61-69)
```rust
    /// The address that receives the collected token_0 creator fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_0_mint,
        associated_token::authority = creator,
        payer = payer,
        associated_token::token_program = token_0_program,
    )]
    pub creator_token_0: Box<InterfaceAccount<'info, TokenAccount>>,
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
