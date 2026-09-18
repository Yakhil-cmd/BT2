### Title
Pool creator role can be assigned to an arbitrary, non-consenting address in `initialize_with_permission`, permanently freezing creator fees - (File: programs/cp-swap/src/instructions/initialize_with_permission.rs)

### Summary
`initialize_with_permission` lets a whitelisted `payer` create a pool and freely choose the `creator` account that becomes `pool_state.pool_creator`. The `creator` account is an `UncheckedAccount` that is never required to sign, nor is it validated against the `payer` or the `permission` PDA authority, so a caller can attribute pool ownership (and its associated fee-collection privilege) to any address without that address's consent.

### Finding Description
In `InitializeWithPermission`, the account list contains: [1](#0-0) 
`creator` is only `UncheckedAccount<'info>` — no `Signer` requirement, no `address =` or `constraint =` tying it to `payer` or to `permission.authority`. The `permission` PDA is derived only from `payer.key()`: [2](#0-1) 
so the permission gate only proves the *payer* is whitelisted (via `create_permission_pda`, which is admin-gated: [3](#0-2) ), not that the named `creator` consented to being recorded as the pool's owner.

At the end of the handler, the arbitrary `creator` key is written straight into `pool_state.pool_creator`: [4](#0-3) 
via `PoolState::initialize`, which stores it verbatim: [5](#0-4) 

`pool_creator` is a privileged role: `collect_creator_fee` requires the signer to equal `pool_state.pool_creator`, and `collect_creator_fee_permissionless` sends the accumulated creator fees to an ATA whose authority is `pool_creator`: [6](#0-5) [7](#0-6) 

Since no signature or link is required from `creator` at pool-creation time, a payer can pass any pubkey — including one whose private key nobody controls (e.g., a vanity/PDA-like account, a known project's public address, a burn address, or simply a randomly generated keypair the attacker discards) — as the pool's `pool_creator`.

### Impact Explanation
Two concrete, non-reputational consequences follow directly from this:
1. **Permanent freezing of creator fee funds**: If `creator` is set to an address with no reachable signer (e.g., a keypair whose secret is discarded, or any PDA that cannot sign a `CollectCreatorFee` transaction), `collect_creator_fee` can never succeed since it requires `creator` to sign, and `collect_creator_fee_permissionless` will move the fees to an ATA owned by that unreachable authority — funds become permanently unrecoverable, an insolvent/locked fee ledger.
2. **Unauthorized privileged effect / impersonation**: A payer can assign a real third party's address as `pool_creator` without their consent, granting that address the on-chain privilege to collect creator fees on a pool it never created or authorized, and creating the false on-chain impression that the pool is endorsed by that party — mirroring the original Gitcoin `RoundFactory` finding where a round could be created under an arbitrary `ownedBy` program without consent.

### Likelihood Explanation
Any account holding a valid `permission` PDA (obtained once from the admin-controlled `create_permission_pda`) can call `initialize_with_permission` and freely choose `creator` with a single transaction and attacker-controlled account inputs — no additional privilege or race condition is required, only that the caller is already a permitted pool creator, which is the intended audience of this instruction.

### Recommendation
Require the `creator` account to be a `Signer` (matching the original permissionless `initialize` flow, where `creator` is the transaction signer) or otherwise cryptographically prove consent (e.g., an off-chain signature verified on-chain, or requiring `creator == payer` unless a separate authorization/allow-list record exists), before writing it into `pool_state.pool_creator`.

### Proof of Concept
1. Payer `P` (holding a valid `permission` PDA) constructs an `initialize_with_permission` transaction.
2. `P` sets the `creator` account field to `V`, an address of `P`'s choosing (either a real third party's public key or a discardable keypair), without any signature from `V`.
3. The instruction executes successfully; `pool_state.pool_creator = V` is recorded, see `pool_state.initialize(..., ctx.accounts.creator.key(), ...)` at `programs/cp-swap/src/instructions/initialize_with_permission.rs:357-372`.
4. As swaps accrue creator fees into `pool_state.creator_fees_token_0/1`, only a signature from `V` (via `collect_creator_fee`) or a transfer into an ATA owned by `V` (via `collect_creator_fee_permissionless`) can release them; if `V`'s key is unreachable, those fees are permanently locked, and if `V` is a real uninvolved party, the pool falsely appears to be created/owned by them.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L20-27)
```rust
#[derive(Accounts)]
pub struct InitializeWithPermission<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: creator of pool
    pub creator: UncheckedAccount<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L153-161)
```rust
    /// CHECK: PDA account used for permission verification.
    #[account(
        seeds = [
            PERMISSION_SEED.as_bytes(),
            payer.key().as_ref(),
        ],
        bump,
    )]
    pub permission: Box<Account<'info, Permission>>,
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

**File:** programs/cp-swap/src/instructions/admin/create_permission_pda.rs (L14-20)
```rust
#[derive(Accounts)]
pub struct CreatePermissionPda<'info> {
    #[account(
        mut,
        constraint = (owner.key() == crate::admin::ID || owner.key() == crate::create_permission_pda_owner::ID) @ ErrorCode::InvalidOwner
    )]
    pub owner: Signer<'info>,
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
