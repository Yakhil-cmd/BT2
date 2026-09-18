### Title
Unvalidated `creator` account in `initialize_with_permission` lets any permissioned payer assign pool-creator fee rights to an arbitrary attacker-controlled address - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
`initialize_with_permission` accepts a `creator` account that is a completely unchecked `UncheckedAccount<'info>` with no `constraint`, `address`, or signer requirement tying it to the transaction signer (`payer`) or to the `permission` PDA used for authorization. [1](#0-0)  The `permission` PDA that gates who may call this instruction is derived from `payer.key()`, not from `creator.key()` [2](#0-1) , yet the value stored in the new pool's `pool_creator` field is taken directly from `ctx.accounts.creator.key()` at the end of the handler. [3](#0-2) 

### Finding Description
This is the direct analog of CVE-2026-5708's root cause: a privileged/consequential attribute (`pool_creator`, analogous to the RES session owner/instance-profile binding) is taken from a caller-supplied account that is never validated to be the actual authorizing principal. The instruction is guarded only by the `permission` account seeded with `payer`'s key [2](#0-1) , which merely confirms `payer` is on some allow-list — it says nothing about `creator`. A caller with valid `payer` permission can pass any arbitrary pubkey (attacker's own wallet, a victim's wallet, or a wallet they don't even control) as the `creator` account, since it carries no `#[account(...)]` constraints at all, not even ownership or signer checks.

`pool_creator` subsequently becomes the sole authority permitted to call `collect_creator_fee`, which is gated with `address = pool_state.load()?.pool_creator` on the `creator` signer. [4](#0-3)  Because `pool_creator` is set from an unchecked, attacker-chosen input during pool creation rather than being forced to equal `payer` (the entity that actually proved permission and paid for the pool), the binding between "who is authorized to create/fund the pool" and "who receives ongoing creator fee revenue" is broken — precisely the "improper control of user-modifiable attributes" pattern in the reference CVE, where an attribute that should be system-derived (tied to the authenticated principal) is instead accepted verbatim from client input.

Contrast this with `initialize` (the non-permissioned variant), which correctly binds the pool_creator to the actual signer: `ctx.accounts.creator.key()` there refers to the `Signer<'info>` who pays for the pool. [5](#0-4)  `initialize_with_permission` deliberately splits `payer` (signer, permission-checked) from `creator` (unchecked, arbitrary) but then uses the unchecked `creator` for the privileged `pool_creator` assignment. [3](#0-2) 

### Impact Explanation
Any pubkey the attacker chooses is granted `pool_creator` status on the newly created pool, giving it exclusive rights to `collect_creator_fee`/`collect_creator_fee_permissionless` for that pool's accumulated `creator_fees_token_0`/`creator_fees_token_1`. This is a privileged-role assignment vulnerability: an unprivileged (but permission-listed) `payer` can hijack the creator-fee stream of a pool by naming themselves (or an accomplice address) as `creator` regardless of who actually is meant to receive it, or conversely grief a legitimate creator by pointing `pool_creator` at an unrelated/unreachable address, permanently misdirecting or freezing future creator fee collection for that pool (funds accumulate in `pool_state.creator_fees_token_0/1` but only the wrong, attacker-chosen key can ever withdraw them). This matches the required impact bar of "unauthorized privileged effect" / permanent freezing or misdirection of LP/creator funds.

### Likelihood Explanation
High. The instruction is reachable by any account holding a `Permission` record (i.e., any address the protocol has already approved to create permissioned pools) with a single transaction; no special timing, race condition, or non-default feature build is required. The only prerequisite is being a permission-listed payer, which is an intended (not privileged-admin) capability of this public-facing instruction — the vulnerability is that this capability is silently escalated into control over an unrelated `creator` attribute.

### Recommendation
Constrain the `creator` account in `InitializeWithPermission` so it cannot be an arbitrary attacker-supplied value: either require `creator` to equal `payer` (mirroring `initialize`), or require `creator` to be a `Signer` (proving consent), or derive/verify `creator` against the `permission` PDA that actually authorized the call. At minimum add an explicit `#[account(constraint = ...)]` binding `creator` to a value that reflects genuine authorization rather than trusting caller-supplied account metadata as done for `pool_creator` in `pool_state.initialize(...)`. [3](#0-2) 

### Proof of Concept
1. Attacker (or any address holding a `Permission` PDA seeded by their own pubkey) calls `initialize_with_permission` as `payer` with a valid `permission` account. [2](#0-1) 
2. Attacker sets the `creator` account field to their own second wallet (or any pubkey), which passes because no constraint validates it. [1](#0-0) 
3. `pool_state.initialize(...)` stores this attacker-chosen pubkey as `pool_creator`. [3](#0-2) 
4. As swap activity accrues `creator_fees_token_0/1` on the pool, only the attacker's chosen `creator` key — validated via `address = pool_state.load()?.pool_creator` — can sign `collect_creator_fee` and withdraw those fees. [4](#0-3)

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L26-27)
```rust
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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L10-13)
```rust
pub struct CollectCreatorFee<'info> {
    /// Only pool creator can collect fee
    #[account(mut, address = pool_state.load()?.pool_creator)]
    pub creator: Signer<'info>,
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-24)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```
