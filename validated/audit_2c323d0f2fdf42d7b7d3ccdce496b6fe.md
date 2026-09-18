## Analog Vulnerability Found

### Title
Unvalidated `creator` account in `initialize_with_permission` allows setting `pool_creator` to an unowned/system-program address, permanently freezing creator fees - (File: `programs/cp-swap/src/instructions/initialize_with_permission.rs`)

### Summary
The `InitializeWithPermission` accounts struct accepts a `creator` field as a completely unchecked, non-signing account, which is then stored verbatim as `pool_state.pool_creator`. Because this address is never validated (no signer requirement, no "not default/zero pubkey" check, no relation enforced to `payer`), a permissioned pool creator can set it to `Pubkey::default()` (Solana's "zero address", which is also the System Program ID) or any other address nobody controls, permanently locking all future creator fees accrued by the pool.

### Finding Description
In `initialize_with_permission.rs`, the `creator` account is declared with no constraints at all: [1](#0-0) 

This value is passed straight into `pool_state.initialize(...)` and persisted as `pool_creator`: [2](#0-1) 

`pool_creator` is a permanent `Pubkey` field on `PoolState`: [3](#0-2) 

This field later gates the only two ways to withdraw accumulated creator trading fees. `collect_creator_fee` requires the `creator` signer to match `pool_creator` exactly: [4](#0-3) 

and `collect_creator_fee_permissionless` sends fees to an ATA owned by whatever `pool_creator` was recorded, regardless of who calls it: [5](#0-4) 

If `pool_creator` is set to `Pubkey::default()` (or any address with no known private key, e.g. the System Program's own ID), `collect_creator_fee` can never succeed because nobody can produce a valid signature for that address, and `collect_creator_fee_permissionless` will simply mint the funds into an ATA that is permanently unreachable (owned by an address with no signing key). Every swap that accrues `creator_fees_token_0` / `creator_fees_token_1` on that pool becomes unrecoverable.

This is a direct on-chain analog of the reported class of bug: a privileged/administrative-style account setter with no zero-address (or "unspendable address") validation, leading to permanent loss/freezing of protocol funds. Note that unlike `initialize.rs` — where `creator` is a required `Signer` and thus practically cannot be an address without a private key — `initialize_with_permission.rs` deliberately decouples `creator` from any signer or transaction-sender check, making the zero/burn-address assignment trivially reachable in a single transaction by whoever is permitted to call this instruction.

### Impact Explanation
Setting `pool_creator` to an uncontrollable address permanently freezes all accrued creator fees for that pool — every subsequent swap that routes trade fees to the creator bucket accrues funds that can never be withdrawn by anyone. This is a permanent freezing of protocol/user funds, matching the High severity of the original report (loss of funds due to missing zero-address validation on a persisted, fee-recipient-controlling address).

### Likelihood Explanation
Any account permitted to call `initialize_with_permission` (i.e., holding a valid `Permission` PDA) fully controls the `creator` field value with a single instruction call — no additional privilege, race condition, or complex setup is required. The mistake is trivial to make (e.g., leaving the field as `Pubkey::default()`, a common placeholder) and equally trivial to exploit maliciously to permanently strand fees.

### Recommendation
Add an explicit constraint on the `creator` account in `InitializeWithPermission` to reject `Pubkey::default()` (and ideally require it be a real, funded/system-owned wallet or require it to sign like in `initialize.rs`):
```rust
#[account(constraint = creator.key() != Pubkey::default() @ ErrorCode::InvalidCreator)]
pub creator: UncheckedAccount<'info>,
```
Alternatively, require `creator` to be a `Signer` consistent with the permissionless `initialize` path, ensuring the recorded `pool_creator` is always an address capable of authorizing `collect_creator_fee`.

### Proof of Concept
1. Attacker (or careless integrator) obtains a valid `Permission` PDA via `create_permission_pda` (whatever the permission-granting flow requires).
2. Attacker calls `initialize_with_permission`, supplying `creator = Pubkey::default()` (or any address with no known keypair) while `payer` is their own wallet supplying the initial liquidity.
3. `pool_state.pool_creator` is set to `Pubkey::default()` per [6](#0-5) .
4. Normal swaps occur on the pool, accruing `creator_fees_token_0`/`creator_fees_token_1`.
5. `collect_creator_fee` can never be called (no signer exists for `Pubkey::default()`), and `collect_creator_fee_permissionless` deposits the fees into an ATA owned by `Pubkey::default()`, which is permanently inaccessible — the accrued creator fees are frozen forever.

### Citations

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L21-27)
```rust
pub struct InitializeWithPermission<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub payer: Signer<'info>,

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

**File:** programs/cp-swap/src/states/pool.rs (L66-70)
```rust
pub struct PoolState {
    /// Which config the pool belongs
    pub amm_config: Pubkey,
    /// pool creator
    pub pool_creator: Pubkey,
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
