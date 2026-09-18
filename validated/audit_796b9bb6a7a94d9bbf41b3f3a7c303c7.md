### Title
Unchecked `creator` account in `initialize_with_permission` lets the payer permanently misassign / freeze pool creator trading fees - ([File: programs/cp-swap/src/instructions/initialize_with_permission.rs])

### Summary
In `InitializeWithPermission`, the `creator` account is declared as a plain `UncheckedAccount<'info>` with **no signer requirement and no address/ownership constraint at all**, unlike the analogous `Initialize` instruction where `creator` is the funding `Signer`. The value supplied for this account is nonetheless written directly into `pool_state.pool_creator`, the field that gates all future creator-fee claims. [1](#0-0) [2](#0-1) 

### Finding Description
`pool_state.pool_creator` is the sole authority checked later by `CollectCreatorFee` (`address = pool_state.load()?.pool_creator`, requiring `creator` to sign) and is the ATA authority used in `CollectCreatorFeePermissionless`: [3](#0-2) [4](#0-3) 

Whoever holds a `Permission` PDA can call `initialize_with_permission` as `payer` and supply an arbitrary `creator` pubkey — the account has zero constraints (no `signer`, no `address ==`, no relation to `payer` or to `permission.authority`) — and that arbitrary pubkey is unconditionally persisted as `pool_creator`: [5](#0-4) 

This is directly analogous to the reported bug class: a role that is supposed to act on behalf of/at the direction of an intended beneficiary is instead able to unilaterally assign a critical access-control field (here, the fee-claiming identity) without any check or consent from that beneficiary, exactly as `BLACKLISTER_ROLE` could unilaterally lock out the real owner in the original report.

### Impact Explanation
Because `creator` is never required to sign, own a keypair, or match any known account, the payer can:
- Set `pool_creator` to an address with no discoverable private key (e.g., a PDA of another program, a vanity/burn-style address, or any account they don't control). `collect_creator_fee` then becomes permanently uncallable (it requires `creator`'s signature), and `collect_creator_fee_permissionless` will keep depositing accrued trade fees into an ATA owned by that unreachable authority. The pool's creator-fee share becomes permanently frozen/unclaimable.
- Alternatively, redirect all creator-fee revenue from the intended, legitimately permissioned pool creator to an address of the payer's own choosing, an unauthorized privileged effect on the pool's fee-ledger accounting.

This is a fee-ledger/fund-freezing issue directly reachable through the listed entry point `initialize_with_permission`, with no privileged signer required beyond holding a `Permission` PDA (which is the intended, non-admin actor for this instruction).

### Likelihood Explanation
High likelihood: no special conditions are needed beyond calling `initialize_with_permission` with attacker-chosen account data for the `creator` field; the transaction succeeds because Anchor performs no validation on that account.

### Recommendation
Constrain the `creator` account in `InitializeWithPermission`, e.g., require it to equal `permission.authority` (the entity the `Permission` PDA was actually granted to), or require `creator` to be a `Signer` acknowledging the assignment, mirroring the trust model used in `Initialize` where the fee-beneficiary and the transaction signer are the same, verified account.

### Proof of Concept
1. Admin creates a `Permission` PDA for `payer_pubkey` via `create_permission_pda`.
2. `payer_pubkey` calls `initialize_with_permission`, supplying:
   - `payer` = `payer_pubkey` (signs, funds pool, receives LP tokens — correct)
   - `creator` = `attacker_controlled_or_unreachable_pubkey` (any account, no signature, no ownership check)
3. `pool_state.initialize(...)` stores `pool_creator = creator.key()` unconditionally.
4. All subsequent `collect_creator_fee` calls fail (signer mismatch) if the chosen `creator` has no keypair, and `collect_creator_fee_permissionless` keeps funneling accrued creator fees into an ATA whose authority no one can move funds from — permanently freezing that portion of pool revenue, or diverting it to an address never intended to receive it.

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L11-13)
```rust
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
