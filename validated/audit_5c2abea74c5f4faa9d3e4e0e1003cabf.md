### Title
Missing validation of `pool_creator` in `initialize_with_permission` permanently locks/mis-routes accrued creator fees - ([File: programs/cp-swap/src/instructions/initialize_with_permission.rs])

### Summary
`initialize_with_permission` accepts an arbitrary, unvalidated `creator` account and stores its pubkey verbatim as `pool_state.pool_creator`, the value later used as the sole authorization check for withdrawing all accumulated creator fees. Analogous to the reported `OsTokenConfig` bug (an unchecked "owner" parameter that can be set to `address(0)`, permanently disabling `onlyOwner` functionality), an unchecked `pool_creator` can be set to a non-signable/attacker-uncontrolled pubkey, permanently disabling `collect_creator_fee` and permanently freezing the pool's accrued creator fees for legitimate use.

### Finding Description
In `InitializeWithPermission`, the `creator` field is declared as a bare `UncheckedAccount` with no signer requirement, no `address` constraint, and no zero-check: [1](#0-0) 

This attacker/pool-payer-supplied value is passed directly into `pool_state.initialize(...)` and permanently persisted as `pool_creator`: [2](#0-1) 

`pool_creator` is the sole field in `PoolState` used to gate withdrawal of creator fees: [3](#0-2) 

`CollectCreatorFee` requires `creator` to be a `Signer` whose key equals `pool_state.pool_creator`: [4](#0-3) 

Because `pool_creator` is never validated at pool creation time (no check that it is a plausible/controllable signer, non-zero, non-PDA, etc.), any `payer` calling `initialize_with_permission` can set `creator` to `Pubkey::default()`, a PDA of this or another program, a token/mint account, or any other address that can never produce a valid transaction signature. Once persisted, `collect_creator_fee` can never succeed for that pool because no valid `Signer` matching that pubkey can ever exist. `collect_creator_fee_permissionless` also derives its ATA authority from the same unvalidated `pool_creator` field: [5](#0-4) 

so even the "permissionless" collection path only ever routes fees to whatever (potentially unowned/inaccessible) address was set at initialization — it does not add any recovery mechanism if that address is unable to receive/claim funds meaningfully (e.g., a PDA no wallet controls, or the zero pubkey, which is a valid System-Program-owned account that no one holds the private key for).

This mirrors the reported class of bug precisely: an authority-defining field is accepted from an unprivileged, single-transaction caller without a zero-address/sanity check, and once persisted it permanently disables the privileged (`onlyOwner`-equivalent, i.e. `creator`-signer-gated) functionality tied to it.

### Impact Explanation
Trade/creator fees continuously accumulate in `pool_state.creator_fees_token_0` / `creator_fees_token_1` for every swap routed through the pool. If `pool_creator` is set to an address that can never sign (e.g. `Pubkey::default()` or a PDA), those accrued fees become permanently unrecoverable/frozen inside the pool's vaults — no instruction path exists to reassign `pool_creator` or reclaim the funds. This is a permanent freezing of protocol/LP-adjacent funds (creator fee revenue), satisfying the "permanent freezing of user or LP funds" acceptance criterion.

### Likelihood Explanation
`initialize_with_permission` is reachable by any account holding a valid `Permission` PDA (a "pool creator" role in the in-scope reachable-instruction list), and the `creator` field is entirely attacker-supplied with zero validation, requiring only a single transaction with an arbitrary account passed for `creator`. This can happen either through attacker intent or simple misconfiguration/tooling error (e.g., passing the wrong keypair's pubkey or a placeholder default value), matching the "accidental error" likelihood profile described in the source report.

### Recommendation
Add an explicit constraint requiring `creator.key() != Pubkey::default()` in `InitializeWithPermission`, and/or require `creator` to be a `Signer` (or otherwise co-sign/attest ownership) so a non-controllable address cannot be silently locked in as the fee-collection authority. At minimum, reject `Pubkey::default()` and any known non-signable program-owned addresses before persisting `pool_creator` in `pool_state.initialize(...)`.

### Proof of Concept
1. Caller obtains a valid `Permission` PDA (permissioned pool creation).
2. Caller invokes `initialize_with_permission`, supplying `creator = Pubkey::default()` (or any PDA belonging to a different program) as the `creator` account — no constraint rejects this.
3. Pool is created successfully; `pool_state.pool_creator` is set to the unsignable address: [2](#0-1) 
4. Swaps occur against the pool, accruing `creator_fees_token_0`/`creator_fees_token_1`.
5. Any attempt to call `collect_creator_fee` fails permanently because no `Signer` can ever match `pool_state.pool_creator`: [4](#0-3) 
6. Accrued creator fees remain frozen in the pool vaults indefinitely, with no instruction available to reassign or reclaim them.

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
