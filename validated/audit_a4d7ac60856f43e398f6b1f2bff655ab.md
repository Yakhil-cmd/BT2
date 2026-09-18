### Title
Unauthenticated `creator` identity in `initialize_with_permission` lets payer spoof pool-creator privilege, permanently freezing creator fees - (File: programs/cp-swap/src/instructions/initialize_with_permission.rs)

### Summary
`initialize_with_permission` stores an arbitrary, attacker-supplied `creator` pubkey as `pool_state.pool_creator` without requiring that pubkey to sign or otherwise prove ownership of the identity, unlike the equivalent field in the standard `Initialize` accounts struct. This spoofed identity is later relied upon as the sole authorization gate for collecting creator fees, mirroring the "Authentication Bypass by Spoofing" class where a relayed, unverified identity is trusted by a privileged downstream consumer.

### Finding Description
In `Initialize` (the permissionless pool-creation path), the creator identity is cryptographically bound to the actual transaction signer: [1](#0-0) 

In `InitializeWithPermission`, however, `creator` is declared as an `UncheckedAccount` with no `Signer` requirement and no constraint tying it to `payer` (the actual signer who funds the pool and must hold a valid `Permission` PDA): [2](#0-1) 

Despite this lack of authentication, the handler unconditionally persists `ctx.accounts.creator.key()` as the pool's `pool_creator` field: [3](#0-2) 

This stored, unauthenticated identity is later trusted as the sole privilege gate in `CollectCreatorFee`, which requires the signer's address to equal `pool_state.pool_creator`: [4](#0-3) 

and as the unauthenticated fund-recipient identity in `CollectCreatorFeePermissionless`, which forwards accumulated fees to an ATA owned by `pool_state.pool_creator` without requiring that key to sign at all: [5](#0-4) 

Because the `payer` (who only needs a valid `Permission` PDA keyed to their own pubkey, see `PERMISSION_SEED` constraint) can pass any `creator` account they like without that account signing or proving any relation to `payer`, they can nominate a pubkey that has no known private key (e.g., a burn address, an unrelated PDA, or any vanity address they generate offline but never intend to control). That address becomes the permanent, unchangeable `pool_creator` for the pool. All creator fees subsequently accrued (`pool_state.creator_fees_token_0/1`, incremented on every swap through the fee-split logic) can only be claimed by whoever signs as that address in `CollectCreatorFee`, or land in an ATA owned by that address via the permissionless path — with no mechanism in the program to change `pool_creator` afterward.

### Impact Explanation
If the spoofed `creator` pubkey has no corresponding keypair, all creator fees for the pool's lifetime are permanently frozen once routed through `collect_creator_fee_permissionless` (tokens sent to an ATA whose owner never signs anything and can never move them), and `collect_creator_fee` can never succeed since no one can produce that signature. This satisfies "permanent freezing of user or LP funds." Alternatively, the payer can spoof the identity of an unrelated third-party wallet they do not control, silently assigning that wallet perpetual rights to collect the pool's creator fees — an unauthorized privileged effect granted to a non-consenting identity, directly analogous to the spoofed-identity/authentication-bypass bug class in the reference report.

### Likelihood Explanation
Exploitation requires only a single call to `initialize_with_permission` by any account holding (or granted) a `Permission` PDA, and passing an attacker-chosen `creator` account key in the instruction's account list — no cryptographic proof of ownership over that key is enforced anywhere in the accounts struct or handler. This is fully reachable from a single submitted transaction with attacker-chosen accounts and data, matching the validation criteria.

### Recommendation
Require `creator` in `InitializeWithPermission` to either be a `Signer` (mirroring `Initialize`), or add an explicit constraint proving consent/ownership (e.g., a signed message or a dedicated `creator` signature check), so the `pool_creator` identity stored in `PoolState` can never be set to an unverified, non-consenting pubkey.

### Proof of Concept
1. Attacker (or any account) obtains a `Permission` PDA for their own `payer` key via `create_permission_pda` (requires only the protocol's `create_permission_pda_owner` to have created it for them, or is otherwise attacker-controlled per deployment policy).
2. Attacker calls `initialize_with_permission`, supplying:
   - `payer` = attacker's own signing keypair (holds the valid `Permission` PDA).
   - `creator` = an arbitrary pubkey the attacker generated offline and does not hold the private key for (or an unrelated victim's wallet address), passed as a plain, non-signing account.
3. The instruction succeeds: `pool_state.pool_creator` is set to the attacker-chosen, non-consenting pubkey (`programs/cp-swap/src/instructions/initialize_with_permission.rs:361`).
4. Swaps occur against the pool, accruing `creator_fees_token_0`/`creator_fees_token_1`.
5. Anyone calls `collect_creator_fee_permissionless`; funds are transferred into an ATA owned by the spoofed `creator` address (`collect_creator_fee_permissionless.rs:17-20`), which — if that key has no matching keypair — can never be moved again, permanently freezing those funds; or, if it is a real third-party wallet, that party now silently gains a valid, un-consented claim on future fee-collection rights via `collect_creator_fee`.

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L21-24)
```rust
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
```

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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L17-20)
```rust
    /// The pool creator that receives the collected creator fees
    /// CHECK: the address is constrained to the `pool_creator` recorded in `pool_state`
    #[account(address = pool_state.load()?.pool_creator)]
    pub creator: UncheckedAccount<'info>,
```
