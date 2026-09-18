## Analog Found

### Title
Permissionless pool creation allows freeze-authority-retained mints, letting an attacker permanently freeze both tokens' vaults and lock all LPs' funds - (File: programs/cp-swap/src/instructions/initialize.rs, programs/cp-swap/src/utils/token.rs)

### Summary
The OpenQ report describes a malicious, non-whitelisted token being accepted to "fund" a claimable position, and that token's revert-on-transfer behavior then blocks withdrawal of *all* tokens (including legitimate ones) bundled with it. The analogous root cause here is that `initialize`/`initialize_with_permission` accept **any** SPL Token or Token-2022 mint pair as `token_0_mint`/`token_1_mint` with no vetting of the mint's freeze authority, and both `withdraw` and `swap_base_input`/`swap_base_output` perform `transfer_checked` calls straight from the pool vaults without any check that the vault token account is not frozen.

### Finding Description
Any unprivileged user can call `initialize` to create a brand-new pool for an arbitrary token pair. The only mint-level check performed is `is_supported_mint`, which merely filters Token-2022 *extension types* (rejecting `TransferHook`, etc.) — it does **not** inspect or reject mints that retain a `freeze_authority`: [1](#0-0) 

`initialize` calls `is_supported_mint` for both mints and otherwise imposes no restriction on the mint's freeze authority: [2](#0-1) 

Once the pool is created and other LPs deposit real value (e.g., depositing a legitimate `token_1` alongside the attacker's malicious `token_0`), the attacker — who controls the freeze authority of their own mint — can submit an SPL `FreezeAccount` instruction against the pool's `token_0_vault`. Both `withdraw` and the swap instructions unconditionally attempt `transfer_checked` from the vaults with no frozen-account guard: [3](#0-2) [4](#0-3) 

`transfer_checked` on a frozen token account fails at the SPL Token/Token-2022 program level, so any transaction touching the frozen vault reverts. Since Solana instructions in `withdraw` execute both the `token_0` and `token_1` transfers atomically within the same instruction, freezing just the malicious `token_0_vault` makes the entire `withdraw` call permanently revert — trapping the legitimate `token_1` funds of every LP in the pool alongside the malicious token, exactly mirroring the OpenQ pattern where one bad asset blocks claims for all bundled assets. Swaps into/out of that vault are similarly permanently blocked.

### Impact Explanation
This permanently freezes LP principal (both `token_0` and `token_1`) for every liquidity provider in the affected pool, and blocks all future swaps through that pool. This is a permanent freezing of user/LP funds reachable by any unprivileged actor via a single `initialize` transaction followed by a standard `FreezeAccount` instruction, warranting a High severity classification.

### Likelihood Explanation
Likelihood is high: pool creation is fully permissionless (`initialize`), the attacker needs only to mint a standard SPL Token or Token-2022 mint while keeping (not revoking) the freeze authority, and no code path in `initialize`, `initialize_with_permission`, `deposit`, `withdraw`, or the swap instructions ever validates `freeze_authority == None` or checks `TokenAccount.is_frozen()` before or after CPI transfers.

### Recommendation
Reject mints whose `freeze_authority` is `Some(..)` at pool-creation time in `is_supported_mint` (both for the SPL Token and Token-2022 code paths), or require pool creators/governance to explicitly whitelist mints via the existing "support mint" mechanism referenced in `initialize.rs`/`initialize_with_permission.rs`. Consider also checking vault account frozen-state at the start of `swap_base_input`/`swap_base_output`/`withdraw` to fail fast with a clear error rather than relying on the underlying CPI revert.

### Proof of Concept
1. Attacker mints `TokenM` via legacy SPL Token program, retaining `freeze_authority = attacker`.
2. Attacker calls `initialize` (or `initialize_with_permission`) pairing `TokenM` as `token_0` (or `token_1`) with a legitimate, popular mint `TokenL`, seeding the pool with small liquidity. `is_supported_mint` passes because `TokenM` uses the legacy Token program owner check (`Token::id()` short-circuit) at [5](#0-4) .
3. Other LPs are attracted by the `TokenL` side and call `deposit`, adding real `TokenL`/`TokenM` liquidity to the pool's vaults.
4. Attacker submits an SPL Token `FreezeAccount` instruction against the pool's `TokenM` vault (using their retained freeze authority).
5. Any subsequent `withdraw` call fails because `transfer_from_pool_vault_to_user` for the frozen `TokenM` vault reverts, and since both transfers occur in the same instruction, the LP can never withdraw their legitimate `TokenL` share either — funds are permanently frozen. Swaps referencing that vault similarly permanently fail.

### Citations

**File:** programs/cp-swap/src/utils/token.rs (L44-71)
```rust
pub fn transfer_from_pool_vault_to_user<'a>(
    authority: AccountInfo<'a>,
    from_vault: AccountInfo<'a>,
    to: AccountInfo<'a>,
    mint: AccountInfo<'a>,
    token_program: AccountInfo<'a>,
    amount: u64,
    mint_decimals: u8,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    token_2022::transfer_checked(
        CpiContext::new_with_signer(
            *token_program.key,
            token_2022::TransferChecked {
                from: from_vault,
                to,
                authority,
                mint,
            },
            signer_seeds,
        ),
        amount,
        mint_decimals,
    )
}
```

**File:** programs/cp-swap/src/utils/token.rs (L335-360)
```rust
pub fn is_supported_mint(
    mint_account: &InterfaceAccount<Mint>,
    mint_associated_is_initialized: bool,
) -> Result<bool> {
    let mint_info = mint_account.to_account_info();
    if *mint_info.owner == Token::id() {
        return Ok(true);
    }
    if mint_associated_is_initialized {
        return Ok(true);
    }
    let mint_data = mint_info.try_borrow_data()?;
    let mint = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;
    let extensions = mint.get_extension_types()?;
    for e in extensions {
        if e != ExtensionType::TransferFeeConfig
            && e != ExtensionType::MetadataPointer
            && e != ExtensionType::TokenMetadata
            && e != ExtensionType::InterestBearingConfig
            && e != ExtensionType::ScaledUiAmount
        {
            return Ok(false);
        }
    }
    Ok(true)
}
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L188-200)
```rust
    let mint0_associated_is_initialized = support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_0_mint,
    )?;
    let mint1_associated_is_initialized = support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_1_mint,
    )?;
    if !(is_supported_mint(&ctx.accounts.token_0_mint, mint0_associated_is_initialized).unwrap()
        && is_supported_mint(&ctx.accounts.token_1_mint, mint1_associated_is_initialized).unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
    }
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L188-216)
```rust
    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.token_0_account.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        if ctx.accounts.vault_0_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        token_0_amount,
        ctx.accounts.vault_0_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.token_1_account.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        if ctx.accounts.vault_1_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        token_1_amount,
        ctx.accounts.vault_1_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;
```
