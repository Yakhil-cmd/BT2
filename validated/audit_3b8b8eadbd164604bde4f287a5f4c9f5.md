Confirmed root cause. This is a valid analog.

### Title
Pool creator can permit an SPL Token mint with a freeze authority, allowing permanent freezing of vault funds and blocking swap/withdraw - (File: `programs/cp-swap/src/utils/token.rs`)

### Summary
`is_supported_mint` is the only gate that decides which token mints are allowed into a pool at `initialize`/`initialize_with_permission` time. For any mint owned by the legacy SPL `Token` program it unconditionally returns `true` without inspecting whether the mint has a `freeze_authority` set. This mirrors the report's bug class where an externally-controlled, pausable asset (CryptoKitty/CryptoFighter NFTs) can be frozen by a third party, blocking a protocol's critical recovery actions (repay/liquidate). Here the "pausable asset" is a token mint whose freeze authority can freeze the pool's vault `TokenAccount`, blocking `swap`/`withdraw` for every LP in that pool.

### Finding Description
`is_supported_mint` at [1](#0-0)  immediately approves any mint owned by the classic SPL `Token` program:
```rust
pub fn is_supported_mint(
    mint_account: &InterfaceAccount<Mint>,
    mint_associated_is_initialized: bool,
) -> Result<bool> {
    let mint_info = mint_account.to_account_info();
    if *mint_info.owner == Token::id() {
        return Ok(true);
    }
```
No check is performed on `mint.freeze_authority`. This function is the sole gate used in `initialize` and `initialize_with_permission` to decide whether a mint may be used to create a pool, as seen at [2](#0-1)  and [3](#0-2) .

Because pool creation is permissionless (an unprivileged pool creator supplies `token_0_mint`/`token_1_mint`), an attacker can:
1. Create an SPL Token mint with `freeze_authority` set to themselves (or a colluding key).
2. Call `initialize` to create a raydium-cp-swap pool using that mint as `token_0_mint`/`token_1_mint`. The pool's vault token accounts (`token_0_vault`/`token_1_vault`) are created via `create_token_account` at [4](#0-3)  as normal SPL `TokenAccount`s owned by the `authority` PDA - these accounts are freezable by the mint's `freeze_authority` like any other token account.
3. Wait for other, unrelated LPs to `deposit` into the pool, growing the vault balances (see `deposit` at [5](#0-4) ).
4. Freeze the vault token account(s) using the SPL Token `FreezeAccount` instruction (which only requires the mint's `freeze_authority` to sign — entirely outside the cp-swap program's control).

Once a vault is frozen, every `token_2022::transfer_checked` CPI that moves funds out of (or into, since a frozen account also blocks incoming transfers) that vault will fail on-chain, because the SPL Token program itself rejects transfers on frozen accounts. This includes:
- `withdraw` (`transfer_from_pool_vault_to_user`) at [6](#0-5) 
- `swap_base_input`/`swap_base_output` (same `transfer_from_pool_vault_to_user`/`transfer_from_user_to_pool_vault` helpers) defined at [7](#0-6) 
- `collect_fund_fee`/creator-fee collection paths that transfer from the same vaults, e.g. [8](#0-7) 

There is no other check anywhere in `deposit.rs`, `withdraw.rs`, or the swap instructions that verifies the mint has no freeze authority, and no re-validation happens after pool creation.

### Impact Explanation
This permanently freezes all LP funds sitting in the affected vault - unlike the original NFT report where only the borrower's own single position is impacted, here every liquidity provider in the pool (not just the attacker) has their share of the pool's funds locked, since `withdraw` and `swap` both revert once the vault is frozen. This satisfies "permanent freezing of user or LP funds," a Medium/High-severity impact per the validation criteria.

### Likelihood Explanation
Likelihood is realistic: creating an SPL Token mint with a freeze authority is trivial and free, and `initialize`/`initialize_with_permission` are fully permissionless, unprivileged entry points reachable in a single transaction with attacker-chosen mint accounts. No special privilege on the cp-swap program is needed - only control of the mint's `freeze_authority`, which the attacker sets themselves at mint creation.

### Recommendation
Extend `is_supported_mint` to reject any mint (legacy SPL Token or Token-2022) whose `freeze_authority` is `Some(_)`, rather than unconditionally trusting legacy SPL Token mints. This closes the gap so that only mints with no freeze authority (or a documented, immutably-cleared one) can be paired into a pool.

### Proof of Concept
1. Attacker creates mint `M` via `spl_token::instruction::initialize_mint` with `freeze_authority = Some(attacker_key)`.
2. Attacker calls `initialize` on cp-swap with `token_0_mint = M`; `is_supported_mint` returns `true` immediately because `*mint_info.owner == Token::id()` ( [9](#0-8) ), so the pool and vault `token_0_vault` are created.
3. A victim LP calls `deposit`, transferring `M` tokens into `token_0_vault` ( [10](#0-9) ).
4. Attacker signs and submits an SPL Token `FreezeAccount` instruction against `token_0_vault` using `attacker_key`.
5. Victim's subsequent `withdraw` call fails at the `transfer_checked` CPI in `transfer_from_pool_vault_to_user` ( [11](#0-10) ) because the vault account is frozen, and `swap_base_input`/`swap_base_output` using the same vault fail identically - the victim's deposited funds remain permanently locked as long as the attacker keeps the account frozen.

### Citations

**File:** programs/cp-swap/src/utils/token.rs (L17-71)
```rust
pub fn transfer_from_user_to_pool_vault<'a>(
    authority: AccountInfo<'a>,
    from: AccountInfo<'a>,
    to_vault: AccountInfo<'a>,
    mint: AccountInfo<'a>,
    token_program: AccountInfo<'a>,
    amount: u64,
    mint_decimals: u8,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    token_2022::transfer_checked(
        CpiContext::new(
            *token_program.key,
            token_2022::TransferChecked {
                from,
                to: to_vault,
                authority,
                mint,
            },
        ),
        amount,
        mint_decimals,
    )
}

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

**File:** programs/cp-swap/src/utils/token.rs (L335-342)
```rust
pub fn is_supported_mint(
    mint_account: &InterfaceAccount<Mint>,
    mint_associated_is_initialized: bool,
) -> Result<bool> {
    let mint_info = mint_account.to_account_info();
    if *mint_info.owner == Token::id() {
        return Ok(true);
    }
```

**File:** programs/cp-swap/src/utils/token.rs (L362-403)
```rust
pub fn create_token_account<'a>(
    authority: &AccountInfo<'a>,
    payer: &AccountInfo<'a>,
    token_account: &AccountInfo<'a>,
    mint_account: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    signer_seeds: &[&[u8]],
) -> Result<()> {
    let space = {
        let mint_info = mint_account.to_account_info();
        if *mint_info.owner == token_2022::Token2022::id() {
            let mint_data = mint_info.try_borrow_data()?;
            let mint_state =
                StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;
            let mint_extensions = mint_state.get_extension_types()?;
            let required_extensions =
                ExtensionType::get_required_init_account_extensions(&mint_extensions);
            ExtensionType::try_calculate_account_len::<spl_token_2022::state::Account>(
                &required_extensions,
            )?
        } else {
            TokenAccount::LEN
        }
    };
    create_or_allocate_account(
        token_program.key,
        payer.to_account_info(),
        system_program.to_account_info(),
        token_account.to_account_info(),
        signer_seeds,
        space,
    )?;
    initialize_account3(CpiContext::new(
        *token_program.key,
        InitializeAccount3 {
            account: token_account.to_account_info(),
            mint: mint_account.to_account_info(),
            authority: authority.to_account_info(),
        },
    ))
}
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L196-200)
```rust
    if !(is_supported_mint(&ctx.accounts.token_0_mint, mint0_associated_is_initialized).unwrap()
        && is_supported_mint(&ctx.accounts.token_1_mint, mint1_associated_is_initialized).unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
    }
```

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L208-212)
```rust
    if !(is_supported_mint(&ctx.accounts.token_0_mint, mint0_associated_is_initialized).unwrap()
        && is_supported_mint(&ctx.accounts.token_1_mint, mint1_associated_is_initialized).unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
    }
```

**File:** programs/cp-swap/src/instructions/deposit.rs (L164-190)
```rust
    transfer_from_user_to_pool_vault(
        ctx.accounts.owner.to_account_info(),
        ctx.accounts.token_0_account.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        if ctx.accounts.vault_0_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        transfer_token_0_amount,
        ctx.accounts.vault_0_mint.decimals,
    )?;

    transfer_from_user_to_pool_vault(
        ctx.accounts.owner.to_account_info(),
        ctx.accounts.token_1_account.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        if ctx.accounts.vault_1_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        transfer_token_1_amount,
        ctx.accounts.vault_1_mint.decimals,
    )?;
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

**File:** programs/cp-swap/src/instructions/admin/collect_fund_fee.rs (L91-119)
```rust
    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.recipient_token_0_account.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        if ctx.accounts.vault_0_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        amount_0,
        ctx.accounts.vault_0_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[auth_bump]]],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.recipient_token_1_account.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        if ctx.accounts.vault_1_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        amount_1,
        ctx.accounts.vault_1_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[auth_bump]]],
    )?;
```
