import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 10
# todo: the path from https://github.com/raydium-io/raydium-cp-swap
SOURCE_REPO = "raydium-io/raydium-cp-swap"
# todo: the name of the repository
REPO_NAME = "raydium-cp-swap"
run_number = os.environ.get('GITHUB_RUN_NUMBER') or os.environ.get('CI_PIPELINE_IID', '0')


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


def load_repository_urls():
    """Load repository URLs from repositories.json."""
    repo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repositories.json")
    if not os.path.exists(repo_file):
        return []

    try:
        with open(repo_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    return [url for url in data if isinstance(url, str) and url.strip()]


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    repository_urls = load_repository_urls()
    if repository_urls:
        run_index = get_cyclic_index(run_number, len(repository_urls))
        BASE_URL = repository_urls[run_index - 1]
    else:
        BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"


scope_files = [
    # =================================================================================
    # Permissionless instruction handlers: every entrypoint any funded wallet can call
    # =================================================================================
    "programs/cp-swap/src/instructions/initialize.rs",
    "programs/cp-swap/src/instructions/initialize_with_permission.rs",
    "programs/cp-swap/src/instructions/deposit.rs",
    "programs/cp-swap/src/instructions/withdraw.rs",
    "programs/cp-swap/src/instructions/swap_base_input.rs",
    "programs/cp-swap/src/instructions/swap_base_output.rs",
    "programs/cp-swap/src/instructions/collect_creator_fee.rs",
    "programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs",
    "programs/cp-swap/src/instructions/mod.rs",

    # =================================================================================
    # Authority-gated handlers: audited for unprivileged reachability and state damage
    # =================================================================================
    "programs/cp-swap/src/instructions/admin/create_config.rs",
    "programs/cp-swap/src/instructions/admin/update_config.rs",
    "programs/cp-swap/src/instructions/admin/update_pool_status.rs",
    "programs/cp-swap/src/instructions/admin/collect_protocol_fee.rs",
    "programs/cp-swap/src/instructions/admin/collect_fund_fee.rs",
    "programs/cp-swap/src/instructions/admin/collect_excess_lamports.rs",
    "programs/cp-swap/src/instructions/admin/create_permission_pda.rs",
    "programs/cp-swap/src/instructions/admin/close_permission_pda.rs",
    "programs/cp-swap/src/instructions/admin/create_support_mint_associated.rs",
    "programs/cp-swap/src/instructions/admin/close_support_mint_associated.rs",
    "programs/cp-swap/src/instructions/admin/mod.rs",

    # =================================================================================
    # Swap curve, fee split and LP<->reserve conversion arithmetic
    # =================================================================================
    "programs/cp-swap/src/curve/calculator.rs",
    "programs/cp-swap/src/curve/constant_product.rs",
    "programs/cp-swap/src/curve/fees.rs",
    "programs/cp-swap/src/curve/mod.rs",

    # =================================================================================
    # On-chain state: pool reserves/fee ledger, config, oracle, permission, mint allowlist
    # =================================================================================
    "programs/cp-swap/src/states/pool.rs",
    "programs/cp-swap/src/states/config.rs",
    "programs/cp-swap/src/states/oracle.rs",
    "programs/cp-swap/src/states/permission.rs",
    "programs/cp-swap/src/states/support_mint_associated.rs",
    "programs/cp-swap/src/states/events.rs",
    "programs/cp-swap/src/states/mod.rs",

    # =================================================================================
    # Token CPIs signed by the AUTH_SEED PDA, zero-copy loader and 128/256-bit math
    # =================================================================================
    "programs/cp-swap/src/utils/token.rs",
    "programs/cp-swap/src/utils/account_load.rs",
    "programs/cp-swap/src/utils/math.rs",
    "programs/cp-swap/src/utils/mod.rs",

    # =================================================================================
    # Program wiring, hardcoded authorities and error surface
    # =================================================================================
    "programs/cp-swap/src/lib.rs",
    "programs/cp-swap/src/error.rs",
]


target_scopes = [
    "Critical. An attacker drains a pool vault or mints another pool's LP by substituting accounts the handler never binds to the loaded PoolState: the single global `authority` PDA derived from `crate::AUTH_SEED` alone (no pool key) signs every `transfer_from_pool_vault_to_user`, `token_mint_to` and `token_burn` in programs/cp-swap/src/utils/token.rs using `pool_state.auth_bump` read from the account rather than `ctx.bumps.authority`, while Swap, Deposit, Withdraw and Withdraw's `token_0_account`/`token_1_account` bind vaults only through `constraint = token_x_vault.key() == pool_state.load()?.token_x_vault`, so a pool_state the attacker created, a forged `auth_bump`, or a vault/mint belonging to a different pool passes the constraints and is still signed for by the program authority.",
    "Critical. An attacker mints LP tokens not backed by deposited reserves in `deposit` (programs/cp-swap/src/instructions/deposit.rs): `CurveCalculator::lp_tokens_to_trading_tokens` with `RoundDirection::Ceiling` in programs/cp-swap/src/curve/constant_product.rs, `PoolState::vault_amount_without_fee`, the `pool_state.lp_supply` counter that can drift from the real `lp_mint.supply`, and `get_transfer_inverse_fee` let the required token_0/token_1 amounts round or truncate to less than the LP share minted, or let a donated/attacker-inflated vault balance be excluded from the ratio, so `lp_supply` stops tracking escrowed reserves.",
    "Critical. An attacker withdraws more than their pro-rata share, or steals another LP's principal, through `withdraw` (programs/cp-swap/src/instructions/withdraw.rs): `RoundDirection::Floor` in `lp_tokens_to_trading_tokens`, the `std::cmp::min(total_token_x_amount, token_x_amount)` clamp, `pool_state.lp_supply.checked_sub`, `token_burn` signed with the AUTH_SEED PDA while the destination `token_0_account`/`token_1_account` carry only a `token::mint` constraint and no `token::authority = owner`, or a vault whose recorded fees exceed its balance, let LP burned and tokens released diverge.",
    "Critical. A swap leaves the pool with less value than before, letting an attacker extract reserves repeatedly: `CurveCalculator::swap_base_input` and `swap_base_output` in programs/cp-swap/src/curve/calculator.rs, `ConstantProductCurve::swap_base_input_without_fees` (floor div) and `swap_base_output_without_fees` (`checked_ceil_div`), `Fees::trading_fee`/`creator_fee` ceil_div, `Fees::split_creator_fee` and `Fees::calculate_pre_fee_amount` round, truncate or split so the `require_gte!(constant_after, constant_before)` check in swap_base_input.rs and swap_base_output.rs passes while the true post-swap vault product falls, or so the creator fee taken on the output side is never subtracted from the reserve the invariant is measured on.",
    "Critical. An attacker makes the pool's fee ledger exceed the vault balance and permanently freeze every user action: `PoolState::update_fees` credits `creator_fees_token_0/1` to the opposite side when `is_creator_fee_on_input` is false while `SwapResult.creator_fee` was deducted from the output transfer, and `PoolState::vault_amount_without_fee` then does `vault_x.checked_sub(protocol + fund + creator fees)` returning `ErrorCode::InsufficientVault` - a crafted sequence of `swap_base_input`/`swap_base_output` calls (or a `CreatorFeeOn::OnlyToken0`/`OnlyToken1` pool from `initialize_with_permission`) drives accrued fees on one side above that vault's real balance, after which swap, deposit, withdraw and creator-fee collection all revert forever.",
    "Critical. An attacker hijacks or pre-drains pool creation: in programs/cp-swap/src/instructions/initialize.rs `create_pool` only requires `pool_account_info.is_signer` when the key is not the POOL_SEED PDA and only checks `owner == system_program::ID`, `create_or_allocate_account` in programs/cp-swap/src/utils/token.rs takes an allocate+assign path for an account that already holds lamports, `AccountLoad::try_from_unchecked` skips the discriminator, and the initial `liquidity = sqrt(vault_0 * vault_1)` minus `lock_lp_amount = 100` with `token_0_mint.key() < token_1_mint.key()` ordering lets a crafted pool_state, a pre-funded vault, or an attacker-chosen `creator_fee_on`/`enable_creator_fee` in `initialize_with_permission` produce a live pool whose state does not match the tokens actually escrowed.",
    "Critical. An attacker uses a Token-2022 mint whose behaviour changes after the pool exists to make the vault receive less than the curve credited: `is_supported_mint` and `support_mint_associated_is_initialized` in programs/cp-swap/src/utils/token.rs allow TransferFeeConfig, InterestBearingConfig, ScaledUiAmount, MetadataPointer and TokenMetadata (and skip all extension checks when a SupportMintAssociated PDA is passed in `ctx.remaining_accounts`), while `get_transfer_fee`/`get_transfer_inverse_fee` read the fee config at the current epoch and `TransferFeeCalculateNotMatch` is the only cross-check - so a transfer fee or ui-amount scale the attacker flips between `initialize` and a later `swap_base_input`, `deposit` or `withdraw` breaks the credited-versus-received equality.",
    "Critical. An attacker steals or destroys accrued creator fees through `collect_creator_fee_permissionless` (programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs): the payer chooses `token_0_program`/`token_1_program` and funds `init_if_needed` ATAs for the `creator` bound only by `address = pool_state.load()?.pool_creator`, then the handler transfers the full `creator_fees_token_0/1` and zeroes them - a frozen, closed or delegate-controlled destination, a transfer-fee mint, a mismatched token program, or a repeated call in one transaction lets the ledger be cleared without the creator receiving the tokens, or lets the rent the payer funded be recovered by the attacker.",
    "Critical/High. An attacker bricks a pool through a write the program makes on the user's behalf: `PoolState::token_price_x32` divides by `token_0_amount`/`token_1_amount` with no zero check, `ObservationState::update` in programs/cp-swap/src/states/oracle.rs does `token_x_price_x32.checked_mul(time_since_last_update)` returning `ErrorCode::MathOverflow` and reads `observation_index` from a packed zero-copy account, and both swap handlers update the oracle after transferring tokens - so a swap or withdraw that leaves one side extreme, or a price magnitude produced by lopsided decimals, makes every later swap on that pool abort with no recovery path for LP holders.",
    "Critical/High blind spot. An ordinary swapper, liquidity provider or pool creator abuses an assumption raydium-cp-swap never wrote down: the first or last liquidity provider taking a rounding or `lock_lp_amount` edge the formula only proved safe for a funded pool, a guard present in swap_base_input.rs but missing in swap_base_output.rs or vice versa, `input_vault`/`output_vault` or `token_0_account`/`token_1_account` aliasing each other or a vault so a balance is read twice in one instruction, a PoolState field re-read after the check that authorized it (`lp_supply`, `status`, `open_time`, `recent_epoch`, `padding`/`padding1` reused by a later upgrade), a `status` bit combination from `set_status_by_bit` that allows deposit but not withdraw, direct donations to a vault or to the WSOL `create_pool_fee` account changing later math, an `amm_config` PDA or `Permission` account an attacker can create and point a pool at, or state left inconsistent by a partially applied instruction that still emits `SwapEvent`/`LpChangeEvent` integrators trust - yielding theft of user funds, unbacked LP minting, pool insolvency, or a pool that can never be swapped or withdrawn from again.",
]


scope_scan = [
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit and fuzzing questions for one Raydium CP-Swap target.

    ```
    target_file format:
    "'File Name: programs/cp-swap/src/instructions/swap_base_input.rs -> Scope: Critical. ...'"
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit questions for this exact Raydium CP-Swap (CPMM) target:

    {target_file}

    Project focus:
    raydium-cp-swap is the Anchor constant-product AMM deployed at CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C. Focus only on what an ordinary wallet reaches: sending initialize, initialize_with_permission, deposit, withdraw, swap_base_input, swap_base_output, collect_creator_fee and collect_creator_fee_permissionless with account lists and instruction data they fully choose, creating their own SPL and Token-2022 mints, token accounts and pools, and composing these calls with other programs in one transaction. Downstream of that: PoolState/AmmConfig/ObservationState loading, the constant-product curve and fee split, the fee ledger, and the SPL token CPIs signed by the AUTH_SEED authority PDA.

    Rules:
    * Treat `File Name:` as the exact file/module.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Use exact Rust symbols (fn, struct, enum, impl, field, const or Anchor account constraint) when possible.
    * Attacker is unprivileged only: anyone who funds a Solana wallet and sends transactions, creates mints, token accounts and pools, provides or withdraws liquidity, swaps, and passes any account list and instruction data the program will accept. They control only their own keys.
    * Attacker is NOT crate::admin::ID, the amm_config protocol_owner or fund_owner, the collect_lamports wallet, a Permission authority, a validator, or another pool's creator, and holds no other user's key. Never assume a malicious validator, leaked key, privileged signer, devnet/localnet feature build, or social engineering.
    * Out of scope, never ask about: Solana runtime, SPL Token or Token-2022 program bugs, Anchor framework bugs, the client/ SDK, off-chain services, RPC, logging, deployment, dependency versions, 51%/sybil/centralization, lack of liquidity, pure MEV ordering, and third-party oracle data simply being wrong.
    * Ignore test files, mocks, benchmarks, docs, generated IDL and config-only findings.
    * Every question must describe a real transaction the attacker actually submits: named instruction, the account list and data they supply, the pool and mints they rely on. No generic unbounded-allocation, memory-growth, compute-exhaustion or "what if the input is huge" speculation without a concrete payload and a concrete broken invariant.
    * Generate 40 to 80 high-signal questions.
    * At least 70% must target theft of user or LP funds, permanent freezing of pool funds, unbacked LP minting, or pool insolvency.
    * Every question must be testable by a `cargo test` unit test over the curve/state types or an anchor `yarn test` / solana-program-test transaction against the program.
    * Avoid generic checklist questions and repeated root causes.

    Core invariants:
    * Account binding: every vault, mint, config and observation account a handler acts on is the one recorded in the loaded PoolState, and the AUTH_SEED PDA signs only for that pool's accounts.
    * Curve soundness: after a swap the real vault product never decreases against the pool, and each fee is charged once on the side the ledger credits.
    * LP backing: pool_state.lp_supply and lp_mint.supply always correspond to the token_0 and token_1 actually escrowed minus accrued protocol, fund and creator fees.
    * Fee-ledger solvency: protocol_fees + fund_fees + creator_fees on each side never exceed that vault's balance.
    * User liveness: no user-submitted transaction can leave a pool where swap, deposit or withdraw reverts forever.

    Each question must include:
    1. target function/method;
    2. attacker action (a concrete instruction: accounts, mints, amounts, data);
    3. preconditions (wallet balance, pool state, mints or token accounts the attacker created);
    4. execution sequence;
    5. invariant tested;
    6. scoped impact;
    7. proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Function: symbol_or_method] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger EXECUTION_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Proof idea: cargo test / anchor solana-program-test PARAMETERS and assert ACCOUNT_BINDING, CURVE_SOUNDNESS, LP_BACKING, FEE_LEDGER_SOLVENCY, or USER_LIVENESS.",
    ]
    """
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a focused Raydium CP-Swap exploit-validation prompt.
    """

    prompt = f"""# SECURITY AUDIT PROMPT

## Question
{security_question}

## Rules
- Use existing repo context only. Analyze only this question and scoped impact.
- Attacker is unprivileged only: anyone who funds a wallet and sends CP-Swap instructions with account lists and data they choose, creates their own SPL or Token-2022 mints, token accounts and pools, provides liquidity, or swaps. No crate::admin::ID, protocol_owner, fund_owner, collect_lamports wallet, Permission authority, validator, or foreign-key access.
- Reject privileged-signer, leaked-key, malicious-validator, devnet/localnet feature build, off-chain, RPC, client-SDK, deployment and misconfiguration-only paths.
- Reject Solana runtime, SPL Token, Token-2022 and Anchor framework bugs, 51%-style, sybil and centralization claims, lack of liquidity, pure MEV ordering, third-party oracle data simply being wrong with no manipulation path, best-practice critiques, and test/mock/docs/generated/config-only findings.
- Reject generic compute-exhaustion or allocation claims with no concrete instruction payload and no broken invariant.
- Focus on real on-chain impact: theft of user or LP funds, permanent freezing of pool funds, unbacked LP minting, fee-ledger or reserve accounting that makes the pool insolvent, or an unauthorized state/parameter change.

## Validate
- Trace the exact reachable path from the attacker's transaction into the affected function, including the account list they supply.
- Check whether the Anchor account constraints (`address = pool_state.load()?...`, `constraint = token_x_vault.key() == ...`, `token::authority`, `token::mint`, `seeds`/`bump`), `PoolState::get_status_by_bit`, `open_time`, `get_swap_params`, `vault_amount_without_fee`, the `require_gte!(constant_after, constant_before)` invariant check, `ExceededSlippage` bounds, `is_supported_mint`, or checked arithmetic already stop it.
- Confirm the path is reachable on the current mainnet build (default features, program id CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C).
- Accept only concrete fund loss or freezing, unbacked LP mint, insolvent pool accounting, or an unauthorized privileged effect.
- Require exact file/function support and a reproducible cargo test or anchor solana-program-test PoC.

## Output
If valid, output exactly:

### Title
[Bug statement] - ([File: file_path])

### Summary
[2-3 sentences]

### Finding Description
[Code path, root cause, attacker instruction and accounts, exploit flow, and why checks fail]

### Impact Explanation
[Concrete scoped impact and severity: Critical (direct theft of user or LP funds, permanent freezing of funds, unbacked LP minting, protocol insolvency) or High (theft of unclaimed fees, temporary freezing of pool funds)]

### Likelihood Explanation
[Preconditions, wallet funding, pool state needed, feasibility, repeatability]

### Recommendation
[Specific fix]

### Proof of Concept
[cargo test / anchor solana-program-test plan with expected assertions]

If invalid, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for Raydium CP-Swap.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Rules
- Use in-scope production program context only. Do not ask for code or claim missing files.
- Use the external report only as a bug-class hint, not as proof.
- Keep only analogs an unprivileged swapper, liquidity provider or pool creator can reach: initialize, initialize_with_permission, deposit, withdraw, swap_base_input, swap_base_output, collect_creator_fee, collect_creator_fee_permissionless, the Anchor account constraints and AUTH_SEED PDA signing, PoolState/AmmConfig/ObservationState loading, the constant-product curve and fee split, or the token CPIs in utils/token.rs.
- Reject privileged-signer, leaked-key, malicious-validator, non-default feature build, off-chain, RPC, client-SDK, deployment, Solana-runtime, SPL/Token-2022 program, Anchor-framework, dependency-only, mocked-only paths, and no-impact analogs.
- Medium, High and Critical only; no low, best-practice, or compute-only analogs.

## Validate
- Map the bug class to the strongest reachable path from a single submitted transaction with attacker-chosen accounts and data.
- Prove root cause with exact file/function support.
- Accept only concrete theft or permanent freezing of user or LP funds, unbacked LP minting, insolvent pool or fee-ledger accounting, or an unauthorized privileged effect.

## Output (Strict)
If valid analog exists, output:

### Title
[Clear vulnerability statement] - ([File: file_path])

### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If not, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict bounty-style validation prompt for Raydium CP-Swap security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and Researcher.Md for scope, exclusions, and valid impact classes.
- Scope is the deployed CP-Swap program only: programs/cp-swap/src/**. Anything outside the on-chain program (client/, SDKs, UI, off-chain services) is out of scope.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- Severities paid by the Raydium Immunefi program: Critical (USD 50,000-505,000), High (USD 40,000), Medium (USD 5,000) under Immunefi Vulnerability Severity Classification V2.3. Medium is valid and must not be discarded: contract unable to operate from lack of token funds, block stuffing, unprofitable griefing, theft of gas. Reject informational, best-practice and low findings.
- Reject malicious-admin, malicious-validator, leaked-key, privileged-signer, devnet/localnet feature build, off-chain, RPC, client-SDK, monitoring, logging, deployment, dependency-only, docs/style, generated-file, and test/mock/config-only issues.
- Reject if the exploit needs crate::admin::ID, the amm_config protocol_owner or fund_owner, the collect_lamports wallet, a Permission authority, a validator, another user's key, victim social engineering, or anything outside what an unprivileged wallet can put in a transaction's accounts and instruction data.
- Reject Solana runtime, SPL Token, Token-2022 and Anchor framework bugs, 51%-style majority attacks, sybil and centralization claims, lack of liquidity, pure MEV ordering the team already knows of, UI bugs, and third-party oracle data being wrong without a manipulation path.
- Reject if the bug was fixed, acknowledged, or publicly disclosed already, per the eligibility rules.
- A valid report must be triggerable by an unprivileged swapper, liquidity provider or pool creator, unless the claim proves escalation from that starting point.
- The final impact must map to an in-scope category: Critical - direct theft of user or LP funds, permanent freezing of funds, unbacked or unauthorized LP minting, or protocol insolvency; High - theft of unclaimed protocol, fund or creator fees, or temporary freezing of funds; Medium - the pool unable to operate, unprofitable griefing, or theft of gas.
- A PoC is mandatory: prose alone is not accepted. Prefer #NoVulnerability over speculative reports.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken account-binding, curve-soundness, LP-backing, fee-ledger-solvency, or user-liveness invariant.
3. Reachable exploit path: preconditions (wallet funding, pool state, attacker-created mints or token accounts) -> submitted instruction with its account list and data -> trigger -> bad result.
4. Existing Anchor account constraints, seeds/bump derivations, PoolState status and open_time gates, get_swap_params and vault_amount_without_fee checks, the constant_after >= constant_before invariant, slippage bounds, is_supported_mint and checked arithmetic reviewed and shown insufficient.
5. Concrete in-scope Critical/High (or clearly-argued Medium) impact with realistic likelihood.
6. Reproducible proof path: cargo test unit PoC or anchor solana-program-test transaction sequence.
7. No obvious rejection reason from SECURITY.md, known issues, privilege assumptions, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Can an ordinary wallet trigger this by sending a CP-Swap instruction with accounts and data it chooses, without any configured authority or foreign key?
- Does the code actually behave as claimed on the current mainnet build (default features, program id CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C)?
- Is the impact caused by this program, not by the Solana runtime, the token programs, Anchor, or a privileged actor?
- Is the fund loss, unbacked mint, insolvency or freeze concrete rather than hypothetical?
- Would an Immunefi triager accept the proof-of-concept?
- What exact test would prove it?

## Output
If valid, output exactly:

Audit Report

## Title
[Clear vulnerability statement] - ([File: file_path])

## Summary
[2-3 sentence summary of the bug and impact]

## Finding Description
[Exact code path, root cause, exploit flow, and why existing checks fail]

## Impact Explanation
[Concrete in-scope impact, severity rationale, and Immunefi V2.3 category]

## Likelihood Explanation
[Attacker capability, funding and pool state required, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or cargo test / anchor solana-program-test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt
