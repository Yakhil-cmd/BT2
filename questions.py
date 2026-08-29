import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the GitLab namespace/project path, for example group/project
SOURCE_REPO = 'Zest-Protocol/zest-v2-contracts'
# todo: the name of the repository
REPO_NAME = 'zest-v2-contracts'

run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')


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
    # LENS: THE CROSS-ACCOUNT SURFACE - one unprivileged user against another.
    #
    # Zest is a shared pool. Almost every call a user makes moves state that OTHER users
    # depend on: `index` and `lindex` reprice everyone's debt and everyone's zToken
    # collateral; `socialize-debt` charges every supplier in a vault for one borrower's
    # loss; the per-block `index-cache` is primed by whoever calls first and consumed by
    # whoever calls next; utilization, `cap-supply`, `cap-debt` and available liquidity are
    # global; `repay` writes a stranger's ledger by design; and `liquidate` is a sanctioned
    # write to another principal's position. This variant hunts ONLY for a scenario where
    # attacker A profits at victim B's expense, or freezes B's funds - never a user harming
    # only itself, and never a shared-pool effect that is simply how lending works.
    #
    # DELIBERATELY ABSENT: the whole dao directory (impacts needing DAO compromise are out
    # of scope, and full DAO control of the registries is intended design), and all
    # flashloan logic, which is out of scope protocol-wide.
    # =================================================================================

    # -- Where one principal touches another --------------------------------------------
    # `repay` with `on-behalf-of`; the entire `liquidate` / `liquidate-multi` /
    # `liquidate-redeem` family; `socialize-debt-asset`; every `receiver`,
    # `collateral-receiver` and `funds-receiver`; and the shared `index-cache` and
    # `last-update` maps that one caller writes and the next caller reads.
    "mainnet/contracts/market/v0-4-market.clar",

    # -- The shared ledger and the 64-element bounds every position must fit through -----
    # `resolve-or-create` binding principals to ids; `mask-to-list-internal` and its
    # `as-max-len? ... u64` with `unwrap-panic`; `last-borrow-block` written onto whichever
    # account the market names, not necessarily the caller.
    "mainnet/contracts/market/v0-market-vault.clar",

    # -- Pool-wide state one user moves for everybody ------------------------------------
    # `index`, `lindex`, `assets`, `principal-scaled`, `utilization`, `cap-supply`,
    # `cap-debt`, `get-available-assets`, `socialize-debt`, and the freely transferable zft.
    # v0-vault-usdc and v0-vault-usdh are the two 6-decimal stablecoin vaults - the pair most
    # likely to sit in one egroup together, where one user's dust becomes another's rounding.
    # v0-vault-stx is the native-STX path through .wstx.
    "mainnet/contracts/vault/v0-vault-stx.clar",
    "mainnet/contracts/vault/v0-vault-usdc.clar",
    "mainnet/contracts/vault/v0-vault-usdh.clar",

    # -- Read paths only: how a victim's position is enumerated and priced ----------------
    # `status`, `status-multi`, `get-bitmap`, `mask-pos`, `subset`, `uint-to-list-u64`.
    # Assume the DAO configured the registry correctly; the bug must be in the lookup.
    "mainnet/contracts/registry/v0-assets.clar",
]


target_scopes = [
    "Critical. LIQUIDATION READS A DIFFERENT POSITION THAN THE HEALTH CHECK WROTE. `liquidate` builds `position` from `get-liquidation-position` (enabled collateral plus ALL debt) and `pos-full` from `get-full-position`, then derives `mask` and the egroup from the first, while `borrow` and `collateral-remove` proved health against `get-position` (enabled only). Show a borrower that is healthy under the mask its own operations were validated against but liquidatable under the mask `liquidate` selects, and seize collateral from a solvent user. Impact: direct theft of user funds.",

    "Critical. NOTHING BOUNDS THE SEIZURE ON THE BORROWER'S SIDE. `min-collateral-expected` protects the liquidator only; the borrower's protection is entirely the arithmetic in `calc-final-liquidation-amounts` and `scale-debt-for-liquidation`, where collateral is re-scaled by `scaled-to-remove / scaled-debt` after debt was already re-derived from capped collateral by `calc-liq-debt-repay-real`. Show a two-step re-derivation that seizes more than `debt-to-repay` times (BPS + liq-penalty), and name the borrower as the victim. Impact: direct theft of user funds.",

    "Critical. ONE BORROWER'S LOSS IS CHARGED TO EVERY SUPPLIER. `socialize-debt-asset` writes `lindex` down for the whole vault, so an attacker can convert its own engineered bad debt into a haircut on strangers. Compute the cheapest position - dust collateral, an asset at a price edge, a partially seized multi-asset borrower - that reaches the socialization branch, and compare the attacker's cost against the value removed from other suppliers. Show the attacker profiting, whether by holding the other side, by redeeming first, or by liquidating the cascade it caused. Impact: direct theft of supplier funds.",

    "Critical. THE `lindex` WRITE-DOWN INSTANTLY REPRICES EVERY OTHER USER'S COLLATERAL. `resolve-ztoken` values rehypothecated collateral as price times the cached `lindex`, and `socialize-debt` lowers `lindex` for the entire vault in one call, with `socialize-debt-asset` immediately refreshing the market's `index-cache` with the new value. Show a single transaction that lowers `lindex` and, in the same block, liquidates third parties whose zToken collateral just lost value through no action of their own. Impact: direct theft of user funds.",

    "Critical. THE FIRST CALLER IN A BLOCK SETS THE INDEXES EVERYONE ELSE USES. `accrue-and-cache` keys `index-cache` on `stacks-block-time` and returns the cached record to every later caller in that block, while the vault's `accrue` is itself a no-op once `last-update` equals the current time. Show attacker A calling first to fix an index favourable to A and unfavourable to victim B, then B's liquidation, borrow or repay in the same block executing against A's snapshot rather than a freshly accrued one. Impact: direct theft of user funds.",

    "Critical. `socialize-debt-asset` REFRESHES THE SHARED CACHE MID-TRANSACTION. Inside the fold it calls `vault-socialize-debt`, then writes `(vault-accrue asset-id)` straight into `index-cache` for the current timestamp, replacing the record other in-flight computations in the same transaction already read. Show a multi-asset liquidation in which values computed before the refresh are combined with values computed after it, so the seizure, the repayment and the socialization are priced against three different index states. Impact: direct theft, or protocol insolvency.",

    "Critical. `liquidate-multi` PRICES N BORROWERS AGAINST ONE SNAPSHOT. `call-liquidate` invokes `liquidate` with `none` for `price-feeds`, so the whole batch runs on whatever `last-update`, `index-cache` and price state the first item established, and each seizure mutates the vault state the next item is evaluated against. Show a batch ordering in which a later borrower is seized on stale or attacker-shaped state, or in which one borrower's socialization changes the health of the next borrower in the same list. Impact: direct theft of user funds.",

    "Critical. `repay` WRITES A STRANGER'S LEDGER. With `on-behalf-of`, an attacker pays dust and `debt-remove-scaled` mutates the victim's `debt` map, its mask through `mask-update`, and its `last-update` through `refresh`. Show a one-unit unsolicited repayment used as a weapon: clearing a debt bit so the victim's mask resolves to a different egroup with different LTVs, removing the asset that made the victim's group favourable, or changing a timestamp another check depends on. Impact: direct theft, or temporary freezing of the victim's funds.",

    "Critical. AN UNSOLICITED WRITE CREATES A POSITION FOR A PRINCIPAL THAT NEVER ACTED. `resolve-or-create` allocates a user id whenever the market names an account, and `repay` accepts an arbitrary `on-behalf-of`. Establish whether an attacker can cause a registry entry, a mask, or a `last-borrow-block` to be created or set for a principal that has never used the protocol, and what that does the first time the victim actually deposits - a pre-existing mask, a consumed id, or an egroup resolution the victim never chose. Impact: permanent or temporary freezing of the victim's funds.",

    "Critical. THE 64-ELEMENT BOUND IS A WEAPON. `mask-to-list-internal`, `get-assets`, `price-multi-resolve`, `iter-price-multi`, `remove-if-match` and the lookup folds all end in `(unwrap-panic (as-max-len? ... u64))`, and every one of them is executed over a VICTIM's position during liquidation and during the victim's own withdrawals. Establish how many collateral and debt rows a position can accumulate, whether any of those rows can be created by someone other than the position owner, and whether a position can be pushed to a size where every evaluation of it aborts. Impact: permanent freezing of the victim's funds.",

    "Critical. A RECIPIENT THAT REFUSES DELIVERY FREEZES THE OPERATION FOREVER. `send-tokens` in market-vault and `send-underlying` in the vaults push value to a principal chosen by the caller - `collateral-receiver`, `funds-receiver`, `recipient` - and a contract principal can make that transfer fail deterministically. Establish which of these are reachable with a victim, rather than the caller, as the destination, and whether any position can be put into a state where liquidation or withdrawal must route through an address that always aborts. Impact: permanent freezing of funds.",

    "Critical. ONE BORROWER CAN LOCK EVERY SUPPLIER OUT. `redeem` requires `(>= available-assets inkind)` where `get-available-assets` reads real liquidity, while `system-borrow` only requires `(<= amount available-assets)` and `(<= (+ debt amount) CAP-DEBT)`. Show a borrow sized to leave the vault unable to service redemptions, held open at a cost the attacker can bear because the interest curve at that utilization is mispriced or because the position is self-funded, and quantify how long suppliers are locked out. Impact: temporary freezing of funds, escalating to permanent if the position cannot be liquidated.",

    "High. THE SUPPLY AND DEBT CAPS ARE A DENIAL SURFACE. `deposit` checks `(<= (+ current-assets amount) CAP-SUPPLY)` against the `assets` var and `system-borrow` checks `(<= (+ debt amount) CAP-DEBT)` against `total-debt`, which grows with accrued interest alone. Show one principal occupying a cap so that no other user can deposit, or accrued interest alone tripping `CAP-DEBT` so that no borrower can refinance and no liquidator can act. Impact: temporary freezing of funds.",

    "Critical. THE VICTIM'S COLLATERAL ROUNDS TO ZERO WHILE ITS DEBT ROUNDS UP. `calculate-asset-notional-value` normalizes collateral with round-down and debt with round-up, and `normalize` divides by `(pow u10 decimals)` after multiplying by price, so the protocol's USD unit is a whole dollar. For a victim holding a small position in an 8-decimal asset against a 6-decimal stablecoin debt, show the pair of amounts at which the position reads as under-collateralised while it is economically healthy, and liquidate it. Impact: direct theft of user funds.",

    "Critical. THE UTILIZATION EVERY OTHER USER IS PRICED BY IS SET BY WHOEVER ACTS FIRST. `interest-rate` interpolates on `calc-utilization` of available liquidity against `total-debt`, and both move with any borrow, repay, deposit or redeem in the same block, while `accrue` only rewrites the indexes once per timestamp. Show a borrow-then-repay, or a deposit-then-redeem, that leaves the accrued index reflecting a utilization no borrower actually experienced, and identify who gained and who lost. Impact: theft of unclaimed yield.",

    "High. SHARES MOVE FREELY WHILE THEY BACK SOMEONE ELSE'S POSITION. The vault `transfer` is a plain FT transfer, and pledged zft is held by .v0-market-vault. Establish exactly who holds pledged shares at every step of `supply-collateral-add`, `collateral-remove-redeem` and `liquidate-redeem`, and whether a third party can transfer shares into the market or market-vault, or out of a transient balance, in a way that changes what another user's position is worth or what it can withdraw. Impact: direct theft, or freezing of user funds.",

    "Critical. `debt-add-scaled` STAMPS `last-borrow-block` ON THE ACCOUNT, NOT THE CALLER. The same-block liquidation guard behind `ERR-LIQUIDATION-BORROW-SAME-BLOCK` reads that stamp. Establish every path on which the market writes debt for an account other than `contract-caller`, and whether an attacker can cause a victim's stamp to be set or left stale - shielding a position that should be liquidated, or exposing one that should be protected. Impact: protocol insolvency, or direct theft from the borrower.",

    "High. LIQUIDATION GRACE IS RESOLVED PER ASSET AND THE ATTACKER PICKS THE ASSET. `is-liquidation-paused` returns true if `pause-liquidation` is set, if the `GLOBAL-LIQUIDATION-GRACE-ID` entry is live, or if the entry for the asset id passed to it is live. Determine exactly which asset id `liquidate` supplies, and show a borrower composing a multi-asset position so that the checked asset is the one under grace while the rest of the position is freely underwater. Impact: protocol insolvency, with the loss borne by suppliers.",

    "High. `status-multi` MISALIGNS ONE USER'S ASSETS WITH ANOTHER'S FLAGS. `(map unwrap-status ids mask)` is a two-list map where `mask` is `uint-to-list-u64` of the enabled bitmap, so an asset id is paired positionally with one element of that expansion rather than with the whole bitmap, and `map` truncates to the shorter list. Since `ids` comes from the position being evaluated, two different users produce two different pairings. Show a victim whose collateral or debt flags come out wrong purely because of which assets it holds. Impact: direct theft, or protocol insolvency.",

    "High. THE VICTIM PAYS FOR SOMEONE ELSE'S ACCRUAL ROUNDING. `accrue` computes `debt-delta` from two round-down products of `principal-scaled`, takes `reserve-inc` from it, and mints treasury shares, while each borrower's own debt grows by a round-up against their scaled balance. Show that across many small borrowers the interest charged and the interest distributed do not agree, and that the residue is taken from, or given to, a party that did not earn it. Impact: theft of unclaimed yield.",

    "Critical. LIQUIDATION LEAVES THE VICTIM'S POSITION UNUSABLE. After a seizure and any socialization, check what remains on the borrower: `debt` rows for assets the fold did not reach, `collateral` rows at zero that `remove-user-collateral` did not `map-delete`, mask bits `mask-update` did not clear, and a `last-borrow-block` that never resets. Show a fully liquidated user who can no longer deposit, borrow, or withdraw because its own stale position state now fails a check, or resolves to an egroup that admits nothing. Impact: permanent freezing of the victim's funds.",

    "Critical. THE SHARED STATE NOBODY TREATED AS SHARED - what the design never modelled. Enumerate every data var and map that ONE user's call writes and ANOTHER user's call reads within the same block: `index`, `lindex`, `last-update` in each vault; `index-cache` and the oracle `last-update` map in the market; `assets`, `principal-scaled`, `total-borrowed`, the zft supply; `nonce` and the position `registry` in market-vault. For each, determine whether reordering the two users' transactions changes the second user's outcome, and find the one where the attacker chooses the ordering and the victim absorbs the difference. Prove it with two accounts in one simnet block and assert the victim's balance or health differs by ordering alone. Impact: name it as direct theft, permanent freezing, or insolvency.",
]


scope_scan = [
]


def question_generator(target_file: str) -> str:
    """
    Generate cross-account exploit questions for one Zest v2 target.

    ```
    target_file format:
    "'File Name: mainnet/contracts/market/v0-4-market.clar -> Scope: Critical. ...'"
    """

    prompt = f"""
    ```

    Generate cross-account security audit questions for this exact Zest Protocol v2 target:

    {target_file}

    Project focus:
    Zest v2 is a Clarity lending market on Stacks, and it is a SHARED POOL: almost every call one
    user makes moves state other users depend on. `accrue` writes `index` and `lindex`, repricing
    every borrower's debt and every holder's rehypothecated zToken collateral. `socialize-debt`
    charges every supplier in a vault for one borrower's loss. The market's `index-cache`, keyed
    on `stacks-block-time`, is primed by whoever calls first in a block and consumed by whoever
    calls next. Utilization, `cap-supply`, `cap-debt` and available liquidity are global. `repay`
    accepts `on-behalf-of` and writes a stranger's ledger by design. `liquidate`, `liquidate-multi`
    and `liquidate-redeem` are sanctioned writes to another principal's position. Every position
    evaluation runs through 64-element list folds ending in `unwrap-panic`.

    EVERY question in this batch must have TWO named parties: attacker A and victim B, where B is
    a different unprivileged principal. A question where the only party affected is the caller
    itself is worthless here and must not be generated.

    Rules:
    * Treat `File Name:` as the exact contract.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Use exact Clarity symbols (define-public/private/read-only names, map, data-var, constant).
    * Name victim B explicitly and state what B loses, what B can no longer do, and for how long.
    * Both A and B are unprivileged: ordinary Stacks principals that fund a wallet, call any
      public function, deploy their own Clarity contracts, pass them as `<ft-trait>`, supply their
      own `price-feeds`, and choose amounts, recipients, `on-behalf-of` and ordering within a block.
    * Neither is a DAO signer, executor, market impl, authorized contract, miner, oracle publisher
      or node operator. Ignore malicious-miner, chain-reorg, MEV-only and social-engineering
      assumptions.
    * An ordinary shared-pool consequence is NOT a finding: a borrower legitimately raising the
      rate everyone pays, a supplier legitimately withdrawing liquidity, a liquidator being paid
      the configured penalty, or a price move affecting all positions. The finding must be a
      defect in this code that lets A take from B or freeze B beyond what the design intends.
    * PROGRAM EXCLUSIONS - a question landing in any of these wastes the whole batch:
      - ANY logic related to flashloans is OUT OF SCOPE. A flashloan may be used as a source of
        capital for a different attack, but never target `flashloan` itself, its fee, its
        `flashloan-permissions` / `default-flashloan-permissions` whitelist, or `in-flashloan`.
      - Liquidation of disabled collateral, and any other deliberate protocol safety design
        decision, is OUT OF SCOPE.
      - Anything requiring DAO compromise, or an accidental or incorrect registry update by the
        DAO, is OUT OF SCOPE. Full DAO control of the asset and egroup registries is intended
        design, and every egroup invariant needing global market and position knowledge is
        verified off-chain by the DAO before approval. Assume both registries are correctly
        configured, and target only the read and resolution paths an ordinary user call executes.
      - Also excluded everywhere: leaked keys or credentials, privileged addresses, external
        stablecoin depegs the attacker did not cause through a bug in this code, 51% and basic
        economic or governance attacks, Sybil attacks, centralization risk, lack of liquidity,
        incorrect data supplied by third-party oracles, best-practice notes, feature requests,
        and test or configuration files.
      - Oracle manipulation caused by a bug in THIS code remains fully in scope.
    * IN-SCOPE IMPACTS - every question must land on one and name it:
      Critical: direct theft of user funds at rest or in motion, other than unclaimed yield;
      permanent freezing of funds; protocol insolvency.
      High: theft of unclaimed yield or royalties; permanent freezing of unclaimed yield or
      royalties; temporary freezing of funds.
    * Every question must be a concrete real-world scenario A can execute on mainnet with its own
      capital. No speculative unbounded-list, memory or resource-hygiene questions - though a
      64-element list bound that a THIRD PARTY can push a victim's position past is in scope.
    * Clarity `+` `-` `*` abort on overflow and underflow; an abort is a finding here when it
      makes a VICTIM's position permanently or temporarily unevaluable - say which.
    * Generate 30 to 40 high-signal questions.
    * At least 70% must land on a Critical impact rather than a High one.
    * Every question must be testable by a Clarinet / vitest simnet test in `local-testing/tests`
      using at least TWO accounts, on a local fork. Never propose testing on mainnet or a public testnet.
    * Avoid generic checklist questions and repeated root causes.
    * Prefer questions where the proof is an ORDERING or an INTERFERENCE test: run B's transaction
      alone, then run it after A's in the same block, and assert B's balance, health, or ability to
      withdraw differs.

    Known dead ends - do NOT generate questions about these:
    * A user harming only its own position, with no second party.
    * Normal shared-pool economics: rates moving, liquidity being used, penalties being paid.
    * Governance setting a bad LTV, cap, fee, penalty, staleness or interest curve.
    * An external oracle or token misbehaving on its own.
    * Findings requiring the attacker to already be an authorized contract, market impl or signer.
    * Anything only reproducible against mock tokens or the mock oracle.

    Core cross-account invariants (each question must break one):
    * NON-INTERFERENCE: no transaction by A changes the value B can withdraw, or B's health, other
      than through the pool economics the protocol openly implements.
    * SANCTIONED WRITES ONLY: the only writes to B's position by another principal are a correct
      liquidation of a genuinely unhealthy position and a repayment that strictly reduces B's debt.
    * SEIZURE BOUND: in any liquidation of B, collateral leaving B equals debt cleared for B scaled
      by the penalty, and never more.
    * ORDERING NEUTRALITY: the outcome of B's transaction does not depend on whether A transacted
      first in the same block.
    * EVALUABILITY: B's position can always be enumerated, priced, liquidated and withdrawn from,
      whatever state any other principal has created.

    Each question must include:
    1. target function/method;
    2. attacker A's action (a concrete contract call with arguments);
    3. victim B and B's starting position;
    4. the interleaving or call sequence, with block boundaries marked;
    5. the cross-account invariant broken;
    6. what B loses and the in-scope impact class;
    7. proof idea using two accounts.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Function: symbol_or_method] Can unprivileged attacker A, by ATTACKER_ACTION, cause victim B holding VICTIM_POSITION to suffer VICTIM_LOSS through CALL_SEQUENCE, violating INVARIANT, causing IMPACT_CLASS? Proof idea: two-account Clarinet simnet test PARAMETERS and assert NON_INTERFERENCE, SANCTIONED_WRITES_ONLY, SEIZURE_BOUND, ORDERING_NEUTRALITY, or EVALUABILITY.",
    ]
    """
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a cross-account Zest v2 exploit-validation prompt.
    """

    prompt = f"""# SECURITY AUDIT PROMPT

## Question
{security_question}

## Rules
- Use existing repo context only. Analyze only this question and scoped impact.
- The claim must involve TWO unprivileged principals: attacker A and a distinct victim B. If the only party affected is the caller, output no vulnerability.
- Both are ordinary Stacks principals: fund a wallet, call any public function, deploy a Clarity contract and pass it as `<ft-trait>`, supply `price-feeds`, choose recipients, `on-behalf-of` and ordering. Neither is a DAO signer, executor, market impl, authorized contract, miner, oracle publisher or node operator.
- Reject malicious-miner, chain-reorg, MEV-only and social-engineering paths.
- Reject ordinary shared-pool economics: rates moving with utilization, liquidity being consumed, a liquidator earning the configured penalty, or a price move affecting everyone.
- OUT OF SCOPE, reject on sight: any flashloan logic (`flashloan`, its fee, its permission whitelist, `in-flashloan`) - though a flashloan used purely as capital for a different attack is fine; liquidation of disabled collateral and other deliberate safety design decisions; anything requiring DAO compromise or an accidental or incorrect DAO registry update, since full DAO control of the asset and egroup registries is intended design and egroup invariants needing global position knowledge are verified off-chain before approval.
- Also reject: leaked keys, privileged addresses, external stablecoin depegs the attacker did not cause through a bug here, 51% / basic economic / governance attacks, Sybil, centralization risk, lack of liquidity, incorrect data supplied by third-party oracles, best-practice notes, feature requests, and test or configuration files. Oracle manipulation caused by a bug in THIS code stays in scope.
- The impact must be one of: Critical - direct theft of user funds at rest or in motion other than unclaimed yield, permanent freezing of funds, or protocol insolvency; High - theft of unclaimed yield or royalties, permanent freezing of unclaimed yield or royalties, or temporary freezing of funds.
- Reject Pyth and Wormhole internals, third-party token behaviour, `local-testing/**`, tests, mocks, deployment plans, docs, read-only aggregators, and dependency-only findings.

## Validate
- State who A is, who B is, and what B holds before A acts.
- Trace A's exact call sequence and mark the block boundaries, then trace B's transaction against the state A left behind.
- Identify every shared variable A wrote that B's transaction reads: `index`, `lindex`, `last-update`, `index-cache`, the oracle `last-update` map, `assets`, `principal-scaled`, `total-borrowed`, the zft supply, `nonce`, the position registry.
- Compute B's outcome twice - with and without A's transaction - and show the difference numerically.
- Check whether health checks, `min-collateral-expected`, caps, pause states, the same-block borrow guard, or Clarity's own aborts already prevent it.
- Confirm the difference is a defect, not the pool economics the protocol openly implements.
- Require exact file/function support and a reproducible two-account Clarinet / vitest simnet PoC on a local fork.

## Output
If valid, output exactly:

### Title
[Bug statement] - ([File: file_path])

### Summary
[2-3 sentences naming attacker, victim and loss]

### Finding Description
[Shared state written by A and read by B, the code path, root cause, exact call arguments, interleaving, and why existing checks fail]

### Impact Explanation
[What B loses or can no longer do, for how long, and the exact in-scope severity category]

### Likelihood Explanation
[Preconditions, A's capital cost, whether A profits, feasibility, repeatability]

### Recommendation
[Specific fix]

### Proof of Concept
[Two-account Clarinet simnet test plan: B alone, then B after A, asserting the difference]

If invalid, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict bounty-style validation prompt for Zest v2 cross-account claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and Researcher.Md for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- A cross-account claim is only valid if the report names a distinct victim principal and shows that victim's outcome changing because of the attacker's transaction. Reject any claim whose only affected party is the caller.
- Reject ordinary shared-pool economics: utilization moving rates, liquidity being consumed, a liquidator earning the configured penalty, or a market-wide price move.
- Reject anything requiring a DAO signer, executor, market impl, authorized contract, miner, oracle publisher, node operator, or leaked keys.
- OUT OF SCOPE, reject on sight: any flashloan logic (`flashloan`, its fee, its permission whitelist, `in-flashloan`) - though a flashloan used purely as capital for a different attack is fine; liquidation of disabled collateral and other deliberate safety design decisions; anything requiring DAO compromise or an accidental or incorrect DAO registry update, since full DAO control of the asset and egroup registries is intended design and egroup invariants needing global position knowledge are verified off-chain before approval.
- Also reject: leaked keys, privileged addresses, external stablecoin depegs the attacker did not cause through a bug here, 51% / basic economic / governance attacks, Sybil, centralization risk, lack of liquidity, incorrect data supplied by third-party oracles, best-practice notes, feature requests, and test or configuration files. Oracle manipulation caused by a bug in THIS code stays in scope.
- The impact must be one of: Critical - direct theft of user funds at rest or in motion other than unclaimed yield, permanent freezing of funds, or protocol insolvency; High - theft of unclaimed yield or royalties, permanent freezing of unclaimed yield or royalties, or temporary freezing of funds.
- Reject Pyth and Wormhole internals, third-party contracts, `local-testing/**`, tests, mocks, deployment plans, `.toml`, docs, read-only aggregator and dependency-only findings.
- Reject if the bug was already fixed, acknowledged, or covered by the published Clarity Alliance, Greybeard or Asymmetric audits.
- Reject any PoC requiring testing on mainnet or a public testnet; only local forks are permitted.
- A PoC is mandatory for every severity. Prefer #NoVulnerability over speculative reports.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Attacker and victim named as distinct unprivileged principals, with the victim's starting position stated.
3. The shared state the attacker writes and the victim reads, identified precisely.
4. Reachable path: victim's baseline outcome, attacker's transaction, victim's outcome after, with the difference quantified.
5. Health checks, slippage bounds, caps, pause states, the same-block borrow guard and Clarity aborts reviewed and shown insufficient.
6. The difference shown to be a defect rather than the intended pool economics, and the attacker shown to profit or the victim shown to be frozen.
7. Reproducible proof: two-account Clarinet / vitest simnet test on a local fork.

## Silent Triage Questions
Before output, internally answer:
- Who is the victim, and would they accept that they lost something they should not have?
- Does the victim's outcome actually depend on the attacker's transaction, or only on market conditions?
- Is this a defect, or simply how a shared lending pool works?
- Which in-scope impact class does it land on, exactly?
- Does the attacker profit, or is this pure griefing, and does the program's impact list still cover it?
- What exact two-account test would prove it?

## Output
If valid, output exactly:

Audit Report

## Title
[Clear vulnerability statement] - ([File: file_path])

## Summary
[2-3 sentence summary naming attacker, victim and impact]

## Finding Description
[Exact code path, shared state, root cause, exploit flow, and why existing checks fail]

## Impact Explanation
[What the victim loses, duration, and the exact in-scope category]

## Likelihood Explanation
[Attacker capability, preconditions, capital cost, profitability, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Two-account Clarinet simnet test plan on a local fork]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a short cross-project cross-account analog scan prompt for Zest v2.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Rules
- Use in-scope production repo context only (`mainnet/contracts/**`, excluding the dao directory). Do not ask for code or claim missing files.
- Use the external report only as a bug-class hint, not as proof.
- Keep only analogs in which one unprivileged principal harms another: a write to a stranger's position, a shared index or cache primed by one caller and consumed by another, a socialization charged to all suppliers, a seizure exceeding its bound, a position made unevaluable by a third party, or an ordering dependence between two users in one block.
- Reject any analog whose only affected party is the caller, and reject ordinary shared-pool economics.
- OUT OF SCOPE, reject on sight: any flashloan logic (`flashloan`, its fee, its permission whitelist, `in-flashloan`) - though a flashloan used purely as capital for a different attack is fine; liquidation of disabled collateral and other deliberate safety design decisions; anything requiring DAO compromise or an accidental or incorrect DAO registry update, since full DAO control of the asset and egroup registries is intended design and egroup invariants needing global position knowledge are verified off-chain before approval.
- Also reject: leaked keys, privileged addresses, external stablecoin depegs the attacker did not cause through a bug here, 51% / basic economic / governance attacks, Sybil, centralization risk, lack of liquidity, incorrect data supplied by third-party oracles, best-practice notes, feature requests, and test or configuration files. Oracle manipulation caused by a bug in THIS code stays in scope.
- The impact must be one of: Critical - direct theft of user funds at rest or in motion other than unclaimed yield, permanent freezing of funds, or protocol insolvency; High - theft of unclaimed yield or royalties, permanent freezing of unclaimed yield or royalties, or temporary freezing of funds.
- Reject malicious-miner, chain-reorg, MEV-only, oracle-publisher, third-party token, `local-testing/**`, mock, deployment-plan, dependency-only and no-impact analogs.

## Validate
- Map the bug class to the strongest reachable Zest path and name attacker, victim and the shared state between them.
- Compute the victim's outcome with and without the attacker's transaction.
- Prove root cause with exact file/function support.
- Name the in-scope impact class it lands on.

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
