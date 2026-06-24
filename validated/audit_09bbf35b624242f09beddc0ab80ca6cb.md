Audit Report

## Title
Markdown Injection in ICRC-21 `GenericDisplayMessage` via Unsanitized `token_name`, `token_symbol`, and `memo` — (`packages/icrc-ledger-types/src/icrc21/responses.rs`)

## Summary

The shared ICRC-21 consent-message library interpolates attacker-controlled strings (`token_name`, `token_symbol`, and UTF-8-decoded `memo`) directly into a Markdown-formatted `GenericDisplayMessage` without sanitization. An unprivileged ingress sender (or malicious dapp) can craft a transaction memo containing a backtick to break out of the inline code span and inject arbitrary Markdown into the consent dialog shown to users. Independently, a canister developer can craft a `token_name` or `token_symbol` containing newlines and Markdown syntax to inject fake fields. Both vectors undermine the core security guarantee of ICRC-21, which is specifically designed to give users a trustworthy view of what they are signing.

## Finding Description

**Vector 1 — `token_name` injection (canister developer)**

`add_intent` in `packages/icrc-ledger-types/src/icrc21/responses.rs` interpolates `token_name` directly into a Markdown heading with no sanitization:

```rust
// line 53
message.push_str(&format!("# Send {}", token_name.unwrap()));
// line 65
message.push_str(&format!("# Spend {}", token_name.unwrap()));
```

A `token_name` containing `\n` followed by Markdown syntax produces additional rendered headings and fields before the real transaction fields are appended. `token_symbol` is similarly interpolated inside backtick code spans in `add_amount` (line 114), `add_fee` (line 144/149), `add_allowance` (line 188), and `add_existing_allowance` (line 213); a backtick in `token_symbol` terminates the code span and allows raw Markdown to follow.

**Vector 2 — `memo` injection (unprivileged ingress sender / malicious dapp)**

`add_memo` decodes the raw ICRC-1 memo bytes as UTF-8 and places the result inside a *single-backtick* inline code span with no escaping:

```rust
// lines 288-294
let memo_str = match std::str::from_utf8(memo.as_slice()) {
    Ok(valid_str) => valid_str.to_string(),
    Err(_) => hex::encode(memo.as_slice()),
};
// line 294
message.push_str(&format!("\n\n**Memo:**\n`{memo_str}`"));
```

A single backtick character inside `memo_str` terminates the code span. Everything that follows is interpreted as raw Markdown by any rendering wallet. This is a fully unprivileged operation: any caller can submit an `icrc1_transfer` with a crafted memo, and the wallet subsequently calls `icrc21_canister_call_consent_message` to display the consent dialog.

**Contrast with ckBTC/ckDOGE minters**

The ckBTC minter (`rs/bitcoin/ckbtc/minter/src/updates/icrc21.rs`, lines 195–209) and ckDOGE minter (`rs/dogecoin/ckdoge/minter/src/updates/icrc21.rs`, lines 196–210) both contain `validate_address` functions with comments that explicitly call out the Markdown-injection risk and validate the address before interpolation. The shared ICRC-1/ICRC-2 library applies no equivalent guard.

**Exploit flow (Vector 2)**

1. Malicious dapp constructs an `icrc1_transfer` with memo bytes equal to the UTF-8 string:
   `` ` ``\n\n`# You are sending 1000 ICP to attacker`\n\n`**To:**`\n`` `attacker_address ``
2. Wallet calls `icrc21_canister_call_consent_message` with these args.
3. `add_memo` produces: `\n\n**Memo:**\n`` ` ``\n\n# You are sending 1000 ICP to attacker\n\n**To:**\n`` `attacker_address` ``
4. Rendered Markdown shows a fake heading and fake "To" field above the real fields.
5. User approves based on the spoofed dialog.

No existing checks guard against this: `icrc21_check_fee` only validates the fee amount; the `MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES` (500 bytes) limit does not prevent a crafted memo from fitting within the limit while still injecting meaningful Markdown.

## Impact Explanation

The impact is concrete user harm via consent-dialog spoofing on the ICRC-1 ledger, an in-scope financial integration. A user who approves based on the displayed dialog may unknowingly authorize a transaction with different parameters than shown (e.g., a larger amount or a different recipient). This matches the allowed impact: **"Significant Chain Fusion, ck-token, ledger, Rosetta, boundary/API, XRC, Internet Identity, NNS, SNS, or infrastructure security impact with concrete user or protocol harm" — High ($2,000–$10,000)**. The ICRC-21 standard's entire purpose is to provide a trustworthy consent message; injecting fake fields directly defeats that guarantee.

## Likelihood Explanation

**Vector 2 (memo injection)** requires only the ability to submit an `icrc1_transfer` with a crafted memo — a standard, unprivileged ingress call available to any IC user or dapp. A malicious dapp that constructs transactions on behalf of users (the standard DeFi pattern) can set the memo without the user's knowledge. The ICRC-21 endpoint is then called by the wallet to show the user what they are signing, at which point the injected Markdown is rendered. Any wallet that calls `icrc21_canister_call_consent_message` and renders `GenericDisplayMessage` as Markdown is affected. The attack is repeatable, requires no special privileges, and is silent.

**Vector 1 (token_name injection)** requires deploying a custom ICRC-1 ledger — accessible to any canister developer on the IC. The ledger appears legitimate until a wallet renders its ICRC-21 consent message.

## Recommendation

1. **Escape backticks in `memo_str`** before placing it inside a code span: replace every `` ` `` with `` \` ``, or switch to a fenced code block (` ``` `) which is immune to single-backtick injection.
2. **Sanitize `token_name` and `token_symbol`** before interpolating them into Markdown: strip or escape newlines (`\n`, `\r`) and Markdown heading/emphasis characters (`#`, `*`, `` ` ``).
3. **Prefer `FieldsDisplayMessage`** for structured data: the `FieldsDisplay` variant carries typed `Value` entries that wallets render without Markdown interpretation, eliminating the injection surface entirely.
4. Apply the same pattern already used in the ckBTC/ckDOGE minters: validate or encode any user-supplied string before it is interpolated into a `GenericDisplayMessage`.

## Proof of Concept

**PoC — memo injection (unprivileged)**

```rust
// Craft a memo that breaks out of the backtick code span
let malicious_memo = b"`\n\n# You are sending 1000 ICP to attacker\n\n**To:**\n`attacker_address".to_vec();

let transfer_args = TransferArg {
    memo: Some(Memo::from(malicious_memo)),
    amount: Nat::from(1_u64),   // actual amount: 1 e8s
    to: victim_account,
    ..Default::default()
};

// Wallet calls icrc21_canister_call_consent_message with these args.
// add_memo produces:
//   \n\n**Memo:**\n`\n\n# You are sending 1000 ICP to attacker\n\n**To:**\n`attacker_address`
// Rendered Markdown shows a fake heading and fake "To" field.
```

This can be verified with a unit test against `build_icrc21_consent_info` in `packages/icrc-ledger-types/src/icrc21/lib.rs` (lines 324–495): pass a `TransferArg` with the crafted memo, request `GenericDisplay`, and assert that the returned `GenericDisplayMessage` string contains the injected heading when rendered as Markdown. The memo bytes (55 bytes) fit well within the 500-byte `MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES` limit.