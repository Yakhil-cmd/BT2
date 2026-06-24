Audit Report

## Title
Memo Backtick Injection Breaks Inline Code Span, Enabling Arbitrary Markdown Field Injection in GenericDisplayMessage — (`packages/icrc-ledger-types/src/icrc21/responses.rs`)

## Summary

In `add_memo`, user-supplied memo bytes that are valid UTF-8 are interpolated verbatim into a single-backtick CommonMark code span (`\n\n**Memo:**\n\`{memo_str}\``). A memo containing a backtick character closes the code span prematurely, and all content between that interior backtick and the template's closing backtick is emitted as raw markdown. A malicious dapp can craft a 32-byte-or-fewer ICRC-1 memo that injects a visually authentic `**To:**` field into the ICRC-21 consent message, spoofing the displayed recipient and directly undermining the security guarantee ICRC-21 is designed to provide.

## Finding Description

`add_memo` at line 284 of `responses.rs` processes the memo as follows:

1. UTF-8 validity is checked; valid UTF-8 is used verbatim, otherwise hex-encoded: [1](#0-0) 

2. For `GenericDisplayMessage`, the raw string is interpolated into a single-backtick code span with no further sanitization: [2](#0-1) 

In CommonMark, a single-backtick code span is terminated by the next single backtick. A memo of `x\`\n\n**To:**\n\`evil` (17 bytes, valid UTF-8, within the 32-byte ICRC-1 limit) produces:

```
\n\n**Memo:**\n`x`\n\n**To:**\n`evil`
```

CommonMark parses this as: inline code `` `x` ``, then a new paragraph with bold heading `**To:**`, then inline code `` `evil` ``. This is visually identical to a legitimate `**To:**` field produced by `add_account`: [3](#0-2) 

The injected field appears **after** the real fields in the message. The memo flows from `TransferArg.memo` → `build_icrc21_consent_info` → `ConsentMessageBuilder.with_memo` → `add_memo` with no sanitization at any step: [4](#0-3) 

The `FieldsDisplayMessage` variant is not affected because it stores the memo as structured `Value::Text` data, not raw markdown: [5](#0-4) 

## Impact Explanation

ICRC-21 consent messages exist specifically to protect users from malicious dapps by showing a human-readable, trustworthy summary of what they are signing. A malicious dapp can set `TransferArg.to = attacker_address` and `TransferArg.memo = b"x\`\n\n**To:**\n\`victim_address"`. The resulting `GenericDisplayMessage` displays the real recipient (attacker) early in the message, then displays an attacker-injected `**To:** \`victim_address\`` at the bottom — where users scrolling to confirm the last visible field are deceived into approving a transfer to the attacker. This is a direct bypass of the primary security boundary ICRC-21 is designed to enforce, with concrete potential for user fund loss. This matches the **High** impact class: unauthorized access to ledger/wallet funds where exploitation requires a malicious dapp interaction (a meaningful per-target constraint).

## Likelihood Explanation

- The attacker is any dapp that can initiate an `icrc1_transfer` or `icrc2_approve` call on behalf of a user via ICRC-21.
- The payload is 17 bytes of printable ASCII, well within the 32-byte ICRC-1 memo limit.
- All bytes are valid UTF-8, passing the only guard in `add_memo`.
- No privileged access, key material, or infrastructure compromise is required.
- Any wallet rendering `GenericDisplayMessage` as markdown (the intended use, given the explicit `# heading`, `**bold**`, `` `code` `` formatting throughout `add_intent`, `add_account`, `add_amount`, `add_fee`) is affected. [6](#0-5) 

## Recommendation

Escape backtick characters in `memo_str` before interpolating into the markdown template. The most robust fix is to use a double-backtick fence and ensure the memo does not contain ` `` `, or to strip/encode all markdown-significant characters:

```rust
// Option 1: escape backticks
let safe_memo = memo_str.replace('`', "\\`");
message.push_str(&format!("\n\n**Memo:**\n`{safe_memo}`"));

// Option 2: strip all markdown-significant characters
let safe_memo = memo_str.replace(|c| matches!(c, '`' | '*' | '_' | '#' | '[' | ']' | '\\'), "");
message.push_str(&format!("\n\n**Memo:**\n`{safe_memo}`"));
```

The same fix should be applied to `add_account` and any other location where user-controlled data is interpolated into `GenericDisplayMessage` markdown. [7](#0-6) 

## Proof of Concept

```rust
// Memo bytes: x`\n\n**To:**\n`evil  (17 bytes, valid UTF-8)
let malicious_memo: Vec<u8> = b"x`\n\n**To:**\n`evil".to_vec();

// In add_memo:
// memo_str = "x`\n\n**To:**\n`evil"  (UTF-8 valid, passes guard)
// appended:  "\n\n**Memo:**\n`x`\n\n**To:**\n`evil`"

// CommonMark rendering:
//   **Memo:**
//   `x`
//
//   **To:**
//   `evil`
//
// Visually identical to a legitimate To: field.
```

A unit test can be written against `ConsentMessage::add_memo` with `GenericMemo::Icrc1Memo(malicious_memo)` on a `GenericDisplayMessage` variant, asserting that the resulting string does not contain `\n\n**To:**\n` outside of a code span. A fuzz test over the memo bytes can further confirm that no memo input produces unintended markdown structure in the output.

### Citations

**File:** packages/icrc-ledger-types/src/icrc21/responses.rs (L48-99)
```rust
    pub fn add_intent(&mut self, intent: Icrc21Function, token_name: Option<String>) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => match intent {
                Icrc21Function::Transfer | Icrc21Function::GenericTransfer => {
                    assert!(token_name.is_some());
                    message.push_str(&format!("# Send {}", token_name.unwrap()));
                    message
                        .push_str("\n\nYou are approving a transfer of funds from your account.");
                }
                Icrc21Function::Approve => {
                    message.push_str("# Approve spending");
                    message.push_str(
                            "\n\nYou are authorizing another address to withdraw funds from your account.",
                        );
                }
                Icrc21Function::TransferFrom => {
                    assert!(token_name.is_some());
                    message.push_str(&format!("# Spend {}", token_name.unwrap()));
                    message.push_str(
                        "\n\nYou are approving a transfer of funds from a withdrawal account.",
                    );
                }
            },
            ConsentMessage::FieldsDisplayMessage(fields_display) => match intent {
                Icrc21Function::Transfer | Icrc21Function::GenericTransfer => {
                    assert!(token_name.is_some());
                    fields_display.intent = format!("Send {}", token_name.unwrap());
                }
                Icrc21Function::Approve => {
                    fields_display.intent = "Approve spending".to_string();
                }
                Icrc21Function::TransferFrom => {
                    assert!(token_name.is_some());
                    fields_display.intent = format!("Spend {}", token_name.unwrap());
                }
            },
        }
    }

    pub fn add_account(&mut self, name: &str, account: String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!("\n\n**{name}:**\n`{account}`"))
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display.fields.push((
                name.to_string(),
                Value::Text {
                    content: account.to_string(),
                },
            )),
        }
    }
```

**File:** packages/icrc-ledger-types/src/icrc21/responses.rs (L284-295)
```rust
    pub fn add_memo(&mut self, memo: GenericMemo) {
        match memo {
            GenericMemo::Icrc1Memo(memo) => {
                // Check if the memo is a valid UTF-8 string and display it as such if it is.
                let memo_str = match std::str::from_utf8(memo.as_slice()) {
                    Ok(valid_str) => valid_str.to_string(),
                    Err(_) => hex::encode(memo.as_slice()),
                };
                match self {
                    ConsentMessage::GenericDisplayMessage(message) => {
                        message.push_str(&format!("\n\n**Memo:**\n`{memo_str}`"));
                    }
```

**File:** packages/icrc-ledger-types/src/icrc21/responses.rs (L296-298)
```rust
                    ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display
                        .fields
                        .push(("Memo".to_string(), Value::Text { content: memo_str })),
```

**File:** packages/icrc-ledger-types/src/icrc21/lib.rs (L392-395)
```rust
            if let Some(memo) = memo {
                display_message_builder =
                    display_message_builder.with_memo(GenericMemo::Icrc1Memo(memo.0));
            }
```
