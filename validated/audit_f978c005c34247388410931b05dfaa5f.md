### Title
Unvalidated Zero `refund_recipient` in L1→L2 Transactions Permanently Burns Gas Refund Tokens - (`File: basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs`)

---

### Summary

In `process_l1_transaction`, the `refund_recipient` for L1→L2 priority transactions is read directly from `transaction.reserved[1]` without any validation. If this field is zero (the default when not explicitly set), the bootloader mints the unused-gas refund to `address(0)`, permanently burning tokens from the treasury. There is no fallback to `transaction.from()` and no zero-address guard. The code itself acknowledges the missing check with a `// TODO: validate address?` comment.

---

### Finding Description

For L1→L2 priority transactions, the gas refund recipient is stored in `reserved[1]` of the ABI-encoded transaction. In `process_l1_transaction`, after computing the refund amount, the bootloader reads this field and mints the refund directly to whatever address it contains:

```rust
let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
mint_base_token::<S, Config>(
    system, system_functions, memories.reborrow(),
    &to_refund_recipient, &refund_recipient, ...
``` [1](#0-0) 

There is no check that `refund_recipient != address(0)` before minting. The `validate_structure` function for ABI-encoded transactions explicitly leaves this unvalidated:

```rust
// reserved[1] = refund recipient for l1 to l2 and upgrade txs
match tx_type {
    Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
        // TODO: validate address?
    }
``` [2](#0-1) 

The `L1TxBuilder` in the test rig defaults `refund_recipient` to `Address::default()` (zero address) when not explicitly set:

```rust
refund_recipient: self.refund_recipient.unwrap_or_default(),
``` [3](#0-2) 

The regression test `test_treasury_based_token_distribution_regression` confirms this behavior is live: it uses `refund_recipient = address(0)` and asserts the refund is credited to `address(0)`, treating it as expected behavior rather than a bug. [4](#0-3) 

For L2 transactions, the refund always goes to `transaction.from()` — there is no analogous zero-address risk there: [5](#0-4) 

The L1→L2 path is the only one that uses the caller-supplied `reserved[1]` field without sanitization.

---

### Impact Explanation

When an L1→L2 priority transaction is submitted with `refund_recipient = address(0)` (either by omission or explicit zero), the bootloader mints the unused-gas refund — `(gas_limit - gas_used) * gas_price` — to `address(0)`. These tokens are deducted from the treasury (`BASE_TOKEN_HOLDER_ADDRESS`) and sent to an unrecoverable address. The treasury balance is permanently reduced by the refund amount with no corresponding benefit to any real user. For transactions with large gas limits and low actual gas usage, this loss can be substantial.

---

### Likelihood Explanation

The `L1TxBuilder` defaults `refund_recipient` to zero when not set, and the `// TODO: validate address?` comment confirms the ZKsync OS team is aware this field is unvalidated. Any L1→L2 transaction submitted without an explicit `refund_recipient` — a common pattern for simple ETH deposits or contract calls initiated from L1 — will silently burn the refund. The path is reachable by any unprivileged user submitting a standard priority transaction.

---

### Recommendation

In `process_l1_transaction`, before minting the refund, check whether `refund_recipient` is `address(0)` and fall back to `transaction.from()`:

```rust
let refund_recipient = {
    let raw = u256_to_b160_checked(transaction.reserved[1].read());
    if raw == B160::ZERO {
        transaction.from.read()
    } else {
        raw
    }
};
```

Additionally, remove the `// TODO: validate address?` placeholder in `validate_structure` and enforce the non-zero constraint there. [1](#0-0) [2](#0-1) 

---

### Proof of Concept

1. Submit an L1→L2 priority transaction with `reserved[1] = 0` (zero `refund_recipient`), `gas_limit = 200_000`, `gas_price = 1000`, and a simple ETH transfer that uses ~21,000 gas.
2. The bootloader computes `to_refund_recipient = (200_000 - 21_000) * 1000 = 179_000_000` tokens.
3. `u256_to_b160_checked(0)` returns `B160::ZERO`.
4. `mint_base_token` is called with `to = address(0)`, minting 179,000,000 tokens to the zero address.
5. The treasury balance decreases by 179,000,000 tokens; `address(0)` balance increases by 179,000,000 tokens; the actual sender receives nothing.
6. The existing test `test_treasury_based_token_distribution_regression` already demonstrates this exact flow with `refund_recipient = address(0)` and asserts the refund goes there — confirming the behavior is present and unguarded in the current codebase. [6](#0-5)

### Citations

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/process_l1_transaction.rs (L336-344)
```rust
    if to_refund_recipient > U256::ZERO {
        let refund_recipient = u256_to_b160_checked(transaction.reserved[1].read());
        mint_base_token::<S, Config>(
            system,
            system_functions,
            memories.reborrow(),
            &to_refund_recipient,
            &refund_recipient,
            l1_chain_id,
```

**File:** basic_bootloader/src/bootloader/transaction/abi_encoded/mod.rs (L267-273)
```rust
        // reserved[1] = refund recipient for l1 to l2 and upgrade txs
        match tx_type {
            Self::L1_L2_TX_TYPE | Self::UPGRADE_TX_TYPE => {
                // TODO: validate address?
            }
            _ => unreachable!(),
        }
```

**File:** tests/rig/src/utils/mod.rs (L409-409)
```rust
            refund_recipient: self.refund_recipient.unwrap_or_default(),
```

**File:** tests/instances/transactions/src/lib.rs (L1843-1843)
```rust
    let refund_recipient = address!("0000000000000000000000000000000000000000"); // refund recipient (zero address)
```

**File:** tests/instances/transactions/src/lib.rs (L1907-1943)
```rust
    // Calculate total amount that should go to operator (fee + refund)
    // Refund recipient is 0 in this test
    let gas_limit = 100_000u64;
    let gas_refund = gas_limit - gas_used;
    let refund_amount = U256::from(gas_refund) * U256::from(gas_price);
    let total_to_operator = fee_paid_to_operator;
    let total_to_refund_recipient = refund_amount;

    // Verify treasury balance decreased by max fee (fees + refund)
    let treasury_decrease = treasury_initial_balance - treasury_final_balance;
    let expected_treasury_decrease = total_to_operator + total_to_refund_recipient;
    assert_eq!(
        treasury_decrease, expected_treasury_decrease,
        "Treasury should decrease by total operator payment plus refund and value transferred"
    );

    // Verify operator received total payment from treasury (fee + refund)
    let operator_increase = operator_final_balance - operator_initial_balance;
    assert_eq!(
        operator_increase, total_to_operator,
        "Operator should receive fee + refund from treasury"
    );

    // Verify recipient received value from treasury (not minted)
    let recipient_increase = recipient_final_balance - recipient_initial_balance;
    assert_eq!(
        recipient_increase, value_to_transfer,
        "Recipient should receive exact value amount from treasury"
    );

    // Verify refund recipient received value from treasury (not minted)
    let refund_recipient_increase =
        refund_recipient_final_balance - refund_recipient_initial_balance;
    assert_eq!(
        refund_recipient_increase, total_to_refund_recipient,
        "Refund recipient should receive correct refund amount from treasury"
    );
```

**File:** basic_bootloader/src/bootloader/transaction_flow/zk/mod.rs (L455-457)
```rust
            // refund
            let refund_recipient = transaction.from();
            let token_to_refund =
```
