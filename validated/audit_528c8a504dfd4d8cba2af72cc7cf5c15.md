Audit Report

## Title
SNS Swap Canister: Unauthenticated ICP Donation to Buyer Subaccount Bypasses Participation Accounting, Enabling Swap Cap Manipulation - (File: `rs/sns/swap/src/swap.rs`)

## Summary
The SNS Swap canister's `refresh_buyer_token_e8s` reads the raw ICP ledger balance of a buyer's subaccount to determine participation credit. Because any principal can transfer ICP to any buyer's subaccount on the ICP ledger without calling `refresh_buyer_tokens`, an attacker can inflate a buyer's credited participation by donating ICP directly to that subaccount. The optional ticket system does not prevent this: if no ticket exists for the buyer, the ticket check is entirely skipped, allowing the full donated balance to be credited and consuming `available_direct_participation_e8s`.

## Finding Description
`refresh_buyer_token_e8s` reads the full ledger balance of the buyer's subaccount:

```rust
// rs/sns/swap/src/swap.rs L1153-1163
let account = Account {
    owner: this_canister.get().0,
    subaccount: Some(principal_to_subaccount(&buyer)),
};
icp_ledger.account_balance(account).await...get_e8s()
``` [1](#0-0) 

The increment is computed as `e8s - old_amount_icp_e8s`, capped at `available_direct_participation_e8s`: [2](#0-1) 

The ticket check is guarded by `if let Some(ticket) = ...` — if no ticket exists for the buyer, the entire check is skipped, as the code comment explicitly confirms:

```rust
// rs/sns/swap/src/swap.rs L1250-1272
if let Some(ticket_sns_sale_canister) =
    memory::OPEN_TICKETS_MEMORY.with(|m| m.borrow().get(&principal))
{
    // ... ticket amount check ...
}
// If there exists no ticket for the buyer, the payment flow will simply ignore the ticket
``` [3](#0-2) 

Furthermore, even when a ticket exists, the check only rejects if `amount_ticket > requested_increment_e8s` — it does not cap the credited amount to the ticket value. It only enforces a lower bound, not an upper bound. [4](#0-3) 

After crediting the buyer, `update_total_participation_amounts()` is called, updating `direct_participation_icp_e8s` and reducing `available_direct_participation_e8s`: [5](#0-4) 

The `available_direct_participation_e8s` is computed as `max - current`: [6](#0-5) 

**Exploit path:**
1. Attacker calls `icrc1_transfer` on the ICP ledger, sending ICP to `Account { owner: swap_canister_id, subaccount: principal_to_subaccount(&victim_or_self) }`.
2. Attacker (or anyone) calls `swap.refresh_buyer_tokens(victim_principal)` — the `buyer` parameter is not restricted to the caller.
3. The swap reads the inflated ledger balance, computes the increment, and credits the buyer's `BuyerState`, consuming `available_direct_participation_e8s`.
4. If the cap is reached, `can_commit` returns true and the swap can be committed early.

The `BuyerState` proto invariant explicitly acknowledges this asymmetry (`icp.amount_e8 <= icp_ledger.balance_of(subaccount(swap_canister, P))`), confirming the design allows ledger balance to exceed recorded participation — the attack exploits exactly this gap. [7](#0-6) 

## Impact Explanation
This is a **High** severity finding. An attacker can force early swap commitment by exhausting `available_direct_participation_e8s` before the intended number of legitimate participants have joined. This constitutes a significant SNS governance/financial impact: the swap finalizes at an attacker-chosen moment, distorting SNS token distribution (buyers credited with donated ICP receive more SNS tokens than they paid for), and potentially blocking new legitimate participants once the cap is consumed. This matches the allowed impact: *"Significant SNS security impact with concrete user or protocol harm."*

## Likelihood Explanation
- **No special privileges required**: Any principal with ICP can call `icrc1_transfer` on the ICP ledger to any subaccount.
- **`refresh_buyer_tokens` accepts any `buyer` principal as a parameter**, so the attacker does not need the victim to act.
- **Cost**: The attacker loses the donated ICP (it is locked in the victim's `BuyerState`), making this a capital-cost attack. For a well-capitalized attacker seeking to manipulate a high-value SNS swap, this is economically rational.
- **Ticket bypass is trivially achieved**: Simply do not call `new_sale_ticket` before transferring ICP. The swap will process the full balance with no ticket check.

## Recommendation
1. **Make the ticket flow mandatory**: Require a valid open ticket for every `refresh_buyer_tokens` call. Reject calls with no ticket, rather than silently ignoring the absence of one.
2. **Cap credited increment to ticket amount**: When a ticket exists, cap `actual_increment_e8s` to `amount_ticket`, not just enforce a lower bound. This prevents donated excess ICP from being credited.
3. **Alternatively, restrict `refresh_buyer_tokens` to the buyer themselves**: Require `caller == buyer` so an attacker cannot trigger crediting on behalf of a victim.

## Proof of Concept
```
Setup:
  - SNS swap OPEN, max_direct_participation_icp_e8s = 1000 ICP
  - current_direct_participation_e8s = 900 ICP
  - available_direct_participation_e8s = 100 ICP

Steps:
  1. Attacker calls ICP ledger icrc1_transfer:
       to: Account { owner: swap_canister_id,
                     subaccount: principal_to_subaccount(victim_principal) }
       amount: 100 ICP  (no swap ticket created)

  2. Attacker calls swap.refresh_buyer_tokens({ buyer: victim_principal }).
     (No ticket exists → ticket check skipped entirely per L1271 comment)

  3. swap reads ledger balance = 100 ICP for victim subaccount.
     old_amount_icp_e8s = 0
     requested_increment_e8s = 100 ICP
     actual_increment_e8s = min(100, 100) = 100 ICP
     → victim BuyerState credited 100 ICP

  4. update_total_participation_amounts():
     direct_participation_icp_e8s = 1000 ICP = max
     available_direct_participation_e8s = 0

  5. can_commit() returns true → swap committed early.
     Victim receives SNS neurons for 100 ICP they did not pay.
     Attacker loses 100 ICP but controls swap finalization timing.

Reproducible as a PocketIC integration test:
  - Deploy swap canister + mock ICP ledger
  - Seed 9 buyers × 100 ICP via normal flow
  - Execute steps 1-5 above
  - Assert can_commit() == true after step 3
  - Assert victim BuyerState.amount_icp_e8s == 100
```

### Citations

**File:** rs/sns/swap/src/swap.rs (L522-535)
```rust
    pub fn available_direct_participation_e8s(&self) -> u64 {
        let max_direct_participation_e8s = self.max_direct_participation_e8s();
        let current_direct_participation_e8s = self.current_direct_participation_e8s();
        max_direct_participation_e8s
            .checked_sub(current_direct_participation_e8s)
            .unwrap_or_else(|| {
                log!(
                    ERROR,
                    "max_direct_participation_e8s ({max_direct_participation_e8s}) \
                    < current_direct_participation_e8s ({current_direct_participation_e8s})"
                );
                0
            })
    }
```

**File:** rs/sns/swap/src/swap.rs (L1153-1163)
```rust
        let e8s = {
            let account = Account {
                owner: this_canister.get().0,
                subaccount: Some(principal_to_subaccount(&buyer)),
            };
            icp_ledger
                .account_balance(account)
                .await
                .map_err(|x| x.to_string())?
                .get_e8s()
        };
```

**File:** rs/sns/swap/src/swap.rs (L1222-1225)
```rust
        // Subtraction safe because of the preceding if-statement.
        let requested_increment_e8s = e8s - old_amount_icp_e8s;
        let actual_increment_e8s = std::cmp::min(max_increment_e8s, requested_increment_e8s);
        let new_balance_e8s = old_amount_icp_e8s.saturating_add(actual_increment_e8s);
```

**File:** rs/sns/swap/src/swap.rs (L1250-1272)
```rust
        if let Some(ticket_sns_sale_canister) =
            memory::OPEN_TICKETS_MEMORY.with(|m| m.borrow().get(&principal))
        {
            let amount_ticket = ticket_sns_sale_canister.amount_icp_e8s;
            // If the user has already bought tokens in this swap at a prior to the current purchase the
            // balance in the subaccount of the SNS sales canister that corresponds to the user will
            // show both the ICP balance used for the previous buy and the ICP balance used to make
            // this new purchase of SNS tokens (requested_increment_e8s + old_amount_icp_e8s).
            // If the ticket has a lower amount specified than what is the requested amount of
            // tokens according to the ICP balance in the subaccount, this check should pass
            // and the actual requested amount of tokens will be used.
            // Lower amounts than specified on the ticket are not excepted.
            if amount_ticket > requested_increment_e8s {
                return Err(format!(
                    "The available balance to be topped up ({requested_increment_e8s}) \
                    by the buyer is smaller than the amount requested ({amount_ticket})."
                ));
            }
            // The requested balance in the ticket matches the balance to be topped up in the swap
            // --> Delete fully executed ticket, if it exists and proceed with the top up
            memory::OPEN_TICKETS_MEMORY.with(|m| m.borrow_mut().remove(&principal));
            // If there exists no ticket for the buyer, the payment flow will simply ignore the ticket
        }
```

**File:** rs/sns/swap/src/swap.rs (L1285-1292)
```rust
        self.buyers
            .entry(buyer.to_string())
            .or_insert_with(|| BuyerState::new(0))
            .set_amount_icp_e8s(new_balance_e8s);
        // We compute the current participation amounts once and store the result in Swap's state,
        // for efficiency reasons.
        self.update_total_participation_amounts();

```

**File:** rs/sns/swap/src/gen/ic_sns_swap.pb.v1.rs (L731-737)
```rust
    /// Invariant between canisters in the OPEN state:
    ///
    ///   ```text
    ///   icp.amount_e8 <= icp_ledger.balance_of(subaccount(swap_canister, P)),
    ///   ```
    ///
    /// where `P` is the principal ID associated with this buyer's state.
```
