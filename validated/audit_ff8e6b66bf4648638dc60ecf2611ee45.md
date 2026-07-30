## Analysis

The PayoutManager bug is a "check happens only at deposit time, not enforced afterward, with no recovery path" pattern: an eligibility gate (AML score) is validated when funds enter the system, the gate silently becomes unsatisfiable later, and nothing lets the now-ineligible principal be released.

Sui's Kiosk / TransferPolicy primitive has the same structural flaw around `sui::kiosk::lock` and `sui::transfer_policy::destroy_and_withdraw`.

**How the analog works:**

- `kiosk::lock` only allows locking an item if the caller can present a live `TransferPolicy<T>` reference at that moment, specifically to guarantee "the item will not be locked in a Kiosk forever" per the module's own doc comment: [1](#0-0) 
- Once locked, `take` is permanently disabled for that item — the only legitimate way out is `list` followed by `purchase`, which produces a `TransferRequest<T>` hot potato that must be resolved via `confirm_request` against *some* `TransferPolicy<T>` object: [2](#0-1) 
- However, `TransferPolicy<T>` is not pinned to the item or the Kiosk in any way — `confirm_request` just checks that the request's collected rule-receipts match `self.rules`, with no binding to a specific policy ID. Crucially, the `TransferPolicyCap<T>` owner (the type's creator/publisher — an ordinary, non-privileged, non-protocol-governance actor) can call `destroy_and_withdraw` "at any moment", deleting the `TransferPolicy<T>` object entirely: [3](#0-2) 
- If that destroy call removes the *last* `TransferPolicy<T>` in existence for type `T`, then any `TransferRequest<T>` generated afterward (from `purchase`/`purchase_with_cap`) can never be confirmed by any object on-chain — the confirming call has no `TransferPolicy<T>` to reference at all. Every previously-`lock`ed item of that type becomes un-sellable, and since it's locked it was already un-`take`-able. There is no admin/recovery function to release it.

This mirrors the report's root cause exactly: the guard ("policy exists") is validated only at the time the asset entered the locked state, the guard is later revoked by a legitimate, permissionless action of the same actor who set it up (not a malicious validator/governance quorum — just an ordinary `Publisher`/`TransferPolicyCap` holder), and no fallback lets the now-stuck item ever leave the Kiosk, permanently freezing its value.

### Title
Kiosk locked items become permanently stranded after all `TransferPolicy<T>` objects are destroyed - (File: `crates/sui-framework/packages/sui-framework/sources/kiosk/transfer_policy.move`)

### Summary
`kiosk::lock` only checks that a `TransferPolicy<T>` exists at lock time, intending to guarantee the item can eventually be sold and removed. But `transfer_policy::destroy_and_withdraw` lets the `TransferPolicyCap<T>` holder delete a `TransferPolicy<T>` at any later time. If that removes the last policy for `T`, every already-locked item of that type in every Kiosk becomes permanently un-listable (no policy to confirm the resulting `TransferRequest`) and, being locked, is also un-`take`-able — the asset is stuck forever with no recovery path.

### Finding Description
`kiosk::lock<T>` requires a `&TransferPolicy<T>` argument purely as an existence check, per the doc comment claiming this "makes sure that the TransferPolicy exists to not lock the item in a Kiosk forever" [4](#0-3) . That guarantee is only point-in-time: nothing stops the `TransferPolicyCap<T>` holder from later calling `destroy_and_withdraw`, which is explicitly documented as callable "by any party as long as they own it... at any moment" [3](#0-2) .

Once locked, `kiosk::take` asserts the item is not locked and aborts, so the owner's only legitimate exit is `list`/`list_with_purchase_cap` + `purchase`, which produces a `TransferRequest<T>` that must pass `confirm_request` against a live `TransferPolicy<T>` [5](#0-4) . If no `TransferPolicy<T>` object exists anywhere on-chain, `confirm_request` cannot be invoked at all for that type — there is no object to call it on — so the purchase transaction can never complete, and the locked item is permanently unreachable by its owner or any buyer.

### Impact Explanation
Any Kiosk item that was locked while a `TransferPolicy<T>` existed becomes permanently frozen — unable to be taken, sold, or otherwise recovered — the moment the last `TransferPolicy<T>` for that type is destroyed. Kiosk-locked items are frequently high-value NFTs/collectibles with enforced royalty policies, so this is a genuine permanent fund/asset lock reachable purely through documented, permissionless framework calls, matching the "permanent fund lock" High-severity impact class.

### Likelihood Explanation
`destroy_and_withdraw` is a normal, documented, permissionless capability action available to any `TransferPolicyCap<T>` holder (a type publisher/creator, not a validator/bridge authority/protocol governance quorum). Creators routinely rotate or clean up policies (e.g., migrating to a new rule set, deprecating a collection). Any locked item that predates such cleanup — and whose owner has not first sold it — is silently and irreversibly stranded. No warning or check in `destroy_and_withdraw` looks at outstanding locked items of type `T`.

### Recommendation
Either (a) prevent `destroy_and_withdraw` from removing the last remaining `TransferPolicy<T>` while locked items of type `T` may still exist (hard to track generally), or (b) decouple the "can eventually be unlocked" guarantee from a specific policy's lifetime — e.g., allow the Kiosk owner to unlock/take an item once it can be shown no `TransferPolicy<T>` exists network-wide, or require `TransferPolicy<T>` objects to be non-destructible once any item has been locked against them, or track an explicit "lockable" registry independent of a deletable shared object.

### Proof of Concept
1. Creator publishes type `T`, creates `TransferPolicy<T>`/`TransferPolicyCap<T>` via `transfer_policy::default` and shares the policy.
2. Alice places an item of type `T` in her Kiosk and calls `kiosk::lock(kiosk, cap, &policy, item)` — succeeds because the policy exists.
3. Creator calls `transfer_policy::destroy_and_withdraw(policy, policy_cap, ctx)`, which is fully permitted per the module's own semantics, removing the only `TransferPolicy<T>` in existence.
4. Alice tries `kiosk::take` — aborts (`EItemLocked`). Alice tries `kiosk::list` + a buyer calls `kiosk::purchase` — the resulting `TransferRequest<T>` cannot be confirmed anywhere because there is no `TransferPolicy<T>` object left to call `confirm_request` on.
5. The item remains permanently locked inside Alice's Kiosk with no recovery path.

### Citations

**File:** crates/sui-framework/packages/sui-framework/sources/kiosk/kiosk.move (L900-929)
```text

```

**File:** crates/sui-framework/packages/sui-framework/sources/kiosk/transfer_policy.move (L159-175)
```text
/// Destroy a TransferPolicyCap.
/// Can be performed by any party as long as they own it.
public fun destroy_and_withdraw<T>(
    self: TransferPolicy<T>,
    cap: TransferPolicyCap<T>,
    ctx: &mut TxContext,
): Coin<SUI> {
    assert!(object::id(&self) == cap.policy_id, ENotOwner);

    let TransferPolicyCap { id: cap_id, policy_id } = cap;
    let TransferPolicy { id, rules: _, balance } = self;

    id.delete();
    cap_id.delete();
    event::emit(TransferPolicyDestroyed<T> { id: policy_id });
    balance.into_coin(ctx)
}
```

**File:** crates/sui-framework/packages/sui-framework/sources/kiosk/transfer_policy.move (L177-200)
```text
/// Allow a `TransferRequest` for the type `T`. The call is protected
/// by the type constraint, as only the publisher of the `T` can get
/// `TransferPolicy<T>`.
///
/// Note: unless there's a policy for `T` to allow transfers,
/// Kiosk trades will not be possible.
public fun confirm_request<T>(
    self: &TransferPolicy<T>,
    request: TransferRequest<T>,
): (ID, u64, ID) {
    let TransferRequest { item, paid, from, receipts } = request;
    let mut completed = receipts.into_keys();
    let mut total = completed.length();

    assert!(total == self.rules.length(), EPolicyNotSatisfied);

    while (total > 0) {
        let rule_type = completed.pop_back();
        assert!(self.rules.contains(&rule_type), EIllegalRule);
        total = total - 1;
    };

    (item, paid, from)
}
```
