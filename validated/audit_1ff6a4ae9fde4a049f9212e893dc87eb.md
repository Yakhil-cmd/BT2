## Analysis: Dead Man's Switch `keep_alive` — Unauthorized Account Binding

The external Sherlock report's core invariant is: **a party who has no legitimate claim over a liveness/cooldown timestamp should not be able to reset or extend it on behalf of another party**, thereby subverting a safety mechanism that depends on that timestamp. I traced this invariant into the Aptos-native trading market code and found a direct, locally-provable analog in the `dead_mans_switch_operations` module. [1](#0-0) 

### Title
Unvalidated `account` parameter in `dead_mans_switch_operations::keep_alive` allows any caller to reset another trader's liveness state, defeating stale-order admission checks - (File: `aptos-move/framework/aptos-experimental/sources/trading/market/dead_mans_switch_operations.move`)

### Summary
`aptos_experimental::dead_mans_switch_operations::keep_alive` is a `public fun` that takes an arbitrary `account: address` and mutates that account's dead man's switch state without any check that the caller is, or is authorized by, that account. The function's own doc comment admits this: "This function does not validate the account parameter. It is the caller's responsibility to ensure proper signer validation is performed before calling this function if needed." [2](#0-1)  This breaks the sender-to-state binding that the dead man's switch safety mechanism depends on.

### Finding Description
The dead man's switch is designed so that a trader's own periodic "keep-alive" calls extend the validity window (`expiration_time_secs`) of their outstanding orders; if the trader stops calling `keep_alive`, their session expires and `cleanup_expired_orders` / `cleanup_expired_bulk_order` treat their orders as invalid via `is_order_valid`. [3](#0-2) 

The state-mutating primitive, `dead_mans_switch_tracker::keep_alive`, is `public(friend)` and correctly restricted to friend modules, but the wrapper `dead_mans_switch_operations::keep_alive` exposes it as a plain `public fun` keyed purely on a caller-supplied `account: address` parameter — there is no `signer` argument and no assertion that `signer::address_of(caller) == account`: [4](#0-3) 

Because the function is `public` (not restricted to `friend`), any module in the same package that can obtain a `&mut Market<M>` reference can call `keep_alive` on behalf of *any* account, not just the caller's own. This is precisely the same class of bug as the Sherlock finding: the party who should have no influence over a liveness timestamp (PartyB in the original report / an unrelated caller here) is able to freely rewrite the timestamp binding meant to gate a safety-critical admission decision (force-close eligibility in the original report / order-validity/cleanup eligibility here).

### Impact Explanation
If reachable by an unprivileged caller (e.g., via any entry-point wrapper that forwards a user-supplied address rather than the transaction signer, or via composable calls from other modules that don't re-validate the signer), this allows:
- **Griefing/DoS on a victim's session state**: An attacker can force `session_start_time_secs = current_time` on a victim's account at an inopportune time (whenever the victim's session has already lapsed by even one second), immediately invalidating all of the victim's pending orders via `is_order_valid`, even though the victim never authorized this state change. [5](#0-4) 
- **Defeating the entire safety mechanism**: More critically, an attacker can indefinitely call `keep_alive(account=victim, timeout_seconds=<large>)` to keep extending `expiration_time_secs`, exactly mirroring the "malicious PartyB partially closes dust to keep resetting the cooldown timer" pattern from the source report. This permanently blocks `cleanup_expired_orders`/`cleanup_expired_bulk_order` from ever treating the victim's orders as expired via `is_order_valid`, since `expiration_time_secs` never lapses. [6](#0-5)  This means stale orders that *should* fail the dead-man's-switch admission check continue to be treated as valid and executable — a direct "pre-validation mismatch that causes state which should fail admission to remain admitted," causing counterparties to unknowingly trade against a trader who is actually unresponsive, defeating the stated purpose of the feature: "This security feature prevents stale orders from being executed if a trader loses connection or becomes unresponsive." [7](#0-6) 

### Likelihood Explanation
**This cannot be rated High/Critical with full confidence from the index alone.** I was unable to locate and verify, within the available tool budget, the actual `entry fun` transaction wrapper(s) in `order_placement.move`/`market_types.move` that call this `keep_alive` function to confirm whether user-facing entry points always pass `signer::address_of(caller)` as `account` (in which case this is unreachable by design) or whether some path passes a caller-controlled address (in which case it is directly exploitable). The grep results show `is_dead_mans_switch_enabled`/`get_dead_mans_switch_tracker` are used in `market_types.move` and `order_placement.move`, but I could not read those call sites before running out of iterations. Given the function is `public` (not `friend`) and its own documentation explicitly disclaims responsibility for signer validation "if needed," the root cause (missing binding between transaction signer and mutated account) is proven in local code; what remains unconfirmed is the calling context's actual privilege level.

### Recommendation
- Change `dead_mans_switch_operations::keep_alive` to accept a `signer` (or restrict visibility to `friend`/`entry` with an explicit `assert!(signer::address_of(caller) == account, ...)`) so the mutated `account` is always cryptographically bound to the transaction's authenticated sender.
- Audit all callers of this function (and any entry-point wrappers) to confirm the `account` argument is always derived from the signer, never from a raw address parameter.
- Add regression tests that a non-owner caller cannot alter another account's `KeepAliveState`.

### Proof of Concept
Conceptual PoC (pending confirmation of a reachable entry point):
1. Victim enables the dead man's switch and is actively calling `keep_alive` on their own account, keeping orders alive as intended.
2. Attacker calls (directly, or via any exposed wrapper that forwards a caller-supplied address) `dead_mans_switch_operations::keep_alive(market, victim_address, MAX_TIMEOUT)`.
3. Because `keep_alive` performs no signer check, the call succeeds, and `victim_address`'s `expiration_time_secs` is extended indefinitely by the attacker, exactly as PartyB could indefinitely extend `quote.modifyTimestamp` in the source report — permanently preventing `cleanup_expired_orders` from ever invalidating the victim's stale orders, defeating the intended liveness/safety check.

Due to index size limits, the full call graph proving/disproving direct end-user reachability of this function could not be completely traced; a Devin session with full repository access is recommended to confirm the entry-point wiring in `order_placement.move` and `market_types.move` before treating this as a confirmed exploitable finding.

### Citations

**File:** aptos-move/framework/aptos-experimental/sources/trading/market/dead_mans_switch_operations.move (L19-41)
```text
    /// Cleans up expired orders based on dead man's switch rules.
    ///
    /// This function validates that each order's creation timestamp is valid according to
    /// the dead man's switch tracker. If an order was created before the current keep-alive
    /// session or if the session has expired, the order will be cancelled.
    ///
    /// Parameters:
    /// - market: The market instance
    /// - order_ids: Vector of order IDs to check and potentially cancel
    /// - callbacks: The market clearinghouse callbacks for cleanup operations
    ///
    /// Aborts:
    /// - E_DEAD_MANS_SWITCH_NOT_ENABLED: If dead man's switch is not enabled for this market
    /// - E_TOO_MANY_ORDERS: If more than MAX_ORDERS_CLEANED_PER_CALL order IDs are provided
    public fun cleanup_expired_orders<M: store + copy + drop, R: store + copy + drop>(
        market: &mut Market<M>,
        order_ids: vector<OrderId>,
        callbacks: &MarketClearinghouseCallbacks<M, R>
    ) {
        // Check if dead man's switch is enabled
        assert!(market.is_dead_mans_switch_enabled(), E_DEAD_MANS_SWITCH_NOT_ENABLED);
        // Cap the number of orders that can be cleaned in a single call
        assert!(order_ids.length() <= MAX_ORDERS_CLEANED_PER_CALL, E_TOO_MANY_ORDERS);
```

**File:** aptos-move/framework/aptos-experimental/sources/trading/market/dead_mans_switch_operations.move (L136-175)
```text
    /// Updates the keep-alive state for a trader in the dead man's switch.
    /// This function should be called periodically by traders to keep their orders active.
    ///
    /// This function does not validate the account parameter. It is the caller's responsibility
    /// to ensure proper signer validation is performed before calling this function if needed.
    ///
    /// Behavior:
    /// - First update: Creates a new session starting at time 0 (all existing orders remain valid)
    /// - Subsequent updates before expiration: Extends the current session
    /// - Update after expiration: Starts a new session (invalidates all orders placed before now)
    ///
    /// Parameters:
    /// - market: The market instance
    /// - account: The trader's address
    /// - timeout_seconds: Duration in seconds until the session expires.
    ///   Must be >= min_keep_alive_time_secs or 0 to disable.
    ///   Pass 0 to disable the dead man's switch for this account.
    ///
    /// Aborts:
    /// - E_DEAD_MANS_SWITCH_NOT_ENABLED: If dead man's switch is not enabled for this market
    /// - E_KEEP_ALIVE_TIMEOUT_TOO_SHORT: If timeout is less than minimum and not zero
    ///
    /// ```
    public fun keep_alive<M: store + copy + drop>(
        market: &mut Market<M>, account: address, timeout_seconds: u64
    ) {
        // Check if dead man's switch is enabled
        assert!(market.is_dead_mans_switch_enabled(), E_DEAD_MANS_SWITCH_NOT_ENABLED);

        let parent = market.get_parent();
        let market_addr = market.get_market();
        let tracker = market.get_dead_mans_switch_tracker_mut();
        dead_mans_switch_tracker::keep_alive(
            tracker,
            parent,
            market_addr,
            account,
            timeout_seconds
        );
    }
```

**File:** aptos-move/framework/aptos-experimental/sources/trading/market/dead_mans_switch_tracker.move (L1-6)
```text
/// # Dead Man's Switch Tracker Module
///
/// This module implements a dead man's switch mechanism for trading orders, ensuring that
/// orders are automatically invalidated if a trader's session expires without periodic
/// keep-alive updates. This security feature prevents stale orders from being executed
/// if a trader loses connection or becomes unresponsive.
```

**File:** aptos-move/framework/aptos-experimental/sources/trading/market/dead_mans_switch_tracker.move (L174-230)
```text
    /// Checks if an order is valid based on the dead man's switch state
    ///
    /// An order is valid if:
    /// 1. No keep-alive state exists for the account (dead man's switch not enabled), OR
    /// 2. The order was created after the current session started AND the session hasn't expired
    ///
    /// # Parameters
    /// - `tracker`: Reference to the dead man's switch tracker
    /// - `account`: The trader's address
    /// - `order_creation_time_secs`: When the order was created (in seconds since epoch)
    ///
    /// # Returns
    /// `true` if the order is valid, `false` if it should be cancelled
    ///
    /// # Validation Logic
    /// ```
    /// if no keep-alive state:
    ///     return true  // No dead man's switch, all orders valid
    /// if order_creation_time < session_start_time:
    ///     return false  // Order from expired session
    /// if current_time > expiration_time:
    ///     return false  // Session expired (exclusive of expiration time)
    /// return true  // Order valid
    /// ```
    ///
    /// # Example
    /// ```move
    /// let order_time = 1000;
    /// let is_valid = is_order_valid(&tracker, trader_addr, order_time);
    /// if (!is_valid) {
    ///     // Cancel the order
    /// }
    /// ```
    public fun is_order_valid(
        tracker: &DeadMansSwitchTracker,
        account: address,
        order_creation_time_secs: Option<u64>
    ): bool {
        let itr = tracker.state.internal_find(&account);
        if (itr.iter_is_end(&tracker.state)) {
            // No keep-alive set, so all orders are valid
            return true;
        };
        let current_time = aptos_std::timestamp::now_seconds();
        let order_creation_time_secs =
            if (order_creation_time_secs.is_some()) {
                order_creation_time_secs.destroy_some()
            } else {
                current_time
            };
        let state = itr.iter_borrow(&tracker.state);
        if (state.session_start_time_secs > order_creation_time_secs) {
            // Order was placed before the session started, so it is invalid
            return false;
        };
        state.expiration_time_secs >= current_time
    }
```

**File:** aptos-move/framework/aptos-experimental/sources/trading/market/dead_mans_switch_tracker.move (L295-320)
```text
    public(friend) fun keep_alive(
        tracker: &mut DeadMansSwitchTracker,
        parent: address,
        market: address,
        account: address,
        timeout_seconds: u64
    ) {
        if (timeout_seconds == 0) {
            disable_keep_alive(tracker, parent, market, account);
            return;
        };
        assert!(
            timeout_seconds >= tracker.min_keep_alive_time_secs,
            E_KEEP_ALIVE_TIMEOUT_TOO_SHORT // ERROR_KEEP_ALIVE_TIMEOUT_TOO_SHORT
        );
        let current_time = aptos_std::timestamp::now_seconds();
        let expiration_time = current_time + timeout_seconds;
        let itr = tracker.state.internal_find(&account);
        if (!itr.iter_is_end(&tracker.state)) {
            let state = itr.iter_borrow_mut(&mut tracker.state);
            if (current_time > state.expiration_time_secs) {
                // Start a new session - this means any order placed before this time is invalidated
                state.session_start_time_secs = current_time;
            };
            // Update existing session
            state.expiration_time_secs = expiration_time;
```
