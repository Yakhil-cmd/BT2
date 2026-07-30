### Title
Missing `paused` check in bridge token-claim path allows minting/withdrawal during emergency freeze while `send_token` is halted - (File: `crates/sui-framework/packages/bridge/sources/bridge.move`)

### Summary
The Sui native bridge module enforces its emergency-pause invariant (`inner.paused`) inconsistently across the mutation entry points of `BridgeInner`, mirroring the MagicSea root cause where `addToPosition()` lacked the same lock-state guard that `renewLock()`/`extendLock()` enforced. In `bridge.move`, `send_token_internal` explicitly checks `assert!(!inner.paused, EBridgeUnavailable)` before burning/escrowing tokens [1](#0-0) , but the claim/mint path that mints from `treasury` for an already-approved incoming transfer (the code preceding it, ending at line 608) contains no equivalent `paused` assertion [2](#0-1) .

### Finding Description
`execute_emergency_op` is the sole mechanism to freeze the bridge, and once `inner.paused = true`, the design intent (as reflected by the explicit checks in `send_token_internal` and in the bridge's Move docs) is that all bridge fund movement should halt [3](#0-2) . However, the claim function that performs `inner.treasury.mint<T>(amount, ctx)` and marks the record `claimed = true` (lines 571-608) performs limiter/route/type checks but never asserts `!inner.paused` [4](#0-3) . This is the same "some mutators check the halt-state, others don't" pattern as `addToPosition()` in MlumStaking, which was left unguarded while `renewLock`/`extendLock` correctly checked the emergency-unlock flag.

### Impact Explanation
If the bridge is frozen because of a detected issue (e.g., a suspicious or compromised message/signature set, or an ongoing governance investigation), any bridge message that had already collected valid committee signatures *before* the freeze can still be submitted to mint/release tokens from the Sui treasury via this claim path, because the pause flag is never consulted here. This directly undermines the "stop all fund movement" guarantee of the emergency pause and can result in unauthorized minting/release of bridged tokens exactly when the pause is supposed to prevent it — a state-corruption/fund-theft outcome inside the bridge governance-halt mechanism, matching the Critical bucket ("bridge message forgery or bridge governance/upgrade bypass that enables illegitimate mint or unlock").

### Likelihood Explanation
Exploitability requires that a valid, already-signed transfer message exist at the moment freeze is triggered (or that signatures continue to be independently collectable off-chain by the caller, since the on-chain call itself does not gate on `paused`). This is a narrower window than an always-available bug, and I was not able to fully confirm — due to index truncation — whether the function above line 571 is `approve_token_transfer` (which only records signatures) vs. the actual `claim_token`/mint function, nor whether callers must supply fresh committee signatures verified elsewhere at call time (which could independently be blocked). This uncertainty should be resolved by reading the full `bridge.move` claim/approve functions and their callers/tests (`bridge_tests.move`) directly, since the indexed content here is fragmentary.

### Recommendation
Add `assert!(!inner.paused, EBridgeUnavailable)` at the start of the claim/mint function (mirroring `send_token_internal`), so that no path can mint or release treasury funds while the bridge is in an emergency-paused state, regardless of when signatures were collected.

### Proof of Concept
Not constructed — this finding is based on static code-path comparison within the available index and requires confirmation against the full `bridge.move` source (specifically the exact function signature/name for lines 571-608 and its call sites) before treating it as verified. Given the significant uncertainty about the exact function semantics and whether an independent guard exists upstream (e.g., in the caller that gathers/verifies signatures), this should be treated as a **candidate** finding requiring manual verification with full file access (e.g., via a Devin session) rather than a confirmed vulnerability.

### Citations

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L571-608)
```text

    // TODO: why do we check validity of the route here? what if inconsistency?
    // Ensure route is valid
    // TODO: add unit tests
    // `get_route` abort if route is invalid
    let route = chain_ids::get_route(source_chain, target_chain);
    // check token type
    assert!(
        treasury::token_id<T>(&inner.treasury) == token_payload.token_type(),
        EUnexpectedTokenType,
    );

    let amount = token_payload.token_amount();
    // Make sure transfer is within limit.
    if (
        !bypass_limiter &&
        !inner
            .limiter
            .check_and_record_sending_transfer<T>(
                &inner.treasury,
                clock,
                route,
                amount,
            )
    ) {
        event::emit(TokenTransferLimitExceed { message_key: key });
        return (option::none(), owner)
    };

    // claim from treasury
    let token = inner.treasury.mint<T>(amount, ctx);

    // Record changes
    record.claimed = true;
    event::emit(TokenTransferClaimed { message_key: key });

    (option::some(token), owner)
}
```

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L610-617)
```text
fun send_token_internal<T>(
    inner: &mut BridgeInner,
    target_chain: u8,
    token: Coin<T>,
    message: BridgeMessage,
) {
    assert!(!inner.paused, EBridgeUnavailable);
    assert!(chain_ids::is_valid_route(inner.chain_id, target_chain), EInvalidBridgeRoute);
```

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L635-648)
```text
fun execute_emergency_op(inner: &mut BridgeInner, payload: EmergencyOp) {
    let op = payload.emergency_op_type();
    if (op == message::emergency_op_pause()) {
        assert!(!inner.paused, EBridgeAlreadyPaused);
        inner.paused = true;
        event::emit(EmergencyOpEvent { frozen: true });
    } else if (op == message::emergency_op_unpause()) {
        assert!(inner.paused, EBridgeNotPaused);
        inner.paused = false;
        event::emit(EmergencyOpEvent { frozen: false });
    } else {
        abort EUnexpectedOperation
    };
}
```
