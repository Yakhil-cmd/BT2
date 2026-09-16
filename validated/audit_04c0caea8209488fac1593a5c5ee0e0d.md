### Title
Non-atomic multi-step address-definition lookup in `validateSignedMessage()` allows a TOCTOU race with concurrent definition-change stabilization - (File: `signed_message.js`)

### Summary
`validateSignedMessage()` in `signed_message.js` resolves an address's definition through **three sequential, unlocked** database reads issued on the shared connection pool (`db`) rather than on a snapshot/transaction connection: (1) look up `main_chain_index`/`timestamp` of `last_ball_unit`, then (2)-(3) `storage.readDefinitionByAddress()`, itself split into `readDefinitionChashByAddress()` followed by `readDefinitionAtMci()`. Each of these is an independent query with no lock and no shared transaction, exactly mirroring the kernel bug class where a page-table walk is split into `p?dp_get()` followed later by `p?d_offset()`, and an unmap in between produces an inconsistent view.

### Finding Description
In the normal unit-validation path (`validation.js`), all reads for a single unit happen inside one `BEGIN ... COMMIT/ROLLBACK` transaction on a dedicated connection, and writes are further serialized by `mutex.lock(arrAuthorAddresses)`. This gives a consistent snapshot across the multi-step definition lookup.

`validateSignedMessage()`, however, defaults `conn = db` when called without an explicit connection (`signed_message.js:117-127`), which is the form used by `wallet.js` and by `formula/evaluation.js` for the `is_valid_signed_package` oscript operator (`formula/evaluation.js:1653-1686`) — a construct reachable by any AA trigger sender who can embed an arbitrary `signed_message` package in a trigger's `data`.

The lookup sequence is:
1. `conn.query("SELECT main_chain_index, timestamp FROM units WHERE unit=?", [last_ball_unit], ...)` at `signed_message.js:200`.
2. `storage.readDefinitionByAddress(conn, objAuthor.address, last_ball_mci, {...})` at `signed_message.js:219`, which itself performs:
   - `readDefinitionChashByAddress()` (`storage.js:754-768`) — finds the latest *stable* `definition_chash` as of `max_mci`.
   - `readDefinitionAtMci()` (`storage.js:779-788`) — resolves that `definition_chash` to an actual definition, again filtered by `is_stable=1 AND main_chain_index<=max_mci`.

None of these three queries run inside a shared transaction or under any address-scoped mutex. Between step 1 and step 3, the writer (`writer.js`/`main_chain.js`) can commit a new `address_definition_changes` row and advance stability for the very address being resolved, on a **different connection**, entirely unguarded by the reads above. Because the reads are not atomic, a node can observe the `last_ball_mci` from *before* the update but resolve `definition_chash`/`definition` using data that only became visible *after* the update (or vice versa), depending on exact interleaving — an inconsistent, TOCTOU-style read analogous to the `try_get_locked_pte()` unmap race.

### Impact Explanation
`is_valid_signed_package` in oscript is a boolean/authenticity primitive that AAs commonly use to gate fund releases, oracle-style attestations, or conditional transfers based on a caller-supplied signed message. If two nodes process the same trigger at slightly different points relative to a concurrent definition-change stabilization, they can reach different verdicts on whether the embedded `signed_message` is validly signed by the claimed address for the given `last_ball_unit`/mci. That is a direct **node disagreement on validity/stability** for AA execution outcomes, which can cascade into disagreement on the AA's resulting state and fund movement — i.e., some witnesses/nodes accept an AA response unit that others reject, threatening the network's ability to reach consensus on the resulting DAG state.

### Likelihood Explanation
Triggering the race requires an attacker-controlled AA trigger containing a `signed_message` referencing an address whose definition is redefined via a `address_definition_change` unit that stabilizes at almost the same time the trigger is being evaluated by different nodes — timing that an attacker who controls both the trigger and the definition-change unit can engineer deliberately (post the redefinition unit just before/around the trigger unit becomes stable). This is a narrow timing window but is fully reachable by an unprivileged AA trigger sender/asset issuer without requiring any node compromise.

### Recommendation
Make `validateSignedMessage()`'s definition resolution atomic: require callers to supply (or internally acquire) a single connection/transaction for the full sequence of `last_ball_unit` lookup + `readDefinitionByAddress()` (both sub-queries), matching the pattern already used by `validation.js`'s `validate()`. Alternatively, wrap the three queries in one `BEGIN`/`COMMIT` on a dedicated connection, or take the same `mutex.lock` scoping used for author-address validation before doing the lookup, so that concurrent stabilization of a definition change cannot be interleaved between the mci lookup and the definition resolution.

### Proof of Concept
1. Deploy AA `A` whose bytecode contains `is_valid_signed_package(evaluated_address, signed_package_expr)` (`formula/evaluation.js:1653`), gating a payout on a caller-supplied `signed_message` in `trigger.data`.
2. Attacker controls address `X` and prepares:
   - Unit `U1`: an `address_definition_change` for `X`, crafted so it becomes stable at mci `M`.
   - A `signed_message` package `P`, valid under `X`'s *new* definition but supplied inside a trigger to AA `A`, with `last_ball_unit` chosen so `last_ball_mci` sits right at the boundary of `U1`'s stabilization.
3. Send the AA trigger referencing `P` timed so that, on different nodes, `U1`'s stabilization races with the three unlocked queries inside `validateSignedMessage()`/`readDefinitionByAddress()`.
4. Because these reads are not wrapped in one transaction/lock, some nodes will resolve `X`'s definition using the pre-`U1` data while the mci check already reflects post-`U1` state (or vice versa), yielding a different `is_valid_signed_package` result across nodes and therefore a different AA response/state — a validity/state disagreement for the same trigger unit.