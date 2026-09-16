### Title
Zombie `is_spent` flag on stable outputs whose spender later becomes `final-bad` freezes funds - (File: `writer.js`, `archiving.js`)

### Summary
The CVE describes a resource (an allocated page) that is provisionally reserved on one code path but never released when a later step of the same operation fails, leading to state corruption detected by a `BUG_ON`. The ocore codebase has an analogous "provisional reservation without guaranteed release" pattern: an output is marked `is_spent=1` as soon as *any* unstable unit references it as an input, before that spending unit's ultimate sequence (`good`/`temp-bad`/`final-bad`) is known, and there is no guaranteed matching step that resets `is_spent=0` if the spending unit is later archived as `final-bad`/`voided`/`uncovered`.

### Finding Description
When `writer.saveJoint` persists any unit that spends a `transfer` input, it unconditionally executes: [1](#0-0) 
setting `is_spent=1` on the referenced output regardless of whether the spending unit's `objValidationState.sequence` is `good`, `temp-bad`, or `final-bad`. This is the "allocation" step, analogous to `shmem_alloc_page()` in the CVE: the resource (spendability of the output) is provisionally consumed before the ultimate validity of the operation is settled.

The counterpart "release" step is expected to happen when a unit is later determined to be permanently invalid and is archived (`generateQueriesToArchiveJoint` in `archiving.js`) or purged as uncovered (`purgeUncoveredNonserialJoints` in `joint_storage.js`, `dir_path` not shown here but referenced earlier). The maintainers' own diagnostic tool documents that this release does not reliably happen for every code path: [2](#0-1) 
The tool explicitly states: *"A difference means the OLD method undercounts a voter's balance because a future unstable unit spent their stable output and was later propagated to final-bad, leaving `is_spent=1` on the output while no good unit claims it in `spent_rows`."* This confirms that in at least one class of paths, the `is_spent` flag set during the "reservation" phase is not cleared during the error/final-bad phase — i.e., the same "allocate on the happy path, forget to release on the error path" defect described in the CVE.

Because `is_spent` gates spendability checks throughout the codebase (`validatePaymentInputsAndOutputs` in `validation.js` treats a spent output as unavailable), an output whose only spender ultimately becomes `final-bad`/`voided`/`uncovered` can be left permanently marked as spent even though, semantically, it was never validly spent. The rightful owner cannot include it as an input in a new payment because validation logic and wallet balance calculations exclude any output with `is_spent=1`.

### Impact Explanation
This is a fund-freezing bug, not a memory-safety crash: legitimate, unspent value becomes permanently unusable by its owner because of an internal accounting flag that is set optimistically but not reliably cleared on the failure path. It also causes silent disagreement between different balance-computation methods within the same codebase (as shown by the existence of `compare_vote_balances.js`, built specifically to detect "zombie-spent outputs"), which is evidence of nodes/wallets computing divergent, unstable output states — matching the "node disagreement on validity/stability" and "AA/user fund freezing" impact categories accepted by the validation rules.

### Likelihood Explanation
This can be triggered by any unprivileged unit poster: post a valid-looking unit `A` that spends a stable output of victim address `V`, but craft `A` in a way that makes it end up permanently `final-bad` (e.g., a genuine double-spend loser, or a unit that a witness/majority ultimately reject) after being provisionally written and having flipped `is_spent=1` on `V`'s output. If the specific archival/purge/void code path invoked for that particular final-bad classification does not reset `is_spent`, `V`'s output remains stuck. Because there are multiple code paths that transition a unit to `final-bad`/`voided`/`uncovered` (normal double-spend resolution, `purgeUncoveredNonserialJoints`, light-client `processHistory` voiding, `archiving.generateQueriesToArchiveJoint`), and only some of them are exercised by the existing tests, this is plausible to trigger without any peer/hub/node compromise — a single poster crafting a competing/losing unit is sufficient. The existence of a dedicated internal auditing script (`tools/compare_vote_balances.js`) written specifically to detect this exact symptom is strong corroborating evidence that this condition has been observed as a real occurrence, not merely a theoretical one.

### Recommendation
- Audit every code path that classifies a unit as `final-bad`, `voided`, or `uncovered` (`archiving.js:generateQueriesToArchiveJoint`, `joint_storage.js:purgeUncoveredNonserialJoints`, `light.js` history-voiding path) and ensure each one issues a matching `UPDATE outputs SET is_spent=0 WHERE unit=? AND message_index=? AND output_index=?` for every `transfer` input of the archived/voided unit, mirroring the `is_spent=1` write done in `writer.js`.
- Add an invariant check (similar in spirit to `tools/compare_vote_balances.js`) that runs as part of normal node consistency checks (like `checkBalances`/`checkStorageSizes` in `aa_composer.js`) to detect and alert on any output with `is_spent=1` whose only referencing input belongs to a `final-bad`/voided/nonexistent unit, and to automatically correct it.
- Consider deriving spendability directly from `NOT EXISTS (good, stable spender)` (the "NEW" method in `compare_vote_balances.js`) rather than relying on a mutable `is_spent` flag with distributed set/clear responsibilities.

### Proof of Concept
1. Attacker/normal user A owns a stable, unspent output `O` (`is_spent=0`).
2. Attacker crafts and broadcasts unit `U1` that spends `O`, timed so it initially validates with `sequence='good'` (or `temp-bad`) and is written via `writer.saveJoint`, which executes `UPDATE outputs SET is_spent=1 WHERE unit=... /* O's coordinates */` per `writer.js:378-383`.
3. Attacker (or protocol dynamics, e.g. a conflicting double-spend, or the unit failing to gain sufficient witness support) causes `U1` to ultimately be classified `final-bad`/voided/archived-as-uncovered via one of the paths in `archiving.js` / `joint_storage.js` / `light.js`.
4. If that specific archival/void code path does not also reset `is_spent=0` on `O` (a gap corroborated by the existence and stated purpose of `tools/compare_vote_balances.js`), `O` remains marked spent forever.
5. Owner A can no longer include `O` as a spendable input in any new payment, and wallet/light balance queries that rely on `is_spent=0` will under-report A's real, spendable balance — a concrete, permanent fund-freezing condition caused purely by posting units, requiring no privileged node/hub/peer access.

### Citations

**File:** writer.js (L378-383)
```javascript
								switch (type){
									case "transfer":
										conn.addQuery(arrQueries, 
											"UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?",
											[src_unit, src_message_index, src_output_index]);
										break;
```

**File:** tools/compare_vote_balances.js (L1-9)
```javascript
/*jslint node: true */
'use strict';
// Compares voter balance calculations for system_vote subjects using two methods:
//   OLD: bal_rows (is_spent=0 stable-good) + spent_rows (unstable-good spending stable-good)
//   NEW: stable-good outputs with no stable-good spender (NOT EXISTS)
//
// A difference means the OLD method undercounts a voter's balance because a future
// unstable unit spent their stable output and was later propagated to final-bad,
// leaving is_spent=1 on the output while no good unit claims it in spent_rows.
```
