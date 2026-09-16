### Title
`dataFeedExists()` treats data-feed messages from not-yet-validated/losing double-spend units as valid oracle evidence - (File: `data_feeds.js`)

### Summary
The Sherlock report describes a bridge observer (`ProcessInboundEvents`) that decodes a Solana transaction as a successful deposit without checking `Meta.Err`, so a transaction that actually reverted is still treated as a valid event. The general bug class is: **trusting an unconfirmed/failed state transition as if it had succeeded, and using it to authorize value transfer**. In `ocore` the analogous mechanism is the "in data feed" oracle-condition evaluator, which is used both in address-definition authentifiers (`definition.js`) and in AA oscript formulas (`formula/evaluation.js`, `in_data_feed`). The unstable-unit code path of `dataFeedExists()` in `data_feeds.js` grants a data-feed match without verifying that the posting unit's `sequence` is `'good'`, unlike the sibling function `readDataFeedValue()`, which explicitly performs that check.

### Finding Description
`dataFeedExists()` is the function backing both:
- the `'in data feed'` operator in address-definition authentifier evaluation (`definition.js:933-940`), which can gate spending/signing conditions on an address, and
- the `'in_data_feed'` oscript operator evaluated inside Autonomous Agents (`formula/evaluation.js:701-748`), which can gate AA logic (fund releases, state transitions, etc.).

For the "unstable" (not-yet-stabilized) branch of the search, `dataFeedExists` iterates `storage.assocUnstableMessages` and matches any `data_feed` message from an author in the requested oracle address list: [1](#0-0) 

Critically, this loop only checks `objUnit.bAA`, MCI bounds, and author-address membership — it never checks `objUnit.sequence`. Compare this with the sibling function `readDataFeedValue()`, used for the value-reading `data_feed` oscript formula, which performs the same kind of unstable-message scan but explicitly filters out units whose `sequence` is not `'good'`: [2](#0-1) 

Because units are known to remain in `storage.assocUnstableMessages` until they are stabilized — and are only deleted from that map when `main_chain.js` finds `sequence === 'final-bad'` at stabilization time — a unit whose sequence has already been determined as a losing double-spend (bad) can still be present and matched by `dataFeedExists()` for as long as it remains unstable: [3](#0-2) 

This mirrors the Solana root cause precisely: one code path (`ProcessInboundEvents`/`dataFeedExists`) omits the "did this actually succeed / is this actually valid" check that the parallel, correctly-implemented code path (`EVM inbound observer`/`readDataFeedValue`) performs.

### Impact Explanation
Any unprivileged party who controls (or colludes with) an address named in an `'in data feed'` oracle list can attempt a double-spend: post two conflicting units from the oracle address, each containing a `data_feed` message with the value needed to satisfy a condition. One branch will eventually be marked `sequence='final-bad'`, but while it is unstable, `dataFeedExists()` still allows it to satisfy `'in data feed'` conditions used to:
- authorize spending from a shared/escrow address whose definition contains `['in data feed', [...]]` as a signing condition, or
- flip AA branching logic that depends on `in_data_feed(...)` to release funds, mint/transfer assets, or change state.

This can lead to unauthorized spending or AA fund loss/incorrect state transitions triggered by data that never becomes canonical, which matches the required impact categories (unauthorized spending / AA fund loss / node disagreement about validity).

### Likelihood Explanation
The precondition is that the oracle/data-feed author (or an unprivileged unit poster acting through such an address) is willing to post conflicting units — this is a normal DAG operation available to any user, not a privileged role (unlike the Solana report's requirement of an admin/observer). The window of exploitability is the interval between unit posting and MCI stabilization, during which `assocUnstableMessages` still contains the eventually-bad message. This is a narrower, more probabilistic window than the original bridge bug (which had no time limit), so likelihood is Medium rather than Critical, but it is concretely reachable without special privileges.

### Recommendation
Add the same `sequence !== 'good'` guard used in `readDataFeedValue()` (`data_feeds.js:219-220`) to the unstable-unit loop inside `dataFeedExists()` (`data_feeds.js:34-44`), so that data-feed matches used for `'in data feed'`/`'in_data_feed'` boolean-existence checks are restricted to units whose sequence has been (or provisionally is) `'good'`, consistent with how AA value-reads already behave.

### Proof of Concept
Conceptual sequence (I could not execute this against a live node, so this is derived purely from the static code paths cited above, not confirmed by dynamic testing):
1. Attacker controls address `O`, which is listed as an oracle in an address definition condition `['in data feed', [[O], 'flag', '=', 'go']]` guarding a payout address, or in an AA's `in_data_feed` check gating a fund release.
2. Attacker crafts two conflicting units from `O` (double-spending the same input) — Unit A contains `{app:'data_feed', payload:{flag:'go'}}`; Unit B is the version that will win the conflict and does not.
3. While Unit A is unstable, if/once its `sequence` becomes `'final-bad'` but before it is stabilized and purged from `storage.assocUnstableMessages`, `dataFeedExists()` still returns `bFound=true` for `flag='go'` because it never inspects `objUnit.sequence`.
4. Any signer/AA relying on `'in data feed'`/`in_data_feed(...)` at that moment observes the condition as satisfied and releases funds/executes logic based on a message that will never be part of the canonical, valid history.

Because I was unable to trace the exact timing at which `objUnit.sequence` is set to `'final-bad'` relative to `assocUnstableMessages` retention (this requires deeper tracing through `validation.js`/`writer.js` sequence assignment that I did not fully complete), the precise exploitation window size is uncertain and should be verified with a live test harness before treating this as fully confirmed exploitable end-to-end.

### Citations

**File:** data_feeds.js (L34-49)
```javascript
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA)
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
			storage.assocUnstableMessages[unit].forEach(function (message) {
				if (message.app !== 'data_feed')
					return;
				var payload = message.payload;
				if (!ValidationUtils.hasOwnProperty(payload, feed_name))
					return;
```

**File:** data_feeds.js (L211-224)
```javascript
	if (bIncludeUnstableAAs) {
		var arrCandidates = [];
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA && !bIncludeAllUnstable)
				continue;
			if (objUnit.sequence !== 'good')
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
```

**File:** main_chain.js (L1554-1557)
```javascript
									if (objUnitProps.sequence === 'final-bad'){
										delete storage.assocUnstableMessages[unit];
										return cb();
									}
```
