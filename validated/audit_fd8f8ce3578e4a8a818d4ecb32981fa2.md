The strongest reachable analog to the BonqDAO oracle-manipulation pattern (consuming a reported value before it has been fully validated/finalized) is an inconsistency in how ocore's two AA-facing oracle primitives, `data_feed[[...]]` and `in_data_feed[[...]]`, read **unstable** data-feed messages.

### Title
`in_data_feed[[...]]` accepts data-feed values from unstable units regardless of unit `sequence`, unlike `data_feed[[...]]` — (File: `data_feeds.js`)

### Summary
`readDataFeedValue()` (used by the `data_feed[[...]]` oscript primitive) explicitly filters out unstable units whose `sequence` is not `'good'` before considering their data-feed messages. `dataFeedExists()` (used by `in_data_feed[[...]]`) does not perform this check at all when scanning `storage.assocUnstableMessages` for AA evaluation, so a data-feed message from a unit that will ultimately be finalized as `final-bad` (e.g., a double-spend loser) can still satisfy an `in_data_feed` condition before stability determination invalidates it.

### Finding Description
In `readDataFeedValue()`, when reading unstable AA data feeds, the loop explicitly skips any unit whose sequence is not good: [1](#0-0) 
```
			if (!objUnit.bAA && !bIncludeAllUnstable)
				continue;
			if (objUnit.sequence !== 'good')
				continue;
``` [2](#0-1) 

In contrast, `dataFeedExists()`, used to evaluate `in_data_feed[[...]]`, iterates the same `storage.assocUnstableMessages` collection but only checks `objUnit.bAA`, `latest_included_mc_index` range, and author-address intersection — it never checks `objUnit.sequence`: [3](#0-2) 

This means a unit that is currently `sequence: 'good'` provisionally (because sequence status is only finally settled once the unit's main-chain-index stabilizes and conflicting spends are resolved) but that will later be reclassified as `sequence: 'final-bad'` (e.g., because its inputs double-spend against a conflicting unit) can still have its `data_feed` message counted by `in_data_feed[[...]]` while the AA is evaluating triggers on unstable state. `data_feed[[...]]` correctly excludes such not-yet-validated/soon-to-be-voided reports; `in_data_feed[[...]]` does not.

Both primitives are wired into AA formula evaluation identically — `data_feed` calls `dataFeeds.readDataFeedValue(...)` and `in_data_feed` calls `dataFeeds.dataFeedExists(...)`, both passing the same `bAA` flag and unstable-message context: [4](#0-3) [5](#0-4) 

The `in_data_feed` primitive is also reachable from address-definition validation (`in data feed` condition), which similarly calls `dataFeeds.dataFeedExists` for pre-stability checks: [6](#0-5) 

### Impact Explanation
Any address that can be named as an "oracle" address in an AA's `in_data_feed[[...]]` condition (this is exactly the analog of the BonqDAO price reporter — an otherwise unprivileged party whose posted messages the AA trusts) can craft two conflicting units: one that posts a "favorable" data-feed value and one that double-spends against it. While unstable, the favorable-value unit is momentarily `sequence: 'good'` and is picked up by `in_data_feed`, letting the AA branch execute (mint, pay out, unlock funds, etc.) based on a report that the network will subsequently invalidate once the double-spend resolves and the unit becomes `final-bad`. This is a fund-loss/fund-freezing vector for any AA relying on `in_data_feed` for its trigger logic, directly analogous to BonqDAO trusting the freshest unvalidated Tellor report instead of waiting for the dispute window to close.

### Likelihood Explanation
Exploitability requires only (1) an AA definition using `in_data_feed[[...]]` with an oracle address the attacker (or a colluding reporter) controls, and (2) the ability to post two conflicting units (ordinary, unprivileged double-spend), both trivially reachable by any unit poster. No special privileges, malicious hub/node behavior, or network-level attack is required — it is purely a validation-logic asymmetry inside `data_feeds.js` triggered by ordinary AA execution on unstable state.

### Recommendation
Add the same `objUnit.sequence !== 'good'` guard to the unstable-message loop in `dataFeedExists()` (mirroring `readDataFeedValue()`), so that `in_data_feed[[...]]` never counts data-feed messages from units that are not (or not yet confirmed) `sequence: 'good'`.

### Proof of Concept
1. Deploy an AA whose trigger logic contains `in_data_feed[[oracles="<ORACLE_ADDR>", feed_name='price', feed_value>=X]]`.
2. As the oracle address, broadcast unit `A` posting `data_feed { price: X }` together with an input `I`.
3. Simultaneously broadcast a conflicting unit `B` that spends the same input `I` differently, arranged so that `A` is the one to be finalized `final-bad` once stability is reached (e.g., unit `B` ends up on the winning branch).
4. Trigger the AA while `A` is still unstable and provisionally `sequence: 'good'`: `in_data_feed` (via `dataFeedExists`, `data_feeds.js:34-43`) reports the value as found and the AA branch executes, even though `A` is later invalidated — whereas an equivalent `data_feed[[...]]` read (via `readDataFeedValue`, `data_feeds.js:217-224`) would correctly have rejected it once sequence resolves.

### Citations

**File:** data_feeds.js (L34-43)
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
```

**File:** data_feeds.js (L205-224)
```javascript
function readDataFeedValue(arrAddresses, feed_name, value, min_mci, max_mci, unstable_opts, ifseveral, timestamp, handleResult){
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	var start_time = Date.now();
	var objResult = { bAbortedBecauseOfSeveral: false, value: undefined, unit: undefined, mci: undefined };
	var bIncludeUnstableAAs = !!unstable_opts;
	var bIncludeAllUnstable = (unstable_opts === 'all_unstable');
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

**File:** formula/evaluation.js (L646-646)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
```

**File:** formula/evaluation.js (L745-745)
```javascript
						dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, mci, bAA, cb);
```

**File:** definition.js (L933-940)
```javascript
			case 'in data feed':
				// ['in data feed', [['BASE32'], 'data feed name', '=', 'expected value']]
				var arrAddresses = args[0];
				var feed_name = args[1];
				var relation = args[2];
				var value = args[3];
				var min_mci = args[4] || 0;
				dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, objValidationState.last_ball_mci, false, cb2);
```
