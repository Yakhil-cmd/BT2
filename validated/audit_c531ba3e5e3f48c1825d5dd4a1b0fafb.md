### Title
Inconsistent validity criteria between `dataFeedExists` and `readDataFeedValue` for unstable AA-posted data feeds allows `in_data_feed()` to match on non-`good` sequence units - (File: data_feeds.js)

### Summary
`data_feeds.js` exposes two entry points used by AA formulas to look at data feeds that come from **unstable** units authored by AA responses within the same primary-trigger chain: `dataFeedExists()` (backs `in_data_feed()`/`is in data feed` address-definition term) and `readDataFeedValue()` (backs `data_feed[...]`). Both iterate `storage.assocUnstableMessages` to find matching `data_feed` messages posted by not-yet-stable AA response units, but they apply **different validity filters** to the candidate units, exactly mirroring the reported bug class where the same conceptual quantity ("is this staking/oracle input valid enough to count") is checked against two different criteria in two code paths.

### Finding Description
In `readDataFeedValue()` the loop over unstable AA messages explicitly rejects any unit whose sequence is not `'good'`: [1](#0-0) 
```
for (var unit in storage.assocUnstableMessages) {
    var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
    ...
    if (objUnit.sequence !== 'good')
        continue;
    if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
        continue;
    ...
```

In `dataFeedExists()`, the analogous loop over the same `storage.assocUnstableMessages` structure performs the `bAA`/`author_addresses`/`latest_included_mc_index` checks but **omits the `objUnit.sequence !== 'good'` check entirely**: [2](#0-1) 

Both functions are meant to answer the same underlying question — "does a not-yet-stable data feed value from this oracle/AA satisfy the condition, before the unit is finally sequenced?" — but `dataFeedExists()` (used by `in_data_feed()` in formulas and by `'in data feed'` address-definition terms) will happily match on a unit that is `temp-bad` or otherwise not `'good'` in sequence, i.e. a unit that is a **loser of a double-spend** and will ultimately be excluded from the ledger (or is provisionally invalid). `readDataFeedValue()`, used by `data_feed[...]`, correctly excludes such units.

This is the same bug class as the audit finding: two enforcement points that should use one consistent "is this input valid/counted" criterion diverge, so one code path (staked vs. shares in the report; sequence-filtered vs. unfiltered here) can accept an input that the other path would reject.

### Impact Explanation
An AA that uses `in_data_feed()` (or an address definition using `'in data feed'`) to gate secondary-trigger logic within the same DAG batch/primary-trigger chain can be made to see a data-feed value as "present" based on a unit that is not sequence-`good` — i.e. a unit that will not actually become part of the accepted ledger, or whose finality is not guaranteed the same way `data_feed[]` would treat it. Because different nodes can observe different sequencing/finality states for temp-bad units before stabilization, this can cause:
- Divergent AA execution results across nodes evaluating the same trigger at slightly different points of DAG propagation (node disagreement on validity), since `in_data_feed()` bypasses the sequence filter that `data_feed[]` enforces.
- An AA branch (e.g., releasing funds conditioned on `in_data_feed(...)`) to fire based on a data-feed post that is not actually valid/serial, leading to incorrect fund release or freezing depending on which branch is taken.

### Likelihood Explanation
This path is reachable by any AA author who writes an AA using `in_data_feed()` with an oracle/AA feed that can be posted alongside other conflicting (double-spending) units in the same unstable window, or a definition using `'in data feed'` term evaluated during AA-context validation (`bAA=true`). No privileged access is required — only a normal AA definition and a unit triggering it (or an oracle/attacker posting conflicting units to attempt to exploit the transient state). The condition requires a specific unstable/sequencing race (a temp-bad candidate existing at evaluation time), which narrows the window, but it is a genuine reachable divergence in behavior between two otherwise-parallel functions in the same file.

### Recommendation
Add the same `objUnit.sequence !== 'good'` (or equivalent) filter to the unstable-message loop in `dataFeedExists()` that is already present in `readDataFeedValue()`, so both `data_feed[]` and `in_data_feed()`/`'in data feed'` apply identical validity criteria to candidate unstable AA-posted data feed messages:
```js
for (var unit in storage.assocUnstableMessages) {
    var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
    if (!objUnit) throw Error("unstable unit " + unit + " not in assoc");
    if (!objUnit.bAA) continue;
    if (objUnit.sequence !== 'good') continue;   // <-- add this line to match readDataFeedValue
    if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci) continue;
    ...
}
```

### Proof of Concept
1. Craft two competing units that spend the same output (a double-spend), with one of them (unit A) authored by an AA response that also emits a `data_feed` message with `feed_name`/value matching a condition used by a downstream AA's `in_data_feed()` check (or an address definition's `'in data feed'` term).
2. Ensure unit A is currently sequenced as non-`'good'` (e.g. it is losing the double-spend race) while still present in `storage.assocUnstableMessages`/`assocUnstableUnits`.
3. Trigger the downstream AA (or evaluate the address definition) so it calls `in_data_feed(...)` with `bAA=true`. Because `dataFeedExists()` does not check `objUnit.sequence`, it will find the message from the losing unit A and return `true`.
4. Compare against calling `data_feed[...]` with the same parameters — `readDataFeedValue()` correctly skips unit A due to its `sequence !== 'good'` check and does not return this value, demonstrating the inconsistency and its potential to steer AA branching or authentication decisions based on a unit that should not count.

Note: I was unable to fully trace every place where `objUnit.bAA`/`objUnit.sequence` are set for entries in `assocUnstableUnits` (the assignment sites live across `storage.js`/`main_chain.js`/`writer.js`, which the available indexed context did not let me fully inspect line-by-line), so the exact reachability window (how long a `bAA` unit can remain non-`'good'` while still enumerable in `assocUnstableMessages`) could not be independently confirmed beyond the code shown above. A Devin session with full repository access would be needed to trace the complete lifecycle of `sequence` transitions for AA response units to confirm the exact exploitation window.

### Citations

**File:** data_feeds.js (L34-50)
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
				var feed_value = payload[feed_name];
```

**File:** data_feeds.js (L213-224)
```javascript
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
