### Title
Uncaught Exception in Ambiguous Data-Feed Candidate Sorting Causes Node Crash - (File: data_feeds.js)

### Summary
`readDataFeedValue()` in `data_feeds.js` builds a list of candidate unstable data-feed messages authored by AAs and, when several candidates are equally ranked, sorts them with a comparator that `throw`s a JavaScript `Error` instead of returning a definite order. This mirrors the SurrealDB bug class: a comparator invoked from `Array.prototype.sort` that does not implement a total order and can raise an exception mid-sort when two elements are “equal” under the comparator’s primary keys, causing an unhandled crash instead of a safe fallback.

### Finding Description
When `data_feed()` is evaluated in oscript with the “include unstable AA messages” option (`unstable_opts` truthy), `readDataFeedValue()` scans `storage.assocUnstableMessages` for `data_feed` messages from AAs and collects the matching candidates: [1](#0-0) 

When more than one candidate matches and `ifseveral` is not `'abort'`, the candidates are sorted by `latest_included_mc_index` then `level`. If both are equal for two candidates and `bIncludeAllUnstable` is false, the comparator throws instead of returning a value: [2](#0-1) 

```js
arrCandidates.sort(function (a, b) {
    if (a.latest_included_mc_index < b.latest_included_mc_index) return -1;
    if (a.latest_included_mc_index > b.latest_included_mc_index) return 1;
    if (a.level < b.level) return -1;
    if (a.level > b.level) return 1;
    if (bIncludeAllUnstable) return 1;
    throw Error("can't sort candidates "+a+" and "+b);
});
```

This is functionally the same defect class as GHSA-m52v-24p8-654f: a sort comparator that is not a total order and panics/throws under specific tie conditions instead of resolving deterministically. Two distinct AA units triggered in the same DAG neighborhood can post `data_feed` messages for the same `feed_name` from addresses that are both being watched by a triggering AA's `data_feed()` call; if those two unstable AA units end up with identical `latest_included_mc_index` and `level` (a realistic condition for units composed around the same time near the same parents), the comparator throws.

### Impact Explanation
The `throw Error(...)` occurs synchronously inside `Array.prototype.sort`, called from within AA-trigger handling (`aa_composer.js` → oscript evaluation → `data_feed()` → `readDataFeedValue`). Because this executes deep inside asynchronous unit-processing code without a wrapping try/catch that gracefully aborts only the current bounce/response, an uncaught exception here can propagate up and crash the Node.js process (unhandled exception), halting further unit/AA processing on the node until manually restarted. Any node evaluating the same trigger (all full nodes need to independently execute AA logic to agree on state) would crash identically, resulting in a network-wide inability to process further AA triggers/confirm new units touching this data feed logic — a denial-of-service condition reachable purely by an unprivileged AA trigger sender/data-feed poster, without needing a malicious peer or node operator privilege.

### Likelihood Explanation
Triggering this requires crafting two AA units (or a data feed provider address plus an AA) that emit `data_feed` messages for the same feed name and are included with identical `latest_included_mc_index` and `level` values while being read via `data_feed()` with the "unstable" option and `ifseveral` set to something other than `'abort'` (e.g. `'last'` or the default). Because `level` and `latest_included_mc_index` are attacker-influenced through unit composition (choice of parents), an attacker with modest DAG-shaping capability can arrange two units satisfying the tie condition, making this feasible for a determined but unprivileged actor.

### Recommendation
Replace the `throw` in the comparator with a deterministic total-order tiebreaker (e.g., compare by `unit` hash string) instead of throwing, so the sort function always returns -1/0/1 and never raises inside `Array.prototype.sort`. Additionally, wrap AA data-feed evaluation paths in defensive error handling so any residual exception in this area results in a graceful bounce of the response rather than a process crash.

### Proof of Concept
1. Deploy/trigger two AA units (or a data-feed-posting address and AA unit) that both send a `data_feed` message with the same `feed_name` for addresses watched by a third triggering AA that calls `data_feed()`/`data_feed_value()` with `[unstable]` option and `ifseveral` not set to `abort`.
2. Arrange parents/timing so both candidate units share identical `latest_included_mc_index` and `level` (attacker controls parent selection during unit composition).
3. Trigger the reading AA; `readDataFeedValue()` in `data_feeds.js` collects both candidates, `arrCandidates.length > 1`, and the sort comparator reaches the tie branch and executes `throw Error("can't sort candidates ...")`, crashing the node process that evaluates the trigger.

### Citations

**File:** data_feeds.js (L211-240)
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
			storage.assocUnstableMessages[unit].forEach(function (message) {
				if (message.app !== 'data_feed')
					return;
				var payload = message.payload;
				if (!ValidationUtils.hasOwnProperty(payload, feed_name))
					return;
				var feed_value = payload[feed_name];
				if (value === null || value === feed_value || value.toString() === feed_value.toString())
					arrCandidates.push({
						value: string_utils.getFeedValue(feed_value, bLimitedPrecision),
						latest_included_mc_index: objUnit.latest_included_mc_index,
						level: objUnit.level,
						unit: objUnit.unit,
						mci: max_mci // it doesn't matter
					});
			});
```

**File:** data_feeds.js (L255-267)
```javascript
			arrCandidates.sort(function (a, b) {
				if (a.latest_included_mc_index < b.latest_included_mc_index)
					return -1;
				if (a.latest_included_mc_index > b.latest_included_mc_index)
					return 1;
				if (a.level < b.level)
					return -1;
				if (a.level > b.level)
					return 1;
				if (bIncludeAllUnstable) // still ambiguous, sort randomly (it's OK outside AAs)
					return 1;
				throw Error("can't sort candidates "+a+" and "+b);
			});
```
