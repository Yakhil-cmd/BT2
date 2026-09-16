### Title
Unbounded scan of `storage.assocUnstableMessages` by unprivileged data-feed spam causes DoS-level slowdown of every AA data-feed lookup - (File: `data_feeds.js`)

### Summary
`dataFeedExists()` and `readDataFeedValue()` in `data_feeds.js`, invoked by the `data_feed()`/`in_data_feed()` oscript operators during AA formula evaluation, iterate with `for (var unit in storage.assocUnstableMessages)` over **every currently unstable unit that carries a `data_feed`/`definition`/`system_vote`/`system_vote_count` message**, testing each one against the queried oracle addresses. Any user can post cheap units containing a `data_feed` message from an address that will later be checked by an AA, growing this in-memory structure. Because `assocUnstableMessages` is only pruned per-unit when that unit's MCI stabilizes (`main_chain.js`, `markMcIndexStable` → `saveUnstablePayloads` → `delete storage.assocUnstableMessages[unit]`), an attacker can keep flooding new data-feed units faster than stabilization drains old ones, growing the scanned set for every subsequent AA data-feed read.

### Finding Description
`storage.assocUnstableMessages` is a global, process-wide map keyed by unit hash, populated for every posted unit (not just AA-related ones) that contains a `data_feed`, `definition`, `system_vote`, or `system_vote_count` message: [1](#0-0) 

Entries are only removed once the unit's MCI is marked stable: [2](#0-1) [3](#0-2) 

Every time an AA (triggered by any user's payment/trigger unit) evaluates `data_feed()` or `in_data_feed()`, `dataFeedExists()`/`readDataFeedValue()` performs a **full linear scan of the entire `assocUnstableMessages` object**, `forEach`-ing over each unit's messages and doing an `_.intersection` per unit: [4](#0-3) [5](#0-4) 

This is analogous to the reported `remove()`/`requestUnstake()` pattern: an unprivileged actor (anyone able to post a unit with a `data_feed` message, e.g. an oracle-mimicking address or simply any address once it is queried as an "oracle" by some AA) can cheaply insert entries into a shared, globally-scanned structure that costs O(n) to traverse on every future read, and the entries persist until stabilized — which under sustained spam (posting new data_feed units faster than the DAG advances/stabilizes, or during any period of degraded stabilization) keeps `n` growing. Because every full node must independently execute the same AA triggers deterministically, this scan cost is paid by every node in the network on every AA data-feed lookup while the backlog is large, unlike `remove()` in the report where the growing queue directly inflated a function's gas cost.

### Impact Explanation
Every AA that reads oracle data via `data_feed()`/`in_data_feed()` pays a cost proportional to the total number of unstabilized units in the whole network carrying data_feed/definition/system_vote messages, not just those relevant to the queried address(es). An attacker can flood the network with minimal-fee units posting `data_feed` messages (no special permission required — any address's data feed can be scanned since the code doesn't require the address to be a "registered" oracle), inflating this shared array. This degrades AA trigger processing time network-wide for any AA using data feeds, and in the worst case (very large backlog combined with unit-processing/validation time budgets) can slow or stall stabilization/response processing, which is a network-wide "unable to confirm new units at expected rate" condition rather than a localized issue in a single contract.

### Likelihood Explanation
Reachable purely by posting ordinary units (unprivileged unit poster) with a `data_feed` app message and no minimum-value constraint, then triggering any AA that calls `data_feed()`. No special access, oracle registration, or hub/peer trust is required. The condition compounds under normal network load and is exacerbated if unit stabilization lags (e.g., temporary DAG congestion), which is a realistic operating condition rather than a rare edge case.

### Recommendation
Avoid a full-map scan in `dataFeedExists`/`readDataFeedValue`; index `assocUnstableMessages` (or a derived structure) by `feed_name`/author address so lookups are O(matching entries) rather than O(total unstable data-feed-bearing units). Alternatively, bound the number of unstable data-feed messages considered per address/feed, or require a minimum fee/size threshold discouraging pure data_feed-message spam, mirroring the "set a minimum amount" mitigation used for the analogous `requestUnstake()` queue-spam issue.

### Proof of Concept
1. Attacker repeatedly posts minimal units, each containing a single `data_feed` message (e.g. `{feed_name: "x", value: i}`) from many distinct/rotating addresses, at a rate exceeding the DAG's stabilization rate, so that `storage.assocUnstableMessages` accumulates thousands of entries (writer.js `saveJoint` unconditionally pushes each such message into the map: `writer.js:603-613`).
2. Any AA (posted by anyone, including the attacker) that calls `data_feed[[oracles=SOME_ADDR, feed_name='y']]` triggers `dataFeedExists`/`readDataFeedValue`, which does `for (var unit in storage.assocUnstableMessages)` over the whole inflated map (`data_feeds.js:34`, `data_feeds.js:213`), performing `_.intersection` and per-message inspection for every entry regardless of relevance to `SOME_ADDR`.
3. As the attacker keeps posting more `data_feed` units, each subsequent AA trigger evaluation that touches `data_feed()` becomes proportionally slower for every full node in the network, since all nodes must execute the same deterministic AA logic.

### Citations

**File:** writer.js (L603-613)
```javascript
			if (objUnit.messages) {
				objUnit.messages.forEach(function(message) {
					if (['data_feed', 'definition', 'system_vote', 'system_vote_count'].includes(message.app)) {
						if (!storage.assocUnstableMessages[objUnit.unit])
							storage.assocUnstableMessages[objUnit.unit] = [];
						storage.assocUnstableMessages[objUnit.unit].push(message);
						if (message.app === 'system_vote' && !objValidationState.bDryRun)
							eventBus.emit('system_var_vote', message.payload.subject, message.payload.value, arrAuthorAddresses, objUnit.unit, 0);
					}
				});
			}
```

**File:** main_chain.js (L1550-1557)
```javascript
								async function saveUnstablePayloads() {
									let arrUnstableMessages = storage.assocUnstableMessages[unit];
									if (!arrUnstableMessages)
										return cb();
									if (objUnitProps.sequence === 'final-bad'){
										delete storage.assocUnstableMessages[unit];
										return cb();
									}
```

**File:** main_chain.js (L1583-1584)
```javascript
									delete storage.assocUnstableMessages[unit];
									cb();
```

**File:** data_feeds.js (L34-47)
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
```

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
