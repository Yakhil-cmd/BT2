### Title
Unbounded iteration over `storage.assocUnstableMessages` in the `data_feed()` oscript function lets any unprivileged unit poster degrade or stall AA execution and MC stabilization - ([File: data_feeds.js])

### Summary
`data_feeds.js:dataFeedExists()` and `readDataFeedValue()` implement the "look at unstable AA-visible data feeds" fast-path used by the `data_feed()` oscript function that any AA can call during trigger execution. Both functions contain a `for (var unit in storage.assocUnstableMessages) { ... }` loop that iterates over *every* entry cached in `storage.assocUnstableMessages` — a process‑wide, in‑memory map that is populated, without any cap, for every `data_feed` / `definition` / `system_vote` / `system_vote_count` message of every still‑unstable unit on the DAG (see `writer.js` around the `saveJoint` message‑caching block). This is structurally the same bug class as the UFarmPool `quexCallback` issue: an attacker‑influenced, unbounded collection is walked in full inside a hot, synchronous code path that every unprivileged AA-triggering unit can force to execute.

### Finding Description
`storage.assocUnstableMessages` is filled unconditionally whenever a unit containing a `data_feed`, `definition`, `system_vote`, or `system_vote_count` message is written, and entries are only removed once that unit's MCI stabilizes: [1](#0-0) 

Posting a `data_feed` message only requires being any valid address; it is not restricted to "oracle" addresses, so any unprivileged unit poster can add arbitrarily many entries to this map simply by posting many low‑value units carrying `data_feed` messages while they remain unstable (i.e. before their MCI is finalized).

Every call to the oscript `data_feed()` formula function (reachable from any AA trigger, i.e. from any unprivileged AA-trigger sender who sends a payment to an AA that calls `data_feed()`) invokes `dataFeeds.readDataFeedValue()`/`dataFeeds.dataFeedExists()`: [2](#0-1) 

Inside these functions, when unstable/AA visibility is requested, the code scans the *entire* `assocUnstableMessages` map, regardless of whether the entries are relevant to the queried oracle addresses, before falling back to a KV-store lookup: [3](#0-2) [4](#0-3) 

The equivalent unbounded pattern also exists in `storage.js`'s `getUnconfirmedAADefinition()` and `getUnconfirmedAADefinitionsPostedByAAs()`, which are invoked on every AA-defined-AA insertion / secondary trigger dispatch and likewise iterate the full `assocUnstableMessages` map: [5](#0-4) 

Node.js runs all of this synchronously in a single-threaded event loop, and unit writing/AA execution occurs under the global write mutex (`saveJoint`/`handleAATriggers`), so a sufficiently large `assocUnstableMessages` map causes each AA trigger that touches `data_feed()` (or each AA-defined-AA insertion) to take proportionally longer, serialized behind the same lock that blocks new-unit validation and MC stabilization for the whole node. Unlike the UFarmPool bug there is no hard revert, but the growth is unbounded by count (only bounded by wall-clock time until MCI stabilization, which itself can be delayed further if the attacker also congests DAG growth), and there is no cap analogous to `MAX_INPUTS_PER_PAYMENT_MESSAGE`/`MAX_MESSAGES_PER_UNIT` limiting the size of this in-memory structure or the number of iterations performed per call.

### Impact Explanation
An attacker who floods the network with cheap units carrying `data_feed` messages (from arbitrary, non-oracle addresses) can grow `assocUnstableMessages` to a large size while those units remain unstable. Every subsequent AA trigger that calls `data_feed()` — a routine oscript primitive used by numerous production AAs (price oracles, DEXes, lending protocols) — then pays an O(n) scan cost on the *global* set of pending data-feed/definition/system-vote messages, not just its own oracle's messages. Because this scan runs inside the single-threaded write-locked path that also handles MC advancement (`writer.saveJoint` → `aa_composer.handleAATriggers`), sufficiently large `n` can materially slow down or effectively stall the processing of new units network-wide, i.e. "a network unable to confirm new units in a timely manner," and can cause AA responses that rely on `data_feed()` to time out or bounce unpredictably (AA fund freezing/failed execution) depending on how long the scan takes relative to any surrounding timeouts.

### Likelihood Explanation
Likelihood is moderate: posting a `data_feed` message costs normal unit fees (headers/payload commission, tps fee), so this is not literally free like the UFarmPool `depositQueue` push, but it is cheap relative to the amount of damage (any address can post `data_feed` messages, no whitelisting), and the attack only needs the flood units to remain unstable for a window of time, which an attacker can extend by delaying their own confirmation (e.g., withholding witnessing, submitting units late in the round) or simply sustaining a continuous flood.

### Recommendation
- Index `assocUnstableMessages` (or a derived structure) by feed_name/oracle address so `dataFeedExists`/`readDataFeedValue`/`getUnconfirmedAADefinition(s)` can do a targeted lookup instead of a full linear scan over all unstable units.
- Impose a hard cap on the number of `data_feed`/`definition`/`system_vote(_count)` messages retained per address (or globally) in `assocUnstableMessages`, mirroring the existing caps such as `MAX_INPUTS_PER_PAYMENT_MESSAGE`/`MAX_OUTPUTS_PER_PAYMENT_MESSAGE`/`MAX_MESSAGES_PER_UNIT`.
- Consider charging a higher fee or requiring bonding for `data_feed` messages from addresses that are not already registered as oracles for any AA, to raise the economic cost of flooding this cache.

### Proof of Concept
1. From many throwaway addresses, submit a large number of low-value units, each containing a `data_feed` message with a distinct `feed_name`, keeping them from stabilizing quickly (e.g., submit continuously so a large "unstable tail" is always present). This grows `storage.assocUnstableMessages` unboundedly.
2. Meanwhile, trigger any AA that calls `data_feed(oracles=..., feed_name=..., ...)` in its oscript (a routine, common pattern for price/exchange/lending AAs) via a normal, unprivileged payment+trigger unit.
3. Observe that `dataFeeds.readDataFeedValue()`'s `bIncludeUnstableAAs` branch (`data_feeds.js:211-274`) must scan the entire (now large) `assocUnstableMessages` map on every such AA trigger, executing this scan synchronously inside the global write-locked path (`writer.saveJoint` → `aa_composer.handleAATriggers`), measurably slowing down the processing of *every* new unit on the node — not just the attacker's units — for as long as the flood is sustained.

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

**File:** formula/evaluation.js (L646-646)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
```

**File:** data_feeds.js (L34-94)
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
				if (relation === '=') {
					if (value === feed_value || value.toString() === feed_value.toString())
						bFound = true;
					return;
				}
				if (relation === '!=') {
					// search only within the same type, otherwise 'abc' != 123 but we don't want to say that they are not equal, because they are incomparable
					if (valueIsNumber()) {
						if (value.toString() !== feed_value.toString())
							bFound = true;
					}
					else {
						if (value !== feed_value)
							bFound = true;
					}
					return;
				}
				if (typeof value === 'number' && typeof feed_value === 'number') {
					if (relationSatisfied(feed_value, value))
						bFound = true;
					return;
				}
				var f_value = (typeof value === 'string') ? string_utils.toNumber(value, bLimitedPrecision) : value;
				var f_feed_value = (typeof feed_value === 'string') ? string_utils.toNumber(feed_value, bLimitedPrecision) : feed_value;
				if (f_value === null && f_feed_value === null) { // both are strings that don't look like numbers
					if (relationSatisfied(feed_value, value))
						bFound = true;
					return;
				}
				if (f_value !== null && f_feed_value !== null) { // both are either numbers or strings that look like numbers
					if (relationSatisfied(f_feed_value, f_value))
						bFound = true;
					return;
				}
				if (typeof value === 'string' && typeof feed_value === 'string') { // only one string looks like a number
					if (relationSatisfied(feed_value, value))
						bFound = true;
					return;
				}
				// else they are incomparable e.g. 'abc' > 123
			});
			if (bFound)
				break;
		}
```

**File:** data_feeds.js (L211-274)
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
		}
		if (arrCandidates.length === 1) {
			var feed = arrCandidates[0];
			objResult.value = feed.value;
			objResult.unit = feed.unit;
			objResult.mci = feed.mci;
			if (ifseveral === 'last')
				return handleResult(objResult);
		}
		else if (arrCandidates.length > 1) {
			if (ifseveral === 'abort') {
				objResult.bAbortedBecauseOfSeveral = true;
				return handleResult(objResult);
			}
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
			var feed = arrCandidates[arrCandidates.length - 1];
			objResult.value = feed.value;
			objResult.unit = feed.unit;
			objResult.mci = feed.mci;
			return handleResult(objResult);
		}
	}
```

**File:** storage.js (L862-900)
```javascript
function getUnconfirmedAADefinition(address) {
	for (var unit in assocUnstableMessages) {
		var objUnit = assocUnstableUnits[unit] || assocStableUnits[unit]; // just stabilized
		if (!objUnit)
			throw Error("unstable unit " + unit + " not in assoc");
		if (objUnit.sequence !== 'good')
			continue;
		var messages = assocUnstableMessages[unit];
		for (var i = 0; i < messages.length; i++) {
			var message = messages[i];
			if (message.app !== 'definition')
				continue;
			var payload = message.payload;
			if (payload.address === address)
				return payload.definition;
		}
	}
	return null;
}

// arrAddresses is an array of AA addresses whose definitions are posted by other AAs
function getUnconfirmedAADefinitionsPostedByAAs(arrAddresses) {
	var payloads = [];
	for (var unit in assocUnstableMessages) {
		var objUnit = assocUnstableUnits[unit] || assocStableUnits[unit]; // just stabilized
		if (!objUnit)
			throw Error("unstable unit " + unit + " not in assoc");
		if (!objUnit.bAA)
			continue;
		assocUnstableMessages[unit].forEach(function (message) {
			if (message.app !== 'definition')
				return;
			var payload = message.payload;
			if (arrAddresses.indexOf(payload.address) >= 0)
			payloads.push(payload);
		});
	}
	return payloads;
}
```
