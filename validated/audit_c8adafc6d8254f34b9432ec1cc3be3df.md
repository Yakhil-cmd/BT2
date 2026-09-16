### Title
Denial of Data-Feed / AA-Trigger Processing via Unbounded Growth of `storage.assocUnstableMessages` — ([File: data_feeds.js])

### Summary
`dataFeedExists` and `readDataFeedValue` in `data_feeds.js` iterate linearly over the in-memory associative array `storage.assocUnstableMessages`, which accumulates one entry per not-yet-stable unit that contains a `data_feed`, `definition`, `system_vote`, or `system_vote_count` message, for as long as that unit remains unstable. Any unprivileged unit poster can post units containing `data_feed` messages at will, and each such unit stays in `assocUnstableMessages` until the main chain advances past it. This mirrors the reported `verifyDoubleSigning`/`delegatedValidators` bug class: a cheap, repeatable, attacker-controlled action grows an array that is later scanned with O(N) complexity on a path that other unprivileged actors (AA trigger senders) must traverse, with no length cap and no ability to prune it early.

### Finding Description
`storage.assocUnstableMessages` is populated in `writer.js` every time a unit with a `data_feed`/`definition`/`system_vote`/`system_vote_count` message is saved: [1](#0-0) 
and it is only cleared for a given unit once that unit's MCI stabilizes, in `main_chain.js`: [2](#0-1) 

Anyone can author a unit with a `data_feed` message — there is only a per-message cap (`MAX_DATA_FEEDS_PER_MESSAGE`), not a cap on the number of distinct units/messages a single address (or many addresses) can post over time: [3](#0-2) 

When an AA's oscript formula evaluates `data_feed[[...]]` / `in_data_feed[[...]]` with the "unstable" lookup option (used so an AA can react to data feeds that have not yet stabilized), the evaluator calls into `dataFeeds.readDataFeedValue`/`dataFeedExists`, which — instead of using the indexed on-disk data_feeds store — walks **every currently unstable unit in the whole network** that carries one of the tracked message types: [4](#0-3) [5](#0-4) 

For each candidate unstable unit it also does an `_.intersection` against the oracle address list and a full `forEach` over that unit's messages. As `assocUnstableMessages` grows (e.g., because an attacker posts many `data_feed`-bearing units, or because MC stabilization slows down for any reason), this loop's cost grows linearly with the size of the unstable set, and it is executed synchronously as part of AA trigger response computation, which every node must reproduce deterministically to advance stabilization.

The same growth-then-scan pattern is reused elsewhere over the identical structure (`getUnconfirmedAADefinitionsPostedByAAs` in `storage.js`, and the `get_system_var_votes` handler in `network.js`), confirming this is a systemic, unbounded, attacker-reachable data structure, not a one-off: [6](#0-5) [7](#0-6) 

### Impact Explanation
Because AA-trigger execution (and thus stabilization, which is deterministic and must be reproduced by every full node) depends on the size of the globally-shared unstable-message set, an attacker can cheaply and continuously post `data_feed`-bearing units (each unit only pays normal, small anti-spam fees and no special privilege is required) to keep inflating `assocUnstableMessages`. Any AA that uses "unstable" data-feed lookups (a documented, intended feature) then becomes progressively slower to execute for every trigger sent to it by any other user, and in the worst case this synchronous, unbounded work delays main-chain advancement/stabilization for the whole network — i.e., "a network unable to confirm new units" in a timely manner, and potential disagreement/lag between full nodes that are still catching up versus those already past the load.

### Likelihood Explanation
Likelihood is elevated to at least Medium because:
- No special privilege, attestation, or witness role is required — any unit-posting user can create `data_feed` messages.
- The cost of posting a `data_feed` message is a normal small transaction fee, while the growth of the shared `assocUnstableMessages` map persists for as long as the unit stays unstable, and units can be kept "fresh" continually by posting more.
- The vulnerable read path (`dataFeeds.readDataFeedValue`/`dataFeedExists` with the unstable option) is a documented, supported AA feature, so triggering it does not require unusual configuration — any AA developer relying on unstable-data-feed reads exposes their AA (and the node executing it) to this cost amplification.

### Recommendation
- Bound the number of tracked entries in `storage.assocUnstableMessages` that can originate from a given address/time window, or index unstable `data_feed` messages by `(feed_name, oracle address)` instead of doing a full O(N) scan of all unstable units per lookup.
- Enforce a global or per-oracle cap on the number of concurrently-unstable `data_feed`/`definition`/`system_vote` units considered by `readDataFeedValue`/`dataFeedExists`, falling back to "not found"/error once the cap is exceeded, analogous to capping `delegatedValidators`.
- Consider charging additional TPS-fee weight proportional to the current size of `assocUnstableMessages` for units that introduce new entries into it, to make the flooding strategy economically unattractive.

### Proof of Concept
1. Attacker repeatedly posts low-value units, each containing one `data_feed` message (`app: "data_feed"`), from one or many addresses. Each posted unit is accepted under existing anti-spam rules (`MAX_DATA_FEEDS_PER_MESSAGE` only limits feeds-per-message, not messages-per-network).
2. Each such unit adds an entry to `storage.assocUnstableMessages` (`writer.js:603-613`) and remains there until its MCI stabilizes (`main_chain.js:1550-1557`).
3. By sustaining a posting rate that keeps a large number of these units unstable (e.g., interleaved with witnessing delays, or simply posting a very large volume in a short interval), the attacker inflates the size of `assocUnstableMessages`.
4. Any AA that uses `data_feed[[..., unstable]]`/`in_data_feed[[..., unstable]]` (or the `light/get_data_feed`/`get_system_var_votes` endpoints) now must scan the entire inflated set on every trigger (`data_feeds.js:13-44`, `205-241`), making that AA's response computation — which every full node performs deterministically as part of stabilization — measurably slower and scaling linearly with the attacker-controlled unstable-message count.

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

**File:** constants.js (L53-55)
```javascript
exports.MAX_DATA_FEED_NAME_LENGTH = 64;
exports.MAX_DATA_FEED_VALUE_LENGTH = 64;
exports.MAX_DATA_FEEDS_PER_MESSAGE = 1024;
```

**File:** data_feeds.js (L13-44)
```javascript
function dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, max_mci, bAA, handleResult){
	var start_time = Date.now();
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	if (bAA) {
		var bFound = false;
		function relationSatisfied(v1, v2) {
			switch (relation) {
				case '<': return (v1 < v2);
				case '<=': return (v1 <= v2);
				case '>': return (v1 > v2);
				case '>=': return (v1 >= v2);
				default: throw Error("unknown relation: " + relation);
			}
		}
		function valueIsNumber() {
			if (typeof value === 'string') {
				const float = string_utils.toNumber(value, bLimitedPrecision);
				return float !== null;
			}
			return true;
		}
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
```

**File:** data_feeds.js (L205-241)
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
```

**File:** storage.js (L882-900)
```javascript
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

**File:** network.js (L3462-3487)
```javascript
					// unconfirmed votes
					is_stable = 0;
					for (let unit in storage.assocUnstableMessages) { // undefined order of iteration, we might handle unstable votes from the same address in the wrong order
						const arrUnstableMessages = storage.assocUnstableMessages[unit];
						for (let message of arrUnstableMessages) {
							if (message.app !== 'system_vote')
								continue;
							const { subject, value } = message.payload;
							const { author_addresses, timestamp, sequence } = storage.assocUnstableUnits[unit];
							if (sequence !== 'good')
								continue;
							for (let address of author_addresses) {
								const prev_vote = votes[subject].find(vote => vote.address === address);
								if (prev_vote) {
									prev_vote.value = value;
									prev_vote.timestamp = timestamp;
									prev_vote.unit = unit;
									prev_vote.is_stable = 0;
								}
								else {
									votes[subject].push({ address, unit, timestamp, value, is_stable });
									assocAddresses[address] = true;
								}
							}
						}
					}
```
