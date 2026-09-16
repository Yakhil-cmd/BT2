### Title
Uncontrolled resource consumption via `in_data_feed`/`data_feed` scanning all unstable DAG messages during AA formula evaluation - (File: data_feeds.js)

### Summary
The oscript formula operators `data_feed[[...]]` and `in_data_feed[[...]]`, when evaluated for an Autonomous Agent (AA) trigger, can force every validating node to iterate over the *entire* in-memory set of currently-unstable units (`storage.assocUnstableMessages`) — an amount of work that scales with the size of the unconfirmed part of the DAG rather than with any fixed, metered cost. Because the oscript complexity/`count_ops` accounting in `formula/validation.js` charges these operators a small constant cost regardless of how many unstable messages actually get scanned at evaluation time, an unprivileged unit poster can cheaply trigger disproportionately expensive AA evaluations, analogous to the CV-CUDA "uncontrolled resource consumption" bug class (fixed-cost API call triggering unbounded internal work leading to DoS).

### Finding Description
When `bAA` is true, `dataFeedExists()` performs a linear scan over `storage.assocUnstableMessages` for *every* unstable unit currently known to the node, checking author-address intersection and iterating that unit's messages, before falling back to the indexed `dataFeedByAddressExists` path: [1](#0-0) 

This scan is invoked directly from the oscript `in_data_feed` evaluator inside `formula/evaluation.js`, reachable from any AA that includes an `in_data_feed[[...]]` expression: [2](#0-1) 

The equivalent unstable-scan path also exists for `data_feed[[...]]` via `readDataFeedValue`, which similarly iterates `storage.assocUnstableMessages` when `unstable_opts` is set: [3](#0-2) 

The formula validator (`formula/validation.js`) is responsible for bounding the "price" of a formula via `complexity` and `count_ops`, which are enforced against `MAX_COMPLEXITY`/`MAX_OPS` before a formula is allowed to run. However, this pricing is a static, per-operator constant — it does not (and structurally cannot, at validation time) account for how many unstable units/messages exist in the node's current state when the AA is later *evaluated*. As the number of unconfirmed units in the DAG grows (which any user can inflate simply by posting many ordinary units, since payment units are cheap and this pool is shared by the whole network), the fixed-price `in_data_feed`/`data_feed` calls become arbitrarily more expensive to actually execute, without the attacker paying more or the formula's static complexity score reflecting the true cost.

This is structurally the same bug class as CVE-2024-0115: a bounded/metered API surface (CV-CUDA Python calls / oscript formula ops) whose per-call cost is assumed constant but which can internally perform unbounded work, allowing a normal caller to cause uncontrolled resource consumption purely by triggering the call repeatedly (or under adverse network conditions), leading to denial of service.

### Impact Explanation
Every full node must evaluate AA triggers during unit processing/stabilization. If an attacker (or just organic network load) causes the unstable-unit set to grow large, and deploys/uses an AA whose formula calls `in_data_feed`/`data_feed` with `unstable_opts` (which any AA author or trigger sender can construct and repeatedly invoke via a posted unit), each trigger evaluation does O(number of unstable units) work. Under load this can meaningfully slow down validation/stabilization across the network, directly matching the "no-impact-on-funds but denial-of-service through processing delay" impact category (a network unable to confirm new units promptly, or nodes disagreeing on processing timing under resource pressure). It does not directly enable fund theft or supply inflation.

### Likelihood Explanation
Likelihood is moderate: it requires (a) deployment of an AA using `in_data_feed`/`data_feed` with the unstable-scan option, and (b) an attacker inflating the unstable-unit pool with many cheap units and then repeatedly sending triggers to that AA. Both actions are available to any unprivileged unit poster/AA trigger sender using ordinary wallet functionality; no privileged network/peer role is required.

### Recommendation
Bound the cost of `in_data_feed`/`data_feed` unstable-set scans independently of static formula complexity — e.g., cap the number of unstable units/messages inspected per call (returning "not found"/error once the cap is hit) as is already done for other unbounded structures (`isTooBigObj`/`isTooDeeplyNestedOrHasTooManyNodes` in `string_utils.js`), or charge `count_ops`/`complexity` proportionally to `storage.assocUnstableMessages` size at evaluation time so the fixed-price assumption in `formula/validation.js` holds.

### Proof of Concept
1. Deploy an AA whose formula contains, e.g.: `in_data_feed[[oracles="<addr>", feed_name="x", feed_value>0, min_mci=0]]` evaluated with unstable-inclusion semantics (`bAA` path).
2. Flood the network with a large number of ordinary units to inflate `storage.assocUnstableMessages` (this is normal, low-cost activity available to any user).
3. Repeatedly send trigger units to the AA. Each trigger evaluation causes `dataFeedExists()` to iterate the full, now-large `assocUnstableMessages` map, even though the formula's `count_ops`/`complexity` charge stayed constant, causing disproportionate CPU time relative to fee paid — reproducible by comparing evaluation latency of the same formula/complexity budget at low vs. high unstable-unit counts.

### Citations

**File:** data_feeds.js (L16-44)
```javascript
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

**File:** formula/evaluation.js (L723-746)
```javascript
					function(err){
						if (fatal_error)
							return cb(false);
						if (typeof evaluated_params.oracles.value !== 'string')
							return setFatalError('oracles is not a string', { arr }, false, cb);
						var arrAddresses = evaluated_params.oracles.value.split(':');
						if (!arrAddresses.every(ValidationUtils.isValidAddress)) // even if some addresses are ok
							return setFatalError('bad oracles', { arr }, false, cb);
						var feed_name = evaluated_params.feed_name.value;
						if (!feed_name || typeof feed_name !== 'string')
							return setFatalError('bad feed name', { arr }, false, cb);
						var value = evaluated_params.feed_value.value;
						var relation = evaluated_params.feed_value.operator;
						if (!isValidValue(value))
							return setFatalError("bad feed_value: "+value, { arr }, false, cb);
						var min_mci = 0;
						if (evaluated_params.min_mci){
							min_mci = evaluated_params.min_mci.value.toString();
							if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
								return setFatalError('bad min_mci', { arr }, false, cb);
							min_mci = parseInt(min_mci);
						}
						dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, mci, bAA, cb);
					}
```
