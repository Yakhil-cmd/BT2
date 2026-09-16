## Finding

Both `dataFeedExists()` and `readDataFeedValue()` in `data_feeds.js` contain a full linear scan over the global, network-wide `storage.assocUnstableMessages` object whenever they are called for an AA (i.e., whenever `bAA` is truthy). This collection holds every message of every unstable unit currently in the whole DAG, and it grows with overall network activity, not with anything scoped to the calling AA or trigger. [1](#0-0) [2](#0-1) 

Both formula ops `data_feed` and `in_data_feed` pass the `bAA` flag directly as the "unstable_opts" argument into `dataFeeds.readDataFeedValue()` / `dataFeeds.dataFeedExists()`: [3](#0-2) [4](#0-3) 

Inside `data_feeds.js`, whenever `bAA` is truthy, the code iterates `for (var unit in storage.assocUnstableMessages)` — over every unstable unit network-wide — before falling back to the indexed KV-store lookup: [5](#0-4) [6](#0-5) 

### Title
Unbounded scan of network-wide `assocUnstableMessages` in AA data-feed lookups causes ever-growing evaluation cost - (File: data_feeds.js)

### Summary
`dataFeedExists()` and `readDataFeedValue()` (used by the `data_feed`/`in_data_feed` oscript formula ops available to any AA) perform an unconditional `for...in` loop over `storage.assocUnstableMessages`, an in-memory collection of **all** messages belonging to **all currently-unstable units in the entire DAG**, whenever the call originates from AA evaluation (`bAA` truthy). This loop has no size cap and its cost scales with total network-wide unstable-unit volume rather than with the number of oracle addresses queried.

### Finding Description
Any AA author can write a definition that uses `data_feed[[...]]` or `in_data_feed[[...]]`. Any unprivileged user can then post a trigger unit to that AA. Each such trigger causes `handleTrigger` → formula evaluation → `getDataFeed`/`dataFeedExists`, which, because `bAA` is true, executes:

```js
for (var unit in storage.assocUnstableMessages) {
    var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
    ...
    storage.assocUnstableMessages[unit].forEach(function (message) { ... });
}
``` [7](#0-6) [8](#0-7) 

`storage.assocUnstableMessages` is populated for every unit in the DAG that has not yet become stable (writer.js adds to it on every unit write) and is not scoped by asset, AA, or address — it is a single global map shared by the whole node. As DAG throughput increases (more parallel/unstable units awaiting the ~12-witness-level stabilization window, e.g. during periods of high transaction volume, deliberate flooding of otherwise-valid units, or AA response chains), the size of this map grows, and so does the per-call cost of *every* AA that uses `data_feed`/`in_data_feed`, for *every* trigger sent to it. This mirrors the reported analog: a function whose cost is driven by an externally/temporally growing collection that is iterated in full on every invocation, with no cap on iterations, eventually risking execution-time exhaustion (the "out of gas" analog in ocore is exceeding the AA execution time budget / node responsiveness, causing the AA to bounce unpredictably or degrade node performance for all AAs using data feeds).

### Impact Explanation
Because the entire unstable-message map is scanned on every AA data-feed evaluation, an attacker can inflate this map (by flooding valid units into the DAG, keeping many units unstable simultaneously) and then trigger AAs that use `data_feed`/`in_data_feed`. This increases CPU time consumed per AA execution across the board (not just for the attacker's own AA), which can cause primary-trigger response computation to slow down, potentially pushing execution outside acceptable time budgets and causing legitimate AA responses to bounce (loss of funds availability/inconsistent execution) or degrading throughput/stability determination for the whole node. This is a medium-severity availability/logic-integrity issue reachable by an ordinary AA trigger sender combined with an AA author who is free to include `data_feed` calls, matching the "AA fund loss or freezing" / "network unable to confirm new units in a timely manner" category.

### Likelihood Explanation
Any user can author an AA using `data_feed`/`in_data_feed` (very common oscript primitives for oracle price feeds), and any user can send it a trigger — no special privilege required. The size of `assocUnstableMessages` is a natural function of DAG throughput and is not something the calling AA or trigger controls directly, but it can be pushed up by ordinary, valid transaction volume or a moderately-resourced actor posting many valid units to keep them unstable, making the degraded-performance condition realistically reachable over time as network usage grows — directly analogous to the referenced report's concern about a loop whose bound grows as the system scales.

### Recommendation
Avoid the unconditional in-memory scan of the entire `assocUnstableMessages` map. Instead, index unstable data-feed messages by `(address, feed_name)` (e.g., maintain a secondary per-address/per-feed structure) so that lookups in `dataFeedExists`/`readDataFeedValue` are proportional to the number of unstable messages actually relevant to the queried oracle addresses/feed name, not to the total number of unstable messages network-wide. Alternatively, bound/cap the scan and/or short-circuit earlier when a match window is exceeded.

### Proof of Concept
1. An attacker (or any legitimate user during high load) posts many valid units so that the network temporarily accumulates a large number of unstable units (`storage.assocUnstableMessages` grows).
2. Any AA definition that contains `data_feed[[oracles=..., feed_name=...]]` or `in_data_feed[[...]]` is triggered by an ordinary user.
3. `formula/evaluation.js`'s `data_feed`/`in_data_feed` handlers call `dataFeeds.readDataFeedValue`/`dataFeeds.dataFeedExists` with `bAA=true`.
4. `data_feeds.js` executes the `for (var unit in storage.assocUnstableMessages)` loop, iterating over every currently unstable unit in the entire DAG regardless of relevance to the queried oracle addresses, before falling back to the indexed store lookup — cost scaling with total unstable-unit count at trigger time.

### Citations

**File:** formula/evaluation.js (L600-663)
```javascript
			case 'data_feed':

				function getDataFeed(params, cb) {
					if (typeof params.oracles.value !== 'string')
						return cb("oracles not a string "+params.oracles.value);
					var arrAddresses = params.oracles.value.split(':');
					if (!arrAddresses.every(ValidationUtils.isValidAddress))
						return cb("bad oracles "+arrAddresses);
					var feed_name = params.feed_name.value;
					if (!feed_name || typeof feed_name !== 'string')
						return cb("empty feed_name or not a string");
					var value = null;
					var relation = '';
					var min_mci = 0;
					if (params.feed_value) {
						value = params.feed_value.value;
						relation = params.feed_value.operator;
						if (!isValidValue(value))
							return cb("bad feed_value: "+value);
					}
					if (params.min_mci) {
						min_mci = params.min_mci.value.toString();
						if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
							return cb("bad min_mci: "+min_mci);
						min_mci = parseInt(min_mci);
					}
					var ifseveral = 'last';
					if (params.ifseveral){
						ifseveral = params.ifseveral.value;
						if (ifseveral !== 'abort' && ifseveral !== 'last')
							return cb("bad ifseveral: "+ifseveral);
					}
					var what = 'value';
					if (params.what){
						what = params.what.value;
						if (what !== 'unit' && what !== 'value')
							return cb("bad what: "+what);
					}
					var type = 'auto';
					if (params.type){
						type = params.type.value;
						if (type !== 'string' && type !== 'auto')
							return cb("bad df type: "+type);
					}
					if (params.ifnone && !isValidValue(params.ifnone.value))
						return cb("bad ifnone: "+params.ifnone.value);
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
					//	console.log(arrAddresses, feed_name, value, min_mci, ifseveral);
					//	console.log('---- objResult', objResult);
						if (objResult.bAbortedBecauseOfSeveral)
							return cb("several values found");
						if (objResult.value !== undefined){
							if (what === 'unit')
								return cb(null, objResult.unit);
							if (type === 'string')
								return cb(null, objResult.value.toString());
							return cb(null, (typeof objResult.value === 'string') ? objResult.value : createDecimal(objResult.value));
						}
						if (params.ifnone && params.ifnone.value !== 'abort'){
						//	console.log('===== ifnone=', params.ifnone.value, typeof params.ifnone.value);
							return cb(null, params.ifnone.value); // the type of ifnone (string, decimal, boolean) is preserved
						}
						cb("data feed " + feed_name + " not found");
					});
```

**File:** formula/evaluation.js (L701-748)
```javascript
			case 'in_data_feed':
				var params = arr[1];
				var evaluated_params = {};
				async.eachSeries(
					Object.keys(params),
					function(param_name, cb2){
						evaluate(params[param_name].value, function(res){
							if (fatal_error)
								return cb2(fatal_error);
							if (res instanceof wrappedObject)
								res = true;
							if (!isValidValue(res) || typeof res === 'boolean')
								return setFatalError('bad in-df param', { arr }, undefined, cb2);
							if (Decimal.isDecimal(res))
								res = toDoubleRange(res);
							evaluated_params[param_name] = {
								operator: params[param_name].operator,
								value: res
							};
							cb2();
						});
					},
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
				);
				break;
```

**File:** data_feeds.js (L16-94)
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

**File:** data_feeds.js (L211-241)
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
```
