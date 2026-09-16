### Title
Denial of Service via Unbounded In-Memory Scan of All Unstable Units in AA `data_feed`/`in_data_feed` Evaluation - (File: data_feeds.js)

### Summary
The `data_feed` and `in_data_feed` oscript operators, when evaluated inside an Autonomous Agent (bAA=true), trigger `dataFeeds.readDataFeedValue()` / `dataFeeds.dataFeedExists()`, which iterate synchronously over **every currently-unstable unit in the whole network** (`storage.assocUnstableMessages`) and all of their messages, on every single invocation. This cost is completely unbounded and is not reflected in the formula's complexity/op-count budget, which only charges a flat cost of 1 per `data_feed`/`in_data_feed` call regardless of how large the unstable-unit set is.

### Finding Description
`formula/evaluation.js` handles the `data_feed` and `in_data_feed` ops by calling into `data_feeds.js`: [1](#0-0) [2](#0-1) 

Both `readDataFeedValue()` and `dataFeedExists()` contain a loop `for (var unit in storage.assocUnstableMessages)` that walks the entire in-memory map of unstable units network-wide and, for each one, does a `.forEach()` over all of that unit's messages, whenever `bAA` (AA context) is true: [3](#0-2) [4](#0-3) 

`storage.assocUnstableMessages` grows with every unstable unit posted anywhere on the DAG (it is populated in `writer.js`/`main_chain.js`), so its size is controlled by the aggregate rate of unit submission relative to stabilization, not by anything the caller can bound.

Meanwhile, the *cost accounting* for these ops during AA validation only adds a fixed, tiny complexity of 1, independent of the actual O(N) (or worse, O(N·messages)) work the interpreter will perform at execution time: [5](#0-4) [6](#0-5) 

Because `MAX_COMPLEXITY`/`MAX_OPS` (100 / 2000) are meant to bound the actual work an AA formula can perform, but this particular loop's cost is decoupled from those counters, an attacker can cheaply write an AA whose trigger evaluation repeatedly calls `data_feed[[...]]` (each call only "costs" 1 complexity point, so tens of such calls fit well within budget) while the network is under load with many unstable units, causing the AA-trigger handler (`aa_composer.js` `handleTrigger` → `evaluateAA`) to perform a very large, synchronous, single-threaded scan on every trigger. This code runs while holding the `['aa_triggers']` / write mutex used for processing new units: [7](#0-6) [8](#0-7) 

### Impact Explanation
Because unit processing (validation + AA triggering) is serialized behind the write lock, a computationally expensive synchronous scan triggered from a single posted unit that invokes an AA relying on `data_feed`/`in_data_feed` can stall processing of subsequent units for the whole node while the scan runs. If an attacker also inflates `storage.assocUnstableMessages` (by rapidly posting many low-cost units, which is cheap relative to the quadratic-ish cost this induces per AA trigger evaluation), the per-trigger cost grows with total network unstable-unit count, not with anything the attacker directly pays for at time of triggering. This can push a node toward an extended block of the write path, i.e., the node becomes temporarily unable to confirm/process new units — matching the "network unable to confirm new units" impact class.

### Likelihood Explanation
`data_feed` is one of the most commonly used oscript primitives (nearly every price-oracle-driven AA, e.g. DEX/AMM contracts, uses it), so a large fraction of deployed AAs already invoke this code path on every trigger. An attacker does not need a privileged role — any account can (a) deploy an AA that calls `data_feed`/`in_data_feed` multiple times, or simply trigger existing popular oracle-consuming AAs, and (b) separately flood the network with cheap unstable units to inflate `assocUnstableMessages`. The complexity/op-count guard that is supposed to bound AA execution cost does not account for this loop's true cost, so there is no economic throttle stopping repeated invocation.

### Recommendation
- Charge complexity/op cost for `data_feed`/`in_data_feed` proportional to the size of the in-memory unstable set actually scanned (or cap the number of unstable units/messages inspected per call and fall back to a bounded DB query beyond that).
- Alternatively, maintain an indexed structure (e.g., per-oracle-address/feed_name map of unstable data-feed messages) instead of a linear scan over all unstable units, so lookup cost is proportional to the relevant oracle's activity, not to global network state.
- Add a hard cap on how many unstable units/messages a single AA trigger evaluation may scan via `data_feed`/`in_data_feed`, independent of `MAX_COMPLEXITY`.

### Proof of Concept
1. Deploy an AA whose trigger handler contains several `data_feed[[oracles=..., feed_name=..., ...]]` or `in_data_feed[[...]]` calls (well within `MAX_COMPLEXITY`/`MAX_OPS`, e.g. 10–20 calls at complexity 1 each).
2. Concurrently (or beforehand), post a large number of cheap units from one or more addresses fast enough that they remain unstable, inflating `storage.assocUnstableMessages` (each unstable unit persists in memory until DAG stabilization catches up).
3. Trigger the AA. Each `data_feed`/`in_data_feed` call performs a full synchronous `for...in`/`.forEach()` scan over the entire unstable-unit map and its messages inside `dataFeeds.readDataFeedValue`/`dataFeedExists`, executed under the AA-processing write lock, delaying processing of subsequently queued units.

### Citations

**File:** formula/evaluation.js (L646-663)
```javascript
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

**File:** formula/evaluation.js (L726-745)
```javascript
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

**File:** formula/validation.js (L26-83)
```javascript
function validateDataFeed(params) {
	var complexity = 1;
	if (params.oracles && params.feed_name) {
		for (var name in params) {
			var operator = params[name].operator;
			var value = params[name].value;
			if (Decimal.isDecimal(value)){
				if (!isFiniteDecimal(value))
					return {error: 'not finite', complexity};
				value = toDoubleRange(value).toString();
			}
			if (operator !== '=') return {error: 'not =', complexity};
			if (['oracles', 'feed_name', 'min_mci', 'feed_value', 'ifseveral', 'ifnone', 'what', 'type'].indexOf(name) === -1)
				return {error: 'unknown df param: ' + name, complexity};
			if (typeof value !== 'string')
				continue;
			switch (name) {
				case 'oracles':
					if (value.trim() === '') return {error: 'empty oracle', complexity};
					var addresses = value.split(':');
					if (addresses.length === 0) return {error: 'empty oracle list', complexity};
				//	complexity += addresses.length;
					if (!addresses.every(ValidationUtils.isValidAddress)) return {error: 'oracle address not valid', complexity};
					break;

				case 'feed_name':
					if (value.trim() === '') return {error: 'empty feed name', complexity};
					break;

				case 'min_mci':
					if (!(/^\d+$/.test(value) && ValidationUtils.isNonnegativeInteger(parseInt(value)))) return {
						error: 'bad min_mci',
						complexity
					};
					break;

				case 'feed_value':
					break;
				case 'ifseveral':
					if (!(value === 'last' || value === 'abort')) return {error: 'bad ifseveral: ' + value, complexity};
					break;
				case 'ifnone':
					break;
				case 'what':
					if (!(value === 'value' || value === 'unit')) return {error: 'bad what: ' + value, complexity};
					break;
				case 'type':
					if (!(value === 'string' || value === 'auto')) return {error: 'bad df type: ' + value, complexity};
					break;
				default:
					throw Error("unrecognized name after checking: "+name);
			}
		}
		return {error: false, complexity};
	} else {
		return {error: 'no oracles or feed name', complexity};
	}
}
```

**File:** formula/validation.js (L381-395)
```javascript
			case 'data_feed':
			case 'in_data_feed':
				var params = arr[1];
				var result = (op === 'data_feed') ? validateDataFeed(params) : validateDataFeedExists(params);
				complexity += result.complexity;
				if (result.error)
					return cb(result.error);
				async.eachSeries(
					Object.keys(params),
					function(param_name, cb2){
						evaluate(params[param_name].value, cb2);
					},
					cb
				);
				break;
```

**File:** aa_composer.js (L59-89)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
}
```

**File:** aa_composer.js (L1865-1868)
```javascript
		evaluateAA(arrDefinition, function (err) {
			if (err)
				return bounce(err);
			var messages = template.messages;
```
