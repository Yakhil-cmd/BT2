### Title
Unbounded iteration over all unstable DAG units in `dataFeedExists()` during AA trigger evaluation causes gas/time DoS - (File: `data_feeds.js`)

### Summary
`dataFeedExists()` is invoked from the `in_data_feed` oscript operator that any Autonomous Agent (AA) definition can use in its formulas. When called in an AA context (`bAA === true`), it iterates over `storage.assocUnstableMessages`, a set that grows with **every unstable unit currently held in memory by the node** (i.e., the whole not-yet-stable portion of the DAG), and for each matching unstable unit it does a nested `.forEach` over that unit's messages. This mirrors the reported analog: an unbounded loop over a set that grows without limit, performed inside code that executes on every AA trigger, imposing linearly increasing CPU/gas cost as the unstable set grows.

### Finding Description
The vulnerable loop: [1](#0-0) 

```
for (var unit in storage.assocUnstableMessages) {
    var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
    ...
    storage.assocUnstableMessages[unit].forEach(function (message) { ... });
    ...
}
```

is reached from the `in_data_feed` operator evaluated by `formula/evaluation.js`, which is used inside any AA's `oscript`/`ojson` formula: [2](#0-1) 

`bAA` is passed straight through to `dataFeedExists`, so any address can post an ordinary AA trigger unit that causes the target AA (if its bytecode uses `in_data_feed`) to run this full scan of `storage.assocUnstableMessages` on every node that processes the trigger — during actual AA-response computation, i.e. transaction "validation"/execution, not just once at parse time.

Unlike the `and`/`or`/`r of set`/`weighted and` operators in `definition.js`, which are bounded by `MAX_COMPLEXITY`/`MAX_OPS` per evaluation: [3](#0-2) 

the cost of a single `in_data_feed` op inside `dataFeedExists` is **not** proportional to a fixed complexity budget — it scales with `storage.assocUnstableMessages`, an in-memory structure whose size is controlled by how many units the whole network currently has un-stabilized. An attacker (or even organic network congestion) can inflate the number of unstable units/messages, and every subsequent AA trigger that happens to call `in_data_feed` then pays the full cost of scanning that entire growing collection, plus a nested per-message `.forEach`.

### Impact Explanation
Because `dataFeedExists` runs synchronously as part of computing an AA's response (state/output changes, fund movement), an inflated unstable-unit set makes AA response computation on every node slower for any AA using `in_data_feed`. If growth of `assocUnstableMessages` is large enough (e.g., during periods of high network load or unit backlog), this can make timely computation of AA responses/bounces impractical on some nodes, risking disagreement about whether/how an AA responds within expected time, or effectively freezing funds routed through such AAs while the unstable set is inflated. This aligns with the report's "network unable to confirm/agree" and "AA fund loss or freezing" impact classes, though severity is bounded by how large `assocUnstableMessages` can practically grow before stabilization catches up.

### Likelihood Explanation
Any unprivileged unit poster can trigger this path merely by sending a trigger to an AA whose formula contains `in_data_feed` (a standard, documented oscript feature) — no special privilege, hub role, or peer position is required. The cost scales with a quantity (number of currently unstable units/messages) that is influenced by ordinary network activity and can be amplified by flooding the DAG with additional units before main-chain stabilization catches up.

### Recommendation
Bound the cost of the `bAA` branch in `dataFeedExists`, e.g., by capping the number of unstable units/messages scanned, indexing unstable data feeds by author address instead of doing a full `for...in` scan of `assocUnstableMessages`, or falling back to the already-bounded KV-stream-based `dataFeedByAddressExists` lookup when the unstable set exceeds a configured threshold.

### Proof of Concept
1. Deploy an AA whose formula uses `in_data_feed`, e.g. `in_data_feed[[oracles="ADDR", feed_name="x", feed_value>0]]`.
2. Flood the network with a large number of units (including some `data_feed` messages) that remain unstable for an extended period (e.g., by delaying stabilization via low-value/slow main-chain progress or simply high throughput), growing `storage.assocUnstableMessages`.
3. Send a trigger to the AA; observe that AA response computation time grows proportionally with the size of `storage.assocUnstableMessages` on every node processing the trigger, unlike other definition operators which are capped by `MAX_COMPLEXITY`/`MAX_OPS`.

### Citations

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

**File:** formula/evaluation.js (L701-745)
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
```

**File:** definition.js (L621-638)
```javascript
	var complexity = 0;
	var count_ops = 0;
	evaluate(arrDefinition, 'r', false, function(err, bHasSig){
		if (err)
			return handleResult(err);
		if (!bHasSig && !bAssetCondition)
			return handleResult("each branch must have a signature");
		if (complexity > constants.MAX_COMPLEXITY)
			return handleResult("complexity exceeded");
		if (count_ops > constants.MAX_OPS)
			return handleResult("number of ops exceeded");
		if (objValidationState.max_complexity) {
			objValidationState.complexity += complexity;
			if (objValidationState.complexity > objValidationState.max_complexity)
				return handleResult(`custom complexity limit ${objValidationState.max_complexity} exceeded`);
		}
		handleResult();
	});
```
