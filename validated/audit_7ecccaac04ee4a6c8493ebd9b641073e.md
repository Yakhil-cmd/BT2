### Title
Denial of service via unbounded per-unit scan in `in_data_feed`/`data_feed` AA formula evaluation - (File: `data_feeds.js`)

### Summary
`dataFeedExists()` in `data_feeds.js` performs an O(N) linear scan over every currently unstable unit in the DAG (`storage.assocUnstableMessages` / `storage.assocUnstableUnits`) whenever an AA formula uses the `in_data_feed` operator (or `in data feed` in address definitions/oscript). The oscript static-complexity validator (`formula/validation.js`, `validateDataFeed`) charges this operation a fixed, tiny complexity cost (complexity `1`, no scaling with DAG state), so the cost accounting model does not reflect the real, unbounded work performed at evaluation time. Any address holder can post a trigger unit that causes an AA to evaluate `in_data_feed(...)`, forcing the node to iterate the full unstable-unit set on every trigger, cheaply and repeatedly, inside the same serialized unit-validation/AA-execution pipeline that processes all other incoming units.

### Finding Description
- `dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, max_mci, bAA, handleResult)` in `data_feeds.js:13` begins, when `bAA` is true, with:
```
for (var unit in storage.assocUnstableMessages) {
    var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
    ...
}
``` [1](#0-0) 
This loop walks over **every unstable unit currently tracked by the node**, independent of `arrAddresses`/`feed_name` selectivity, before falling back to a DB query per oracle address (`dataFeedByAddressExists`) for the non-bAA path [2](#0-1) .

- This function is reachable from a single posted trigger via two oscript entry points:
  - `in_data_feed` inside AA formula evaluation, in `formula/evaluation.js:701-748`, which calls `dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, mci, bAA, cb)` [3](#0-2) .
  - `in data feed` inside address-definition evaluation, in `definition.js:933-940`, which calls the same function with `bAA=false` (still funnels into the per-address DB lookup path) [4](#0-3) .

- The static complexity/ops accounting for this operator in the formula validator only assigns a flat cost:
```
function validateDataFeed(params) {
    var complexity = 1;
    ...
}
``` [5](#0-4) 
and this fixed cost is what is compared against `constants.MAX_COMPLEXITY`/`constants.MAX_OPS` in `aa_validation.js:567-570` and `formula/validation.js` [6](#0-5) . There is no term in the cost model that scales with the number of unstable units currently in the DAG, i.e., the *declared* cost of the operation is decoupled from its *actual* runtime cost.

- All unit validation, including AA trigger validation and (per `network.js`) primary AA trigger dry-runs, is serialized through `mutex.lock(...)`/`mutex.lock('handleJoint')`, e.g. in `validation.js:357` and `network.js:1258` [7](#0-6) [8](#0-7) . This means the expensive `dataFeedExists` scan runs on the same shared, effectively single-threaded processing path used to validate and confirm every other incoming unit on the node — directly analogous to Mattermost's "shared extraction worker pool" being saturated by cheap-to-submit-but-expensive-to-process documents.

### Impact Explanation
An attacker who can post a payment/trigger to any AA whose oscript uses `in_data_feed` (or who defines such an AA/address themselves — no special privilege required) can repeatedly send small, cheap trigger units. Each trigger causes the node to scan the entire in-memory unstable-unit index during validation before other units in the queue can be validated. Because the static cost model charges only complexity `1` for this, the attacker's cost to submit (byte fee) is essentially unrelated to the actual CPU/O(N) work induced, and this work happens inside the mutex-serialized validation pipeline shared by the whole node. Under load (many outstanding unstable units, which can itself be inflated by cheap unit spam), this can materially delay validation/confirmation of unrelated units — a network unable to confirm new units in a timely manner, matching the required "node unable to confirm new units" impact bar.

### Likelihood Explanation
Likelihood is moderate: exploitation requires (a) an AA using `in_data_feed` to exist and be triggerable (attacker can deploy their own AA to guarantee this) and (b) a sufficiently large pool of unstable units to make the scan costly. Both conditions are attacker-controllable without needing any special permission — deploying an AA and sending trigger units are actions available to any unprivileged address, and inflating the unstable-unit count can be done by the same attacker via ordinary cheap unit spam.

### Recommendation
- Charge `in_data_feed`/`data_feed` complexity or `count_ops` proportional to the size of `storage.assocUnstableMessages`/`assocUnstableUnits` (or an appropriate upper bound) rather than a flat constant, so the static cost model reflects real work.
- Alternatively, replace the linear scan over all unstable units with an indexed lookup keyed by author address / feed name (mirroring the DB-backed path already used for the non-`bAA` case), removing the O(N) dependency on total unstable-unit count entirely.
- Consider bounding the maximum number of times a single trigger evaluation may invoke this scan (already partially achieved via `MAX_OPS`/`MAX_COMPLEXITY`, but only if the per-call cost is corrected as above).

### Proof of Concept
1. Deploy an AA whose formula contains, e.g.:
   `bounce_engine trigger: if (in_data_feed(['SOME_ORACLE'], 'x', '=', 1)) { ... }`
   This is validated cheaply (`complexity += 1` per `formula/validation.js` `validateDataFeed`).
2. Flood the network with many small units to grow `storage.assocUnstableUnits`/`assocUnstableMessages` (any ordinary posted unit, no special privilege needed).
3. Repeatedly send trigger payments to the AA above. Each trigger evaluation invokes `dataFeeds.dataFeedExists(..., bAA=true, ...)`, which iterates the full unstable-unit map in `data_feeds.js:34-43` inside the mutex-serialized validation/AA-execution path (`validation.js:357`, `network.js:1258`), degrading validation throughput for all units on the node while the attacker's per-trigger cost remains minimal under the flat complexity charge.

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

**File:** data_feeds.js (L95-108)
```javascript
		if (bFound)
			return handleResult(true);
	}
	async.eachSeries(
		arrAddresses,
		function(address, cb){
			dataFeedByAddressExists(address, feed_name, relation, value, min_mci, max_mci, cb);
		},
		function(bFound){
			console.log('data feed by '+arrAddresses+' '+feed_name+relation+value+': '+bFound+', df took '+(Date.now()-start_time)+'ms');
			handleResult(!!bFound);
		}
	);
}
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

**File:** aa_validation.js (L567-571)
```javascript
			if (complexity > constants.MAX_COMPLEXITY)
				return cb('complexity exceeded: ' + complexity);
			if (count_ops > constants.MAX_OPS)
				return cb('number of ops exceeded: ' + count_ops);
			cb();
```

**File:** network.js (L1258-1259)
```javascript
				ifOk: async function(objValidationState, validation_unlock){
					clearHost();
```
