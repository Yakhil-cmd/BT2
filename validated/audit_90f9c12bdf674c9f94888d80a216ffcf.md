### Title
Unbounded oracle-address list in AA formula `data_feed`/`in_data_feed` bypasses complexity metering, enabling per-trigger DoS - (File: formula/validation.js)

### Summary
The AA formula engine's `data_feed` and `in_data_feed` operators accept an `oracles` parameter that is a colon-separated string of addresses, which is split and iterated over at evaluation time. Unlike the equivalent `in data feed` operator in address/asset definitions (`definition.js`), which explicitly charges one complexity point per additional oracle address, the formula-level validators (`formula/validation.js`) have this exact accounting **commented out**, so the number of oracle addresses does not count toward `MAX_COMPLEXITY`/`MAX_OPS`. This mirrors the OCL-1 class of bug: an array whose length is not bounded by the anti-spam/gas-accounting mechanism, iterated in a hot path (here, sequential KV-store range-stream reads per address), reachable by any user who triggers the AA.

### Finding Description
In `definition.js` the `in data feed` op explicitly bounds cost: [1](#0-0) 
which does `complexity += arrAddresses.length-1;` — i.e., each oracle address in the list costs one complexity unit, capped globally by `constants.MAX_COMPLEXITY` (100) via the `evaluate()` guard: [2](#0-1) 

The AA-formula equivalents, `validateDataFeed` and `validateDataFeedExists` in `formula/validation.js`, parse the same kind of colon-separated `oracles` string but have the address-count complexity charge explicitly disabled: [3](#0-2) [4](#0-3) 
Both contain the line `//complexity += addresses.length;`, commented out, while everything else in these functions (address-format validation, name/length checks) is enforced. `getAttestationError` for `attestors` shows the same commenting-out pattern is absent for length metering as well.

At execution time, `formula/evaluation.js`'s `data_feed` and `in_data_feed` cases split the `oracles` string on `:` and hand the resulting array directly to `dataFeeds.readDataFeedValue` / `dataFeeds.dataFeedExists`: [5](#0-4) [6](#0-5) 
These functions iterate the oracle-address array with `async.eachSeries`, and for each address open a dedicated KV-store range-read stream (`readDataFeedByAddress` / `dataFeedByAddressExists`): [7](#0-6) [8](#0-7) [9](#0-8) 

Notably, the light-wallet request handler `readDataFeedValueByParams` explicitly caps this same `oracles` array to 10 entries: [10](#0-9) 
confirming that the developers considered the oracle-array length a cost/DoS factor worth bounding — but this bound was not applied (or was deliberately disabled) for the AA-formula code path that every full node must execute during consensus.

Because a formula string can be up to 10000 characters when embedded directly as an address-definition `formula` op (enforced in `definition.js` line 599) or up to the general AA payload/unit size limit (`MAX_UNIT_LENGTH`, ~5MB) when part of an AA definition's `getters`/`bound_state_vars`/message formulas, an attacker who authors an AA can embed a very long `:`-joined list of syntactically valid addresses (44 chars each) as the `oracles` literal in a `data_feed`/`in_data_feed` call. Because the complexity charge for this array is disabled, the AA definition passes `validateFormula`'s `MAX_COMPLEXITY`/`MAX_OPS` checks trivially: [11](#0-10) 

### Impact Explanation
Every full node in the network must independently evaluate an AA's formulas whenever the AA is triggered (i.e., on every unit sent to that AA's address), including during initial validation and again if/when advancing the stability point. If the formula contains a `data_feed`/`in_data_feed` call with thousands of oracle addresses, each trigger forces every validating node to perform thousands of sequential KV-store iterator opens/reads synchronously in `async.eachSeries`. This is a genuine node-wide resource-consumption vector triggered by ordinary, permissionless trigger units — any address can send a payment/trigger to the AA to force its formulas to execute. Because the complexity/ops accounting that is supposed to bound AA execution cost does not count this array's size, the anti-spam mechanism designed specifically to prevent this class of issue is silently bypassed for this one operator family, unlike the parallel `in data feed` address-definition op which is properly bounded. Repeated triggering can materially slow down AA response processing and unit validation on all nodes, degrading network throughput/confirmation. This does not directly cause unauthorized spending or double-spend, but it is a network-wide resource-exhaustion/availability issue reachable by an unprivileged trigger sender.

### Likelihood Explanation
Likelihood is moderate: it requires an AA author to deliberately craft a formula with such an oracle list (a straightforward, non-privileged action — anyone can post an AA definition), after which any unprivileged party (or the AA author) can repeatedly trigger it. No special permissions, timing, or race conditions are needed; only crafting a sufficiently long, syntactically-valid, colon-joined address list.

### Recommendation
Re-enable and enforce complexity accounting for the `oracles` address list in `formula/validation.js`'s `validateDataFeed` and `validateDataFeedExists` (and any other formula op — `attestors` in `getAttestationError` — that parses an unbounded colon-joined address list), mirroring the treatment in `definition.js`'s `in data feed` op (`complexity += arrAddresses.length - 1`). Alternatively/additionally, impose an explicit hard cap on the number of oracle addresses accepted by `data_feed`/`in_data_feed` at validation time (consistent with the 10-oracle cap already enforced in `data_feeds.js`'s `readDataFeedValueByParams`), rather than relying solely on generic complexity accounting.

### Proof of Concept
1. Compose an AA definition whose formula (e.g. in a `getter`, `messages`, or `bound_state_vars` formula) contains: `data_feed[oracles=[A1:A2:A3:...:A5000], feed_name='x']` where `A1..A5000` are 5000 syntactically valid (but arbitrary/never-posted) Obyte addresses joined by `:`. The resulting `oracles` string stays well under the `MAX_UNIT_LENGTH`/10000-char formula-length limits.
2. Submit this AA definition; `aa_validation.js`'s `validateFormula` calls `formula/validation.js`'s `validateDataFeed`, whose complexity charge for the oracle list is commented out (`formula/validation.js:47`), so `complexity` stays at 1 for that op regardless of list length, and the AA passes the `MAX_COMPLEXITY`/`MAX_OPS` checks in `aa_validation.js:567-570`.
3. Trigger the AA with a normal payment. On every validating node, `formula/evaluation.js`'s `data_feed` case (`formula/evaluation.js:602-646`) splits the 5000-address string and calls `dataFeeds.readDataFeedValue`, which does `async.eachSeries` over all 5000 addresses, opening 5000 sequential KV-store range-read streams per trigger (`data_feeds.js:275-285`, `data_feeds.js:331-339`).
4. Repeating step 3 forces this expensive sequential I/O work on every full node for each trigger, disproportionate to the small complexity/ops cost recorded for the AA — the same bug class as OCL-1's unbounded `setPrices` arrays causing excess gas consumption per call.

### Citations

**File:** definition.js (L103-111)
```javascript
	function evaluate(arr, path, bInNegation, cb){
		complexity++;
		count_ops++;
		if (complexity > constants.MAX_COMPLEXITY)
			return cb("complexity exceeded at "+path);
		if (count_ops > constants.MAX_OPS)
			return cb("number of ops exceeded at "+path);
		if (objValidationState.max_complexity && objValidationState.complexity + complexity > objValidationState.max_complexity)
			return cb(`custom complexity limit ${objValidationState.max_complexity} exceeded at ${path}`);
```

**File:** definition.js (L413-418)
```javascript
				if (!isNonemptyArray(arrAddresses))
					return cb("no addresses in "+op);
				for (var i=0; i<arrAddresses.length; i++)
					if (!isValidAddress(arrAddresses[i])) // it is ok if the address was never used yet
						return cb("oracle address not valid");
				complexity += arrAddresses.length-1; // 1 complexity point for each address (1 point was already counted)
```

**File:** formula/validation.js (L42-49)
```javascript
			switch (name) {
				case 'oracles':
					if (value.trim() === '') return {error: 'empty oracle', complexity};
					var addresses = value.split(':');
					if (addresses.length === 0) return {error: 'empty oracle list', complexity};
				//	complexity += addresses.length;
					if (!addresses.every(ValidationUtils.isValidAddress)) return {error: 'oracle address not valid', complexity};
					break;
```

**File:** formula/validation.js (L104-111)
```javascript
		switch (name) {
			case 'oracles':
				if (value.trim() === '') return {error: 'empty oracles', complexity};
				var addresses = value.split(':');
				if (addresses.length === 0) return {error: 'empty oracles list', complexity};
			//	complexity += addresses.length;
				if (!addresses.every(ValidationUtils.isValidAddress)) return {error: 'not valid oracle address', complexity};
				break;
```

**File:** formula/evaluation.js (L600-646)
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
```

**File:** formula/evaluation.js (L701-746)
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
```

**File:** data_feeds.js (L98-107)
```javascript
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
```

**File:** data_feeds.js (L196-202)
```javascript
	var stream = kvstore.createKeyStream(options);
	stream.on('data', handleData)
	.on('end', onEnd)
	.on('error', function(error){
		throw Error('error from data stream: '+error);
	});
}
```

**File:** data_feeds.js (L331-339)
```javascript
	kvstore.createReadStream(options)
	.on('data', handleData)
	.on('end', function(){
		handleResult(objResult.bAbortedBecauseOfSeveral);
	})
	.on('error', function(error){
		throw Error('error from data stream: '+error);
	});
}
```

**File:** data_feeds.js (L342-351)
```javascript
function readDataFeedValueByParams(params, max_mci, unstable_opts, cb) {
	var oracles = params.oracles;
	if (!oracles)
		return cb("no oracles in readDataFeedValueByParams");
	if (!ValidationUtils.isNonemptyArray(oracles))
		return cb("oracles must be non-empty array");
	if (!oracles.every(ValidationUtils.isValidAddress))
		return cb("some oracle addresses are not valid");
	if (oracles.length > 10)
		return cb("too many oracles");
```

**File:** aa_validation.js (L535-572)
```javascript
	function validateFormula(aa_opts, cb) {
		if (typeof aa_opts.formula !== 'string' || !aa_opts.locals)
			throw Error("bad opts in validateFormula: " + JSON.stringify(aa_opts));
		var opts = {
			formula: fixFormula(aa_opts.formula, address),
			complexity: complexity,
			count_ops: count_ops,
			bAA: true,
			bStatementsOnly: aa_opts.bStatementsOnly || false,
			bGetters: aa_opts.bGetters || false,
			bStateVarAssignmentAllowed: aa_opts.bStateVarAssignmentAllowed || false,
			locals: aa_opts.locals,
			readGetterProps: readGetterProps,
			mci: mci,
		};
	//	console.log('--- validateFormula', formula);
		formulaValidator.validate(opts, function (result) {
			if (typeof result.complexity !== 'number' || !isFinite(result.complexity))
				throw Error("bad complexity after " + opts.formula + ": " + result.complexity);
			complexity = result.complexity;
			count_ops = result.count_ops;
			if (result.error) {
				if (result.error_location) {
					validationErrorDetails = {
						formula: opts.formula,
						error_location: result.error_location,
					};
				}
				var errorMessage = "validation of formula " + opts.formula + " failed: " + result.error
				errorMessage += result.errorMessage ? `\nparser error: ${result.errorMessage}` : ''
				return cb(errorMessage);
			}
			if (complexity > constants.MAX_COMPLEXITY)
				return cb('complexity exceeded: ' + complexity);
			if (count_ops > constants.MAX_OPS)
				return cb('number of ops exceeded: ' + count_ops);
			cb();
		});
```
