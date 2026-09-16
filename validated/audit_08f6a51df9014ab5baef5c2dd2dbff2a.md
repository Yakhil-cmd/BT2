### Title
Crash via double stream-callback invocation in data feed range scan when a matching record is found — ([File: data_feeds.js])

### Summary
`dataFeedByAddressExists()` in `data_feeds.js` opens a `kvstore` key-stream to search for a matching data-feed record and installs both a `'data'` handler and an `'end'` handler that both can call the terminal `onEnd()` function. When a match is found for relations other than `=`, the `'data'` handler calls `stream.destroy()` and then immediately calls `onEnd()` itself, while the stream's `'end'` event handler is still registered and can also fire and call `onEnd()` a second time, which is guarded only by a `throw Error("second call of onEnd")`. [1](#0-0) 

### Finding Description
Inside `dataFeedByAddressExists`, for relational (non-`=`) comparisons, `handleData` calls `stream.destroy()` and then synchronously invokes `onEnd()`: [2](#0-1) 

`onEnd` is a one-shot completion function guarded by a `bOnEndCalled` flag that throws an unhandled `Error("second call of onEnd")` if invoked twice: [3](#0-2) 

The `'end'` event handler is registered on the same stream and also calls `onEnd`: [4](#0-3) 

Whether `stream.destroy()` reliably suppresses a subsequently-queued `'end'` event depends on the underlying `kvstore` iterator implementation; if the `'end'` event is still delivered asynchronously after `destroy()` (e.g., because the iterator had already buffered/queued its final read before `destroy()` took effect), `onEnd()` will be invoked twice, hitting the explicit `throw`. Because this code executes synchronously inside unit/authentifier validation (not inside a try/catch that safely converts exceptions to validation failures at this depth), an uncaught exception here can crash the node process.

This function is reachable from two unprivileged, attacker-controlled entry points:
1. `in data feed` inside an **address definition's authentifier evaluation** (`definition.js`), evaluated whenever any unit signed by that address (smart address) is validated by any node. [5](#0-4) 
2. `in_data_feed` / `data_feed` formula operators evaluated during **AA trigger execution** (`formula/evaluation.js`), reachable by anyone sending a trigger to an AA that uses such a condition. [6](#0-5) 

Both paths funnel into `dataFeeds.dataFeedExists` → `dataFeedByAddressExists`, which any unprivileged unit author can trigger by simply posting a unit that satisfies a pre-existing data-feed condition with a relational operator (`<`, `<=`, `>`, `>=`).

### Impact Explanation
An unhandled exception thrown inside unit/AA-trigger validation crashes the full node process handling it. Because validation of an authentifier condition or AA-trigger formula happens on every node independently as part of consensus-relevant processing (unit validation / AA trigger execution during main-chain stabilization), an attacker able to reliably trigger the double-`onEnd()` race could crash multiple nodes processing the same unit/trigger, halting confirmation of new units on affected nodes — matching the "network unable to confirm new units" impact bar.

### Likelihood Explanation
Triggering the race requires the underlying `kvstore` stream implementation to still deliver an `'end'` event after `stream.destroy()` was called — a timing/implementation detail that is not guaranteed to be deterministic across all storage backends/versions ocore supports (sqlite/rocksdb key-stream shims). This makes exploitability implementation- and timing-dependent rather than trivially deterministic from message content alone, so likelihood is lower than the AHCI NCQ analog, though the attacker fully controls when to post the qualifying data-feed condition and trigger.

### Recommendation
Remove the manual `onEnd()` call from `handleData` (or unregister the `'data'`/`'end'` listeners before destroying the stream), and make `onEnd` idempotent instead of throwing, e.g.:
```js
function onEnd(){
    if (bOnEndCalled)
        return; // already handled via destroy() path
    bOnEndCalled = true;
    ...
}
```
Additionally wrap the data-feed stream handling in try/catch at the call sites in `definition.js` and `formula/evaluation.js` so a stray exception here degrades to a validation error rather than crashing the process.

### Proof of Concept
1. Post a unit `U1` from address `A` with a `data_feed` message setting `feed_name = 5`.
2. Define a smart address (or AA) whose authentifier/formula uses `in data feed`/`in_data_feed` with a relational operator (e.g., `feed_value: '>3'`) against oracle `A` and `feed_name`.
3. Post a second unit `U2` referencing that authentifier condition (or send an AA trigger evaluating that formula) so that `dataFeedByAddressExists` is invoked with a relation that hits the `handleData` match branch calling `stream.destroy()`.
4. Under kvstore backend timing where the iterator still emits a queued `'end'` event after `destroy()`, `onEnd()` fires twice, throwing `Error("second call of onEnd")` uncaught, crashing the node process validating `U2`/the trigger.

### Citations

**File:** data_feeds.js (L165-202)
```javascript
	var count = 0;
	var count_before_found = 0;
	var handleData;
	if (relation === '=')
		handleData = function(data){
			count++;
			count_before_found++;
			bFound = true;
		};
	else
		handleData = function(data){
			count++;
			if (bFound)
				return;
			count_before_found++;
			var mci = string_utils.getMciFromDataFeedKey(data);
			if (mci >= min_mci && mci <= max_mci){
				bFound = true;
				console.log('destroying stream prematurely');
				stream.destroy();
				onEnd();
			}
		};
	var bOnEndCalled = false;
	function onEnd(){
		if (bOnEndCalled)
			throw Error("second call of onEnd");
		bOnEndCalled = true;
		console.log('data feed by '+address+' '+feed_name+relation+value+': '+bFound+', '+count_before_found+' / '+count+' records inspected');
		handleResult(bFound);
	}
	var stream = kvstore.createKeyStream(options);
	stream.on('data', handleData)
	.on('end', onEnd)
	.on('error', function(error){
		throw Error('error from data stream: '+error);
	});
}
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
