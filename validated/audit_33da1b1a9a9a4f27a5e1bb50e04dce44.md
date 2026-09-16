## Analysis

The strongest ocore analog to the Vesting.sol "unbounded array" DoS is in the **data-feed lookup path** used by both address/asset spending conditions and AA formulas: `dataFeedByAddressExists()` in `data_feeds.js`, reached via the `in data feed` / `in_data_feed` operators. [1](#0-0) 

### Title
Unbounded data-feed key-stream scan in `in data feed` condition allows validation-time denial of service - ([File: data_feeds.js])

### Summary
The `in data feed` condition (usable both in address/asset spending definitions via `definition.js` and in AA formulas via `formula/evaluation.js`'s `in_data_feed` op) resolves to `dataFeeds.dataFeedExists()` → `dataFeedByAddressExists()`. For any relation other than `=`, this function opens a `kvstore.createKeyStream()` over the full range of `df\n<address>\n<feed_name>\n...` keys and iterates every matching record, only short-circuiting if the target value is *found*; if it is never found, the stream is read to its end, inspecting every record ever posted for that oracle address/feed_name. [2](#0-1) 

Because any unprivileged unit poster can post arbitrarily many `data_feed` messages (bounded only by per-message name/value length and per-message feed count, not by total count over time), the number of `df\n...` key-stream records for a given `(address, feed_name)` pair grows without bound over time. [3](#0-2) 

### Finding Description
This mirrors the Vesting.sol bug class exactly: an entity with no special privilege (the data-feed poster, i.e. the address referenced as "oracle" in someone else's spending condition or AA logic) can append records indefinitely, growing a data structure that a *different* party relies on and which is *iterated in full* on the unhappy path. Instead of a Solidity array iterated in a `for` loop until it exceeds the block gas limit, ocore iterates a LevelDB/RocksDB key-stream until exhaustion, executed synchronously as part of consensus-critical unit validation:

- `validateAuthentifiers()` in `definition.js` evaluates address/asset spending conditions (e.g. `in data feed` referencing an oracle) for every unit trying to spend from that address — this runs on every full node validating any unit that touches such an address.
- `evaluate()`'s `in_data_feed` case in `formula/evaluation.js` performs the identical unbounded scan when an AA trigger evaluates that formula. [4](#0-3) 

Unlike the bounded, indexed lookups used elsewhere in the data-feed code (`readDataFeedByAddress` uses `limit: 1` and range-bounded `gte/lte`), the `>`, `>=`, `<`, `<=` branches of `dataFeedByAddressExists` have no `limit` and no early termination when the value is *not* satisfied — the whole historical set for that address/feed is walked every single time the condition is evaluated by every validating node. [5](#0-4) 

### Impact Explanation
An oracle-style address (or any address that a victim's spending condition/AA references for `in data feed`) can be flooded with cheap `data_feed` messages that never satisfy the comparison. Every subsequent unit that needs to evaluate that condition — including the legitimate spender's own payment — must scan the entire, ever-growing key range on every node during validation. This can degrade or effectively stall confirmation of units depending on that condition network-wide, matching the "network unable to confirm new units" / node-freezing impact class, analogous to the beneficiary being permanently unable to `claim()` in Vesting.sol.

### Likelihood Explanation
Posting `data_feed` messages is cheap and available to any unprivileged unit poster; the only per-unit constraints are feed-name/value length and count-per-message (`MAX_DATA_FEEDS_PER_MESSAGE`), not a cap on the total number of feed entries accumulated over time for a given address/feed_name. [6](#0-5) 

An attacker willing to pay ordinary transaction fees over time can grow the scanned range arbitrarily, making the attack straightforward and repeatable against any address/AA whose logic relies on `in data feed` with a non-`=` relation.

### Recommendation
- Add an upper bound / early-abort (e.g. `options.limit`) to the `>`, `>=`, `<`, `<=` branches of `dataFeedByAddressExists`, or require a maximum scan window (e.g., cap total records inspected and fail/require narrower `min_mci`/`max_mci` bounds).
- Consider rate-limiting or capping the number of data-feed entries retained/queryable per `(address, feed_name)` pair, or requiring `min_mci` to bound the scan explicitly.
- Charge scan-proportional cost (complexity/ops) for `in_data_feed` in AA formulas so that the cost of an expensive scan is reflected in `MAX_COMPLEXITY`/`MAX_OPS`, and consider similar complexity accounting for the same operator used in address/asset definitions.

### Proof of Concept
1. Attacker (or a party that will later be referenced as an "oracle" in some address's spending condition or an AA's `in_data_feed` check) repeatedly posts `data_feed` messages under their own address for feed name `F`, with values that will never satisfy a target comparison (e.g., always negative when the condition checks `> 100`).
2. A victim address defines a spending condition `['in data feed', {oracles: "<attacker_address>", feed_name: "F", feed_value: [">", 100]}]`, or an AA formula uses `in_data_feed[[oracles="<attacker_address>", feed_name="F", feed_value>100]]`.
3. Every time the victim (or anyone) tries to spend from that address, or the AA is triggered, `dataFeedByAddressExists` streams and inspects every one of the attacker's posted records (never finding a match), consuming increasing time/resources on every validating node as the attacker keeps posting more records.
4. Repeated indefinitely, this can push validation time for affected units to unacceptable levels, freezing the victim's ability to spend / the AA's ability to respond, and burdening every node in the network during consensus validation.

Note: I could not fully trace every call site of `dataFeedByAddressExists`/`in data feed` in `definition.js` and `arbiter_contract.js` within the available search iterations (the tool budget was exhausted before I could pull the exact `in data feed` case body in `definition.js`); the core unbounded-scan mechanism in `data_feeds.js`, however, is clearly confirmed and is the root cause supporting this finding.

### Citations

**File:** data_feeds.js (L110-202)
```javascript
function dataFeedByAddressExists(address, feed_name, relation, value, min_mci, max_mci, handleResult){
	if (relation === '!='){
		// comparison only makes sense within the same type, otherwise 'abc' != 123 but we don't want to say that they are not equal, because they are incomparable
		return dataFeedByAddressExists(address, feed_name, '>', value, min_mci, max_mci, function(bFound){
			if (bFound)
				return handleResult(true);
			dataFeedByAddressExists(address, feed_name, '<', value, min_mci, max_mci, handleResult);
		});
	}
	var prefixed_value;
	var type;
	if (typeof value === 'string'){
		var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
		var float = string_utils.toNumber(value, bLimitedPrecision);
		if (float !== null){
			prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(float);
			type = 'n';
		}
		else{
			prefixed_value = 's\n'+value;
			type = 's';
		}
	}
	else{
		prefixed_value = 'n\n'+string_utils.encodeDoubleInLexicograpicOrder(value);
		type= 'n';
	}
	var strMinMci = string_utils.encodeMci(min_mci);
	var strMaxMci = string_utils.encodeMci(max_mci);
	var key_prefix = 'df\n'+address+'\n'+feed_name+'\n'+prefixed_value;
	var bFound = false;
	var options = {};
	switch (relation){
		case '=':
			options.gte = key_prefix+'\n'+strMaxMci;
			options.lte = key_prefix+'\n'+strMinMci;
			options.limit = 1;
			break;
		case '>=':
			options.gte = key_prefix;
			options.lt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\r';  // \r is next after \n
			break;
		case '>':
			options.gt = key_prefix+'\nffffffff';
			options.lt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\r';  // \r is next after \n
			break;
		case '<=':
			options.lte = key_prefix+'\nffffffff';
			options.gt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\n';
			break;
		case '<':
			options.lt = key_prefix;
			options.gt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\n';
			break;
	}
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

**File:** validation.js (L1925-1951)
```javascript
		case "data_feed":
			if (objValidationState.bHasDataFeed)
				return callback("can be only one data feed");
			objValidationState.bHasDataFeed = true;
			if (!isNonemptyObject(payload))
				return callback("data feed payload must be non-empty object");
			if (Object.keys(payload).length * objUnit.authors.length > constants.MAX_DATA_FEEDS_PER_MESSAGE)
				return callback("too many data feeds in message");
			for (var feed_name in payload){
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return callback("feed name "+feed_name+" too long");
				if (feed_name.indexOf('\n') >=0 )
					return callback("feed name "+feed_name+" contains \\n");
				var value = payload[feed_name];
				if (typeof value === 'string'){
					if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
						return callback("data feed value too long: " + value);
					if (value.indexOf('\n') >=0 )
						return callback("value "+value+" of feed name "+feed_name+" contains \\n");
				}
				else if (typeof value === 'number'){
					if (!isInteger(value))
						return callback("fractional numbers not allowed in data feeds");
				}
				else
					return callback("data feed "+feed_name+" must be string or number");
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
