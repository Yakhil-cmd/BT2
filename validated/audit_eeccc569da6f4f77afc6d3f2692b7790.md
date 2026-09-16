Based on my research, I found a concrete analog to the Hono IP-restriction bug in ocore's data feed comparison logic used by Autonomous Agents.

### Title
Non-canonical numeric data feed value representations bypass `=`/`!=` conditions in AA `in_data_feed`/`data_feed` unstable-lookup path - ([File: data_feeds.js])

### Summary
The Hono bug compares incoming values against static rules using raw string equality without normalizing to a canonical form, letting a non-canonical but semantically-equal value slip past the rule. `ocore`'s `dataFeedExists()` function has the same structural flaw: for the "unstable AA data feed" fast path it compares the AA-supplied `value` against a posted `feed_value` using `value.toString() === feed_value.toString()` instead of canonicalizing both to a numeric form, while the parallel "stable/persisted" lookup path in the very same file does canonicalize numbers via `string_utils.toNumber()` + `string_utils.encodeDoubleInLexicograpicOrder()` before comparing.

### Finding Description
`dataFeedExists()` in [1](#0-0)  resolves `in_data_feed`/`data_feed` oscript conditions for AAs by scanning currently-unstable `data_feed` messages network-wide (any unit whose author is in `arrAddresses`, regardless of whether it belongs to the same trigger/bounce chain): [2](#0-1) 

This equality/inequality test relies purely on JavaScript's default `toString()` serialization of the values, without normalizing numeric representations (e.g., `100`, `"100"`, `"1e2"`, `"100.0"`, `"1.00e2"` are all the numeric value 100 but stringify differently). Contrast this with the canonical, persisted lookup path in the same module, which explicitly parses and canonicalizes numeric strings before comparison/indexing: [3](#0-2) 

and the same canonicalization is applied when data feeds are persisted at stabilization: [4](#0-3) .

Because the "unstable" fast path used only inside AA formula evaluation (`bAA=true`, reached via the `in_data_feed`/`data_feed` oscript ops in [5](#0-4) ) skips this canonicalization, whoever controls the textual form of a posted `data_feed` payload value (the address acting as oracle for that feed) can make numerically-equal values fail an `=` check or numerically-equal values incorrectly satisfy a `!=` check, purely by choosing an alternate but numerically identical serialization (scientific notation, trailing zeros, etc.).

### Impact Explanation
AA authors commonly gate fund release, minting, whitelisting, or abort logic on `in_data_feed`/`data_feed` conditions (`==`/`!=` against oracle-posted values). Because the comparison used while the referenced data-feed message is still unstable does not canonicalize numeric representations the same way the stable/canonical path does, an oracle (which can be any address referenced in the AA's `oracles` parameter, including one influenced by the trigger sender in permissionless/self-referential AA designs) can post a data feed value in a non-canonical numeric form to make a `!=`-based restriction incorrectly evaluate as satisfied (analogous to an IP-deny rule being bypassed), or make an `=`-based authorization check incorrectly fail/succeed relative to the true numeric value. This can lead to unauthorized execution of protected AA branches, incorrect fund transfers, or AA fund loss/freezing depending on how the AA logic is structured around the check.

### Likelihood Explanation
Exploitation only requires posting a `data_feed` message with a value in an alternate numeric textual form (e.g., `"1e2"` instead of `"100"`) from an address that some AA treats as an oracle, and triggering evaluation of that AA's `in_data_feed`/`data_feed` condition while the data-feed unit is still unstable. No special privileges are required beyond being able to post a unit and being a recognized oracle address for the target AA, which is a normal, low-barrier interaction pattern for AAs that use dynamically supplied oracle lists.

### Recommendation
In the `bAA` unstable-message branch of `dataFeedExists()` (and the corresponding "several candidates" branch in `readDataFeedValue()`), canonicalize both `value` and `feed_value` through the same numeric parsing/encoding used by the persisted-lookup path (`string_utils.toNumber` and `encodeDoubleInLexicograpicOrder`, or at minimum `parseFloat`-based numeric comparison when both sides parse as numbers) before performing `=`/`!=`/relational comparisons, so that the unstable fast path and the stable canonical path always agree on numerically equivalent values.

### Proof of Concept
1. Deploy an AA `B` whose oscript uses `in_data_feed[[oracles=$oracle, feed_name='status', feed_value != 'blocked']]` (or a numeric equivalent, e.g. `feed_value != 100`) to gate a sensitive branch (e.g., fund release), where `$oracle` can be influenced by the trigger or is an address the attacker can post from.
2. From the oracle address, post a `data_feed` unit with `status` set to a numeric value in non-canonical form that is numerically equal to the guarded value (e.g., post `100` as `"1e2"`, or `"100.00"`), while unit remains unstable.
3. Trigger AA `B` while the data feed unit is still unstable so that `dataFeedExists()` takes the `bAA` branch in [6](#0-5) .
4. Observe that `value.toString() !== feed_value.toString()` evaluates true (e.g., `"100" !== "1e2"`) even though the values are numerically equal, causing the `!=` condition to be satisfied and the guarded branch to execute despite the oracle having reported the numerically-blocked value.

### Citations

**File:** data_feeds.js (L13-33)
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
```

**File:** data_feeds.js (L51-67)
```javascript
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
```

**File:** data_feeds.js (L119-136)
```javascript
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
```

**File:** main_chain.js (L1596-1613)
```javascript
										var strValue = null;
										var numValue = null;
										if (typeof value === 'string'){
											strValue = value;
											var bLimitedPrecision = (mci < constants.aa2UpgradeMci);
											var float = string_utils.toNumber(value, bLimitedPrecision);
											if (float !== null)
												numValue = string_utils.encodeDoubleInLexicograpicOrder(float);
										}
										else
											numValue = string_utils.encodeDoubleInLexicograpicOrder(value);
										arrAuthorAddresses.forEach(function(address){
											// duplicates will be overwritten, that's ok for data feed search
											if (strValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci, unit);
											if (numValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\nn\n'+numValue+'\n'+strMci, unit);
											// if several values posted on the same mci, the latest one wins
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
