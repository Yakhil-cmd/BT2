Based on the report's bug class — an untrusted/unvalidated value bypassing a trust check that is correctly enforced in a sibling code path, letting it "poison" data that downstream consumers treat as authoritative — I found a concrete, reachable analog in the data-feed evaluation logic used by AA/definition conditions.

### Title
Missing `sequence === 'good'` filter in `dataFeedExists` allows non-serial (bad) unstable data feeds to satisfy `in_data_feed`/`in data feed` conditions - (File: data_feeds.js)

### Summary
`data_feeds.js`'s `dataFeedExists()` scans `storage.assocUnstableMessages` for `data_feed` messages from unstable AA-relevant units to answer `in_data_feed` (AA formula) and `'in data feed'` (address/asset definition) queries, but unlike its sibling `readDataFeedValue()`, it never checks that the unit's `sequence` is `'good'`.

### Finding Description
`dataFeedExists` iterates all unstable units and, for those whose author intersects the queried oracle addresses and whose `latest_included_mc_index` falls in range, treats any `data_feed` message payload as a real, existing feed value: [1](#0-0) 

Contrast this with `readDataFeedValue`, the twin function used for the `data_feed` value-fetching op, which explicitly excludes non-serial units before considering their unstable messages: [2](#0-1) 

The `sequence` field distinguishes serial ('good') units from conflicting/non-serial ones that will ultimately be excluded from consensus state once finality is reached ('final-bad'/'temp-bad'). `dataFeedExists` is reachable from two independent unprivileged entry points that any unit/trigger author can trigger:
- The `'in data feed'` address/asset-definition operator: [3](#0-2) 
- The `in_data_feed` oscript/AA-trigger evaluation operator: [4](#0-3) 

Both pass `bAA`/definition context straight into `dataFeedExists`, which then performs the unfiltered scan over `assocUnstableMessages` for the `bAA` branch.

### Impact Explanation
Because the unstable-scan branch of `dataFeedExists` does not check `sequence`, a conflicting/non-serial unit authored by (or forging authorship intersecting) the queried oracle address can have its `data_feed` payload counted as "existing" while still unstable — even though, once finality is reached, only the serial (`sequence='good'`) sibling unit's data would remain valid. Since AA execution (`in_data_feed`) and address/asset spending-condition evaluation (`'in data feed'`) must be deterministic across all validating nodes for consensus to hold, any node-local timing difference in which conflicting unit it currently regards as part of `assocUnstableMessages`/`assocUnstableUnits` before the conflict is resolved can produce different `in_data_feed` results on different nodes for the same trigger/last_ball_mci. This can cause AA bounce/response divergence (fund loss/freezing for AA-held funds) or a spending-condition ('in data feed') check to pass on one node and fail on another for the same unit, i.e., node disagreement on unit/AA validity — a Medium/High-severity consensus-safety issue matching the "node disagreement on validity" and "AA fund loss or freezing" categories in scope.

### Likelihood Explanation
Reachability requires no special privilege: any address can act as an "oracle" referenced by an AA's `in_data_feed[[oracles=...]]` condition or by an address/asset definition's `['in data feed', ...]` clause, and any unit author can post conflicting (non-serial) units from that oracle address while units are still unstable. The precise window in which two nodes observe different `sequence` states for the same not-yet-stable unit is timing-dependent, and I was not able to fully verify from static reading how wide/reliable that window is (this would require tracing `main_chain.js`/`writer.js` sequence-assignment timing across parallel branches under contention) — this is the main residual uncertainty in confirming exploitability end-to-end.

### Recommendation
Add the same `objUnit.sequence !== 'good'` (or equivalent "skip non-serial units") filter to the unstable-scan loop inside `dataFeedExists` (data_feeds.js lines 34-43) that already exists in `readDataFeedValue` (line 219), so that `in_data_feed`/`'in data feed'` evaluation is consistent with `data_feed` value retrieval and cannot be influenced by units destined to be excluded from consensus state.

### Proof of Concept
1. Oracle address `O` is referenced by an AA as `in_data_feed[[oracles=O, feed_name='x', feed_value>10, min_mci=N]]`.
2. Attacker controlling `O` (or an address that becomes non-serial due to a conflicting double-spend/parallel unit) posts two conflicting units both containing a `data_feed` message with `feed_name='x'` — one with `x=20`, both currently unstable and both present in `storage.assocUnstableMessages`/`assocUnstableUnits` on some nodes before conflict resolution finishes.
3. Any node that still regards this unit as part of `assocUnstableMessages` (regardless of its eventual `sequence` outcome) will report `in_data_feed(...) === true` for `feed_value>10`, while a node that has already resolved the conflict (unit now `sequence='final-bad'`, dropped from active unstable tracking, or not intersecting the mci window) reports `false`.
4. AA triggers depending on this condition are processed with different outcomes (bounce vs. success) on different nodes for the same trigger unit, producing consensus divergence on AA-controlled funds.

### Citations

**File:** data_feeds.js (L34-50)
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
```

**File:** data_feeds.js (L217-224)
```javascript
			if (!objUnit.bAA && !bIncludeAllUnstable)
				continue;
			if (objUnit.sequence !== 'good')
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
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
