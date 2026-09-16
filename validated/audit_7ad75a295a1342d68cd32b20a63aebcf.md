### Title
`dataFeedExists()` omits the sequence='good' filter that `readDataFeedValue()` enforces, letting `in_data_feed[[...]]` count data feeds from non-serial (temp-bad/final-bad) AA units - ([File: data_feeds.js])

### Summary
`data_feeds.js` exposes two entry points used by the oscript formula evaluator for AAs: `readDataFeedValue()` (backs `data_feed[[...]]`) and `dataFeedExists()` (backs `in_data_feed[[...]]`). Both scan `storage.assocUnstableMessages` to let an AA see data feeds posted by other unstable AA-response units before finality. `readDataFeedValue()` correctly requires `objUnit.sequence !== 'good'` be skipped, but `dataFeedExists()` has no such check, so it will treat data-feed payloads carried by units that are doomed to be `temp-bad`/`final-bad` (i.e. losers of a double-spend/conflict resolution and destined to be voided) as valid evidence for satisfying an `in_data_feed[[...]]` condition.

### Finding Description
In `data_feeds.js`, `readDataFeedValue()` filters candidate units with: [1](#0-0) 
which explicitly excludes any unit whose `sequence` is not `'good'`.

By contrast, `dataFeedExists()` iterates the same `storage.assocUnstableMessages` map but never checks `sequence`: [2](#0-1) 

`sequence` is the field that marks a unit as `good`, `temp-bad`, or `final-bad` depending on whether it conflicts with another unit spending the same output(s); `temp-bad`/`final-bad` units are explicitly treated by the rest of the codebase as "non-existent competitors" that will ultimately be voided: [3](#0-2) 

`dataFeedExists()` is reached from the AA oscript evaluator for the `in_data_feed[[...]]` expression with `bAA` set to true (enabling the unstable-message scan): [4](#0-3) 

Because the `sequence` check is missing, an `in_data_feed[[...]]` condition inside an AA can be satisfied by a data-feed message carried in a unit that is `temp-bad` or `final-bad` at evaluation time — i.e., a unit that has lost (or will lose) a conflict for the same spent output and will never become part of the canonical, "good" history. `data_feed[[...]]` on the very same payload would correctly return "not found" for that value, creating an inconsistency between the two related oscript primitives operating on the same underlying data.

### Impact Explanation
An AA author whose logic branches on `in_data_feed[[oracles=..., feed_name=..., feed_value...]]` (e.g., "if the given oracle ever posted price X, release funds / mint an asset / advance state") can have that branch satisfied by a value that is not really canonical — it comes from a unit that is going to be voided as non-serial. Since AA logic commonly gates fund releases, mints, or irreversible state transitions on such feed checks, this can lead to AA fund loss/incorrect fund release based on data that the protocol itself considers invalid, contrary to the intended semantics of "look at the actual state of the DAG." This falls under the accepted impact category of AA fund loss/freezing caused by acting on data the protocol has already decided to treat as excluded/invalid.

### Likelihood Explanation
The condition requires the AA-side `in_data_feed[[...]]` primitive (only reachable when `bAA` is true, i.e., another AA-response unit is the data feed source) to be exercised while a relevant source unit is unstable and non-`good` sequence — a state that regularly arises naturally whenever conflicting/double-spending units are broadcast for the same output, which any unprivileged unit poster (including an AA author whose AA authored the feed-carrying response) can trigger by crafting conflicting spends. No special privilege beyond posting units/triggers is required, so the likelihood is realistic for any DAG built around chained AAs consuming each other's data feeds.

### Recommendation
Add the same `if (objUnit.sequence !== 'good') continue;` guard to the unstable-scan loop in `dataFeedExists()` in `data_feeds.js` (mirroring `readDataFeedValue()`), so that `in_data_feed[[...]]` and `data_feed[[...]]` are consistent and both only consider units whose sequence is `'good'`.

### Proof of Concept
1. Define AA-B with a state variable read via a chained AA (AA-A) that posts a `data_feed` message in its response unit (`objUnit.bAA === true`).
2. Arrange for two response units of AA-A to be created such that they conflict over the same spent output, so that when validation runs, one gets `sequence = 'good'` and the other gets `temp-bad`/`final-bad` (see `validation.js:1243-1344`, `checkSerialAddressUse`).
3. Have the `temp-bad` unit's `data_feed` payload contain the specific `feed_name`/value that the target AA's `if` clause checks via `in_data_feed[[oracles=<AA-A address>, feed_name='X', feed_value=<target>]]` (`formula/evaluation.js:701-745`).
4. Trigger AA-B while both units are unstable. Because `dataFeedExists()` (`data_feeds.js:13-97`) does not check `sequence`, the loop over `storage.assocUnstableMessages` will find the payload in the `temp-bad`/`final-bad` unit and set `bFound = true`, causing `in_data_feed[[...]]` to evaluate `true`.
5. Compare with an equivalent `data_feed[[...]]` lookup for the same value via `readDataFeedValue()` (`data_feeds.js:205-241`), which correctly skips the non-`good` unit and would not find the value — demonstrating the inconsistency and that an AA relying on `in_data_feed` can be misled into acting on data that the protocol will not ultimately recognize as canonical.

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

**File:** data_feeds.js (L213-224)
```javascript
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
```

**File:** main_chain.js (L1327-1336)
```javascript
						if (row.sequence === 'final-bad'){
							arrFinalBadUnits.push(row.unit);
							return row.content_hash ? cb() : setContentHash(row.unit, cb);
						}
						// temp-bad
						if (row.content_hash)
							throw Error("temp-bad and with content_hash?");
						findStableConflictingUnits(row, function(arrConflictingUnits){
							var sequence = (arrConflictingUnits.length > 0) ? 'final-bad' : 'good';
							console.log("unit "+row.unit+" has competitors "+arrConflictingUnits+", it becomes "+sequence);
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
