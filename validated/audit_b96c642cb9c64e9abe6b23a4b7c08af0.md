Confirmed: the persisted (stable) data feed writes in `main_chain.js` correctly skip `sequence === 'final-bad'` units, so once a unit is stabilized as bad, its data feed never enters the durable `df\n`/`dfv\n` kvstore records. However, the *unstable* scan path in `dataFeedExists()` in `data_feeds.js` has no equivalent guard.

### Title
`in_data_feed`/AA data-feed-exists check trusts unstable messages from not-yet-resolved (potentially bad-sequence) units - (File: `data_feeds.js`)

### Summary
`dataFeedExists()` in [1](#0-0)  iterates `storage.assocUnstableMessages` for AA evaluation (`bAA===true`) and only filters by `objUnit.bAA`, `latest_included_mc_index` range, and author address intersection. It never checks `objUnit.sequence === 'good'`. This is inconsistent with the sibling function `readDataFeedValue()`, which explicitly requires `objUnit.sequence !== 'good'` to be skipped ( [2](#0-1) ), and with the persistence logic in `main_chain.js` that discards all messages of a `final-bad` unit before they are ever written to the durable data-feed index ( [3](#0-2) ).

### Finding Description
`dataFeedExists()` is invoked from the formula evaluator for the `in_data_feed` oscript operator used inside AA definitions ( [4](#0-3) ) with `bAA=true`. When evaluating whether a data feed with a given name/value exists, it scans every unstable unit currently in `storage.assocUnstableMessages`, including units whose final sequence (`good`/`temp-bad`/`final-bad`) has not yet been determined by DAG conflict resolution, or units already known to be non-serial. Because there is no `objUnit.sequence` check, a data-feed message contained in a unit that is (or will become) non-serial can still cause `bFound = true` and make the `in_data_feed[...]` formula evaluate to `true` for an AA trigger being processed in the same or an adjacent unstable window.

This is the direct analog of the reported bug class: trusting externally supplied "oracle" data without validating that the data source/record is actually valid/final, mirroring `latestAnswer()` returning a value without any freshness/validity check. Here the "freshness/validity" check that's missing is the sequence check that the codebase itself considers necessary (it's present in `readDataFeedValue` and in the stabilization writer, just missing in `dataFeedExists`).

### Impact Explanation
An AA that uses `in_data_feed[[oracles=..., feed_name=..., feed_value=...]]` to gate fund release/transfer decisions can be triggered based on a data-feed post that is not actually valid/serial in the DAG. If the posting unit is later resolved as non-serial (bad), the condition the AA relied on was never really "true" from the perspective of final consensus, yet the AA already acted on it (e.g., released funds, changed state) during the unstable window. This can lead to AA fund loss/misallocation or a state divergence between what nodes see as valid once the conflicting unit's sequence resolves, i.e. a node-disagreement/inconsistent-AA-execution scenario under the DAG's eventual-consistency model.

### Likelihood Explanation
Reachability requires: (1) an oracle address or the poster's own address to be listed as one of the addresses in the AA's `in_data_feed` oracle list (many bounties/tests use `this_address` or the trigger sender's own address as an allowed oracle, per [5](#0-4) ), and (2) the poster/trigger sender being able to post two conflicting (double-spending) units, one of which carries the desired `data_feed` payload, timed to be evaluated by the AA before conflict resolution finality. This is achievable by any ordinary unit poster / AA trigger sender without special privileges, since posting sibling/conflicting units is a normal wallet capability, making likelihood moderate (matches the report's "3/5").

### Recommendation
Add the same sequence check used in `readDataFeedValue()` to `dataFeedExists()`'s unstable-message scanning branch, e.g. skip units where `objUnit.sequence !== 'good'` before considering their `data_feed` messages, so unresolved/non-serial units cannot satisfy `in_data_feed` conditions used by AAs.

### Proof of Concept
1. Deploy an AA whose logic contains:
   `in_data_feed[[oracles="THIS_ADDRESS_OR_ALLOWED_ORACLE", feed_name="flag", feed_value=1]]` gating a payout branch.
2. From the allowed oracle/trigger-sender address, construct two conflicting units `U1` and `U2` that spend the same output (double-spend), where `U2` contains `data_feed {flag: 1}` and is broadcast alongside the AA trigger unit while both are still unstable.
3. Because `dataFeedExists()` (called via `in_data_feed`, `bAA=true`) does not filter by `objUnit.sequence`, the AA trigger processed while `U2` is unstable (and not yet determined non-serial) sees `bFound = true` and executes the payout branch.
4. Later, DAG conflict resolution marks `U2` as `temp-bad`/`final-bad`; `main_chain.js`'s stabilization logic ( [6](#0-5)  ) discards its data feed from the durable index — but the AA already executed its response based on the now-invalid feed.

### Citations

**File:** data_feeds.js (L13-43)
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

**File:** data_feeds.js (L211-224)
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
```

**File:** main_chain.js (L1550-1557)
```javascript
								async function saveUnstablePayloads() {
									let arrUnstableMessages = storage.assocUnstableMessages[unit];
									if (!arrUnstableMessages)
										return cb();
									if (objUnitProps.sequence === 'final-bad'){
										delete storage.assocUnstableMessages[unit];
										return cb();
									}
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

**File:** test/formula.test.js (L848-853)
```javascript
test.cb('formula - datafeed with this_address', t => {
	evalFormula({}, "data_feed[[oracles=\"KRPWY2QQBLWPCFK3DZGDZYALSWCOEDWA:\"||this_address, feed_name=\"test\", ifseveral=\"last\", min_mci = 10]] == 10", objValidationState.arrAugmentedMessages, objValidationState, 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU', res => {
		t.deepEqual(res, true);
		t.end();
	});
});
```
