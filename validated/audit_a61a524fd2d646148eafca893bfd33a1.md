### Title
Uncaught exception in `readDataFeedValue` crashes node when two unstable AA data-feed messages tie on `latest_included_mc_index`/`level` - (File: `data_feeds.js`)

### Summary
When an AA formula reads a `data_feed` value with `unstable_opts` set to include unstable AA messages (the normal in-AA-execution mode, `bIncludeAllUnstable === false`), candidate data-feed values from still-unstable AA response units are sorted by `latest_included_mc_index` and DAG `level`. If two matching candidates are fully tied on both fields, the sort comparator executes `throw Error("can't sort candidates ...")` synchronously instead of returning a deterministic result, propagating an uncaught exception out of the read path used during AA trigger evaluation.

### Finding Description
`readDataFeedValue()` builds `arrCandidates` from `storage.assocUnstableMessages` for any unstable AA response unit authored by one of the requested oracle addresses whose `data_feed` message matches the requested `feed_name`/`feed_value`: [1](#0-0) 

When more than one candidate is found and `ifseveral` is not `'abort'`, the candidates are sorted by `latest_included_mc_index`, then by `level`; if both are equal and `bIncludeAllUnstable` is false (which is exactly the case for AA-context reads, since `unstable_opts` is passed as the boolean `bAA` rather than the string `'all_unstable'`), the comparator throws instead of resolving the tie: [2](#0-1) 

This function is invoked directly, synchronously, from the `data_feed` opcode evaluation used inside AA `state`/`if`/`init` formulas: [3](#0-2) 

Two independent, unstable AA response units authored by the same oracle address(es) (or two addresses both included in the `oracles` parameter) can legitimately end up with identical `latest_included_mc_index` and identical DAG `level` — e.g. two response units produced from sibling trigger units that share the same parent set, since `level` is derived purely from parent levels. Any unprivileged AA trigger sender can arrange this by posting two trigger units with the same parents that both cause the target AA (or two AAs both matched by the `oracles` filter) to post different values for the same `feed_name` in their state-update messages. A third AA (or the same AA on a later message) then reading `data_feed[[oracles=...]]` without a `feed_value` filter, while both responses are still unstable, will trigger the tie and the uncaught `throw`.

### Impact Explanation
The `throw` is not part of an intentional AA-bounce error path (those use `cb2(...)`/`setFatalError` to reject the formula gracefully) — it is a raw JavaScript exception thrown synchronously inside `Array.prototype.sort`'s comparator. Because the call chain from `handleTrigger` → `formulaParser.evaluate` → `evaluate()` (`data_feed` case) → `dataFeeds.readDataFeedValue` has no surrounding try/catch at this point, the exception propagates as an uncaught exception in the AA-processing code path. Since all full/witness nodes deterministically process the same units in the same DAG state, every node evaluating this trigger hits the same tie and crashes identically, which halts further unit processing (AA responses, and potentially the whole node process) — a network-wide inability to confirm/process new units until the offending state is somehow bypassed.

### Likelihood Explanation
Reaching the exact tie condition (`latest_included_mc_index` equal and `level` equal for two data-feed-matching candidates from unstable AA response units) requires deliberate but straightforward crafting: an attacker posts two trigger units on the same parents so that resulting AA response units share the same level, targeting an AA (or set of AAs listed as `oracles`) that emits a `data_feed` state message with differing values, and arranges for a consumer AA to read that feed with `ifseveral` other than `'abort'` while both responses are unstable. This is achievable by any unprivileged unit/trigger poster without needing operator, hub, or peer privileges, making likelihood moderate-to-high given only DAG-shape control is needed.

### Recommendation
Do not `throw` on unresolved sort ties in the AA-read path. Instead, define a deterministic, total tie-break (e.g., compare `unit` hashes lexicographically) for all cases, not just when `bIncludeAllUnstable` is true, and return that result instead of throwing. Additionally, wrap the `data_feed`/`in_data_feed` evaluation calls into `dataFeeds` functions with a try/catch that converts any unexpected internal error into a formula-level fatal error (`setFatalError`) rather than allowing a raw exception to escape into `handleTrigger`.

### Proof of Concept
1. Post trigger unit `T1` and trigger unit `T2` both parented on the same parent set `P`, each addressed to trigger AA `X` (or to two different AAs `X1`/`X2`, both to be listed together in `oracles`).
2. AA `X`'s (or `X1`, `X2`'s) state code emits `data_feed[[<feed_name>=<value>]]` where the posted value differs between the two responses (e.g., driven by `trigger.data` differences).
3. Because `T1` and `T2` share parents `P`, their AA response units `R1`/`R2` end up at the same DAG `level`, and, if included in the same MC round, the same `latest_included_mc_index`.
4. Before `R1`/`R2` stabilize, post a further trigger to AA `Y` whose formula executes `data_feed[[oracles='<X or X1:X2>', feed_name='<feed_name>', ifseveral='last']]` (no `feed_value` filter, so both `R1` and `R2` qualify as candidates).
5. `readDataFeedValue` collects two candidates with identical `latest_included_mc_index` and `level`; the sort comparator hits the `bIncludeAllUnstable` false branch and executes `throw Error("can't sort candidates ...")`, uncaught, crashing AA trigger processing on every full node that evaluates `Y`'s trigger.

### Citations

**File:** data_feeds.js (L211-240)
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
```

**File:** data_feeds.js (L255-267)
```javascript
			arrCandidates.sort(function (a, b) {
				if (a.latest_included_mc_index < b.latest_included_mc_index)
					return -1;
				if (a.latest_included_mc_index > b.latest_included_mc_index)
					return 1;
				if (a.level < b.level)
					return -1;
				if (a.level > b.level)
					return 1;
				if (bIncludeAllUnstable) // still ambiguous, sort randomly (it's OK outside AAs)
					return 1;
				throw Error("can't sort candidates "+a+" and "+b);
			});
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
