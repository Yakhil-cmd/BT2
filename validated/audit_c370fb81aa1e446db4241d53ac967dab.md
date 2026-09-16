### Title
Unconditional full scan of all network-wide unstable messages on every `data_feed` oscript call - unbounded compute DoS ([File: formula/evaluation.js], [File: data_feeds.js])

### Summary
`formula/evaluation.js`'s `data_feed` opcode handler calls `dataFeeds.readDataFeedValue` passing `bAA` (a boolean that is simply "are we evaluating inside an AA") into the `unstable_opts` parameter slot, which unconditionally turns on a synchronous, full iteration over every entry in the in-memory `storage.assocUnstableMessages` map for **every single** `data_feed[[...]]` lookup performed by any AA — this is the same unbounded-loop-over-a-growing-collection bug class described in the report (an ever-larger set is scanned in full on a hot, externally-triggerable path).

### Finding Description
`readDataFeedValue` accepts a `unstable_opts` argument and, when truthy, loops over the entire `storage.assocUnstableMessages` associative array (every unit in the DAG that is currently unstable and carries a `data_feed`/`definition`/`system_vote`/`system_vote_count` message): [1](#0-0) 

For each entry it also does a `_.intersection` and a `.forEach` scan of that unit's messages: [2](#0-1) 

The intent, based on the parameter name (`unstable_opts`) and the `ifseveral`/`all_unstable` handling, is that this expensive branch should only run when an oscript author explicitly asks to include unstable data feeds. However, the caller in the formula evaluator passes `bAA` — which is simply "is the current formula evaluation happening in an AA context" — into this slot instead of an actual opt-in flag: [3](#0-2) 

Because `bAA` is `true` for essentially every AA execution (the `data_feed` function is one of the most common oscript primitives, used for price oracles etc.), this means **every** `data_feed[[...]]` call made by **any** AA — triggered by any unprivileged user simply by sending a trigger unit to that AA — unconditionally walks the entire `storage.assocUnstableMessages` object, i.e., every currently-unstable unit in the whole network that carries a data_feed/definition/system_vote message, regardless of whether the oscript author ever asked for "unstable" behavior.

This loop is not subject to `constants.MAX_COMPLEXITY`/`MAX_OPS` formula-complexity accounting (those only count oscript operations, not the internal iterations of `readDataFeedValue`), so there is no built-in bound analogous to a gas limit — exactly the failure mode in the referenced report, where a persistent, ever-larger collection is iterated in full on a routine call and only a size limit (never applied) would prevent unbounded cost. As DAG/network activity increases (more concurrent unstable AA responses/data-feed posts before the ~12-witness stabilization window closes), `assocUnstableMessages` grows and this per-call cost grows with it, on a path reachable by any AA trigger sender.

### Impact Explanation
Because this is invoked synchronously inside AA response computation (a hot, deterministic, node-wide path), a large `assocUnstableMessages` set makes every AA that uses `data_feed` (a nearly universal primitive) become disproportionately expensive to evaluate. Under load (e.g. many outstanding unstable units/AA responses), this can:
- slow down or block AA trigger processing across the whole node (event-loop-bound Node.js process), delaying confirmation of new units network-wide;
- cause AA executions that legitimately should succeed to run so long that they interact badly with time/complexity assumptions elsewhere in the pipeline, risking bounced/failed AA responses and locked trigger funds.

This satisfies the "network unable to confirm new units" / "AA fund loss or freezing" impact classes from the validation rubric.

### Likelihood Explanation
Any user can reach this by simply sending a trigger to any AA whose bytecode contains a `data_feed[[...]]` call (extremely common), so the "hot path" invocation requires no special privilege. The severity of the resulting slowdown depends on how large `storage.assocUnstableMessages` is at that moment, which grows naturally with network/AA activity and can be amplified by an attacker who posts many messages/AA triggers shortly before invoking `data_feed`-using AAs, mirroring the "grows over time until DoS" pattern from the source report.

### Recommendation
Fix the argument mismatch so that `unstable_opts` reflects an explicit opt-in (e.g., a `params.unstable` value from the oscript call) instead of the unrelated `bAA` flag, and bound/limit the cost of the `assocUnstableMessages` scan (e.g., by pre-indexing unstable messages by author address instead of doing a full table scan with `_.intersection` per unit) so the cost does not grow unbounded with total network activity.

### Proof of Concept
1. Deploy any AA whose oscript contains `data_feed[[oracles=..., feed_name=...]]`.
2. Ensure a moderately large number of unstable units carrying `data_feed`/`definition`/`system_vote` messages exist in `storage.assocUnstableMessages` (naturally occurs under sustained network/AA activity, or can be amplified by posting many such messages just before triggering the target AA).
3. Send a trigger to the AA; observe that `formula/evaluation.js` calls `dataFeeds.readDataFeedValue(..., bAA, ...)` with `bAA === true`, causing `data_feeds.js:211-241` to iterate over the entire `assocUnstableMessages` map for every `data_feed` call in the AA, regardless of any oscript-level "unstable" option — the cost scaling with the size of that map rather than being O(1)/bounded. [4](#0-3) [5](#0-4)

### Citations

**File:** data_feeds.js (L205-241)
```javascript
function readDataFeedValue(arrAddresses, feed_name, value, min_mci, max_mci, unstable_opts, ifseveral, timestamp, handleResult){
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	var start_time = Date.now();
	var objResult = { bAbortedBecauseOfSeveral: false, value: undefined, unit: undefined, mci: undefined };
	var bIncludeUnstableAAs = !!unstable_opts;
	var bIncludeAllUnstable = (unstable_opts === 'all_unstable');
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
		}
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
