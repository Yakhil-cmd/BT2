## Title
Uncaught exception via ambiguous unstable AA data feed candidates in `data_feeds.js` `readDataFeedValue` - crashes node when evaluating an AA data_feed selector during trigger processing - ([File: data_feeds.js])

### Summary
`readDataFeedValue()` in `data_feeds.js` collects candidate unstable data-feed messages from other unstable AA-response units when an AA formula reads `data_feed[[...]]` without `ifseveral='abort'`. When more than one candidate is found, the code tries to order them deterministically by `latest_included_mc_index` then by `level`. If both are equal and the caller is not in `all_unstable` mode (i.e., normal AA execution, `bIncludeAllUnstable === false`), the comparator falls through to `throw Error("can't sort candidates "+a+" and "+b)` [1](#0-0)  instead of returning a controlled error to the caller. This is analogous to CVE-2021-34555's root cause: code assumes a field will resolve to a single, cleanly-ordered value and dereferences/operates on that assumption without a safe fallback, crashing the process when multiple values collide.

### Finding Description
`readDataFeedValue` is invoked from the oscript formula evaluator's `data_feed` operator during AA trigger/response processing [2](#0-1) . This aggregates data-feed messages from unstable AA-response units matching the requested `feed_name`/`oracles` into `arrCandidates` [3](#0-2) . When there are 2+ matching candidates and `ifseveral` is not `'abort'`, the array is sorted to deterministically pick the "last" (most recent) candidate [4](#0-3) .

The comparator only has deterministic tie-breaking when `bIncludeAllUnstable` is true (i.e., `unstable_opts === 'all_unstable'`); in that branch ties are allowed to sort arbitrarily. But for ordinary AA getter/state evaluation, `unstable_opts` is passed as `bAA` (a boolean truthy value, not the string `'all_unstable'`) [5](#0-4) , so `bIncludeAllUnstable` is `false`. In that case, if two candidate messages from different unstable AA-response units have the exact same `latest_included_mc_index` and the exact same `level`, the comparator throws an uncaught `Error`, since there is no synchronous `try/catch` around this call inside `evaluate()`/`getDataFeed()` [2](#0-1) .

`latest_included_mc_index` and `level` are unit-graph properties that a sufficiently-crafted set of parallel-sibling units (e.g., two units both authored by different AA addresses that are both being watched as "oracles" in the same `data_feed[[...]]` call, both included in the DAG at the same point) could realistically collide on, especially since `level` reflects topological depth which can be shared by many sibling units at the same point of the DAG. Any unprivileged unit poster/AA trigger sender who can arrange for two matching data-feed-posting AA-response units to appear unstable with identical `latest_included_mc_index`/`level` at the moment some AA's formula evaluates `data_feed[[...]]` (without `ifseveral: 'abort'`) can trigger this uncaught `throw`.

Because this throw occurs synchronously inside a callback chain invoked from AA trigger handling (`aa_composer`/`aa_validation`/`formula/evaluation.js`), and there is no enclosing `try/catch` at this call site to convert it into a formula-level error (unlike other error paths in the same function which properly call `setFatalError(...)` and `cb(...)`), the exception propagates up as an unhandled exception in the Node.js process, crashing the daemon.

### Impact Explanation
A crash triggered during AA trigger/response processing halts the affected node's unit processing. If triggerable deterministically by any unprivileged AA trigger sender across many/most nodes running affected AAs, this can cause: nodes disagreeing on validity/stability of units being processed at the time of the crash, or a broader inability of the network to confirm new units if this is common in widely-used AA getters/formulas (denial of service on validation availability), matching the accepted-impact class of "node disagreement on validity or stability" / "a network unable to confirm new units."

### Likelihood Explanation
This requires: (1) an AA whose oscript/ojson definition calls `data_feed[[...]]` (or `in_data_feed`) without `ifseveral: 'abort'` reading from oracle addresses that are also AA addresses producing data feed messages while unstable; and (2) two matching unstable candidate messages colliding exactly on `latest_included_mc_index` and `level`. This is a narrower and more probabilistic trigger condition than the original CVE (which required only a single crafted header), but it is fully controllable by an attacker who can shape the DAG (post units at will) and coordinate two AA responses to land at the same MCI/level relative to the reading AA's evaluation point. It does not require a malicious peer/hub/node — only ordinary unit/trigger posting capability.

### Recommendation
Replace the `throw Error(...)` fallback in the comparator at `data_feeds.js` with a deterministic, side-effect-free tie-breaker (e.g., compare by `unit` hash string, as `getWinnerInfo` in `headers_commission.js` does via `sha1` hashing) so that ties never throw, and propagate any unavoidable ambiguity to the caller as a normal formula evaluation error (`cb("several values found")` / `objResult.bAbortedBecauseOfSeveral = true`) rather than an unhandled exception.

### Proof of Concept
1. Deploy two AA addresses `A1` and `A2` that each post a `data_feed` message with the same `feed_name` under conditions that let both be included as unstable AA-response units with identical `latest_included_mc_index` and identical `level` (e.g., trigger both from sibling units posted in the same round so their AA responses land at the same DAG depth/mci).
2. Deploy/trigger a third AA `B` whose formula evaluates `data_feed[[oracles="A1:A2", feed_name="x"]]` (default `ifseveral` != `'abort'`) while `A1`'s and `A2`'s responses are still unstable.
3. When `B`'s trigger is processed, `readDataFeedValue` collects both unstable candidates, finds `arrCandidates.length > 1`, and since `latest_included_mc_index` and `level` tie and `bIncludeAllUnstable` is false, the sort comparator throws an uncaught `Error("can't sort candidates ...")`, crashing the evaluating node's process during AA trigger handling.

### Citations

**File:** data_feeds.js (L211-241)
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
		}
```

**File:** data_feeds.js (L250-268)
```javascript
		else if (arrCandidates.length > 1) {
			if (ifseveral === 'abort') {
				objResult.bAbortedBecauseOfSeveral = true;
				return handleResult(objResult);
			}
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
			var feed = arrCandidates[arrCandidates.length - 1];
```

**File:** formula/evaluation.js (L600-663)
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
					//	console.log(arrAddresses, feed_name, value, min_mci, ifseveral);
					//	console.log('---- objResult', objResult);
						if (objResult.bAbortedBecauseOfSeveral)
							return cb("several values found");
						if (objResult.value !== undefined){
							if (what === 'unit')
								return cb(null, objResult.unit);
							if (type === 'string')
								return cb(null, objResult.value.toString());
							return cb(null, (typeof objResult.value === 'string') ? objResult.value : createDecimal(objResult.value));
						}
						if (params.ifnone && params.ifnone.value !== 'abort'){
						//	console.log('===== ifnone=', params.ifnone.value, typeof params.ifnone.value);
							return cb(null, params.ifnone.value); // the type of ifnone (string, decimal, boolean) is preserved
						}
						cb("data feed " + feed_name + " not found");
					});
```
