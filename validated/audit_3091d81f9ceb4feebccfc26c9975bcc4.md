### Title
Unhandled exception crash in AA `data_feed` oracle resolution via unsortable candidate ties - ([File: data_feeds.js])

### Summary
The CVE describes a segmentation fault in an LLVM sort routine (`matchAndRewriteSortOp`) triggered by malformed input that the comparator/sort logic did not defensively validate. The analogous bug class in `ocore` is a comparator function passed to `Array.prototype.sort()` that `throw`s an `Error` instead of returning a total order when it cannot resolve a tie between candidate values, reachable from attacker-controlled AA state (unstable data-feed messages from other AAs) during formula evaluation of the `data_feed()` oscript function.

### Finding Description
`readDataFeedValue()` in [1](#0-0)  builds `arrCandidates` from all currently-unstable messages of app `data_feed` authored by oracle addresses referenced in the AA formula, when `unstable_opts` is truthy (i.e. `bIncludeUnstableAAs`). When more than one qualifying candidate exists and `ifseveral` is not `'abort'`, the candidates are sorted: [2](#0-1) 

The comparator orders by `latest_included_mc_index`, then `level`, and only falls back to `return 1` (accepting ambiguity) when `bIncludeAllUnstable` is true. Otherwise it executes `throw Error("can't sort candidates ...")` inside the comparator callback that `Array.prototype.sort` invokes.

The `data_feed` oscript function in AA formula evaluation calls this exact path with `bAA` (a boolean `true`, not the string `'all_unstable'`) as the `unstable_opts` argument: [3](#0-2) 

Because `bAA !== 'all_unstable'`, `bIncludeAllUnstable` is `false` in this call path, so the `throw` branch is live whenever an AA's `data_feed()` call resolves two or more unstable oracle-authored data-feed messages that happen to share the identical `latest_included_mc_index` and `level`. Two units can legitimately share the same `level` and `latest_included_mc_index` when they are parallel/sibling units built on the same parent set (e.g., two AA response units triggered concurrently in the same DAG round), which is a state fully reachable by an unprivileged party who posts a trigger causing two named oracle AAs to emit `data_feed` messages in the same unstable window.

This throw occurs synchronously inside the native `Array.prototype.sort` call stack, inside AA trigger/response processing, which is core consensus-path code executed by every full node when handling AA responses and units. An uncaught exception thrown from deep inside this call chain is analogous to the LLVM segfault: unvalidated/unexpected input state (an unresolvable tie) crashes the routine instead of being handled gracefully.

### Impact Explanation
If this `throw` is not caught by any enclosing try/catch along the AA trigger execution path (evaluation is invoked from `aa_composer.js`'s `handleTrigger`/`evaluateAA`, which is itself invoked from the unit-processing/writer pipeline), it becomes an uncaught exception in the node's core processing code. In Node.js, an uncaught synchronous exception crashes the process. Because this fires during processing of units that are part of normal DAG/consensus flow (AA trigger evaluation, executed by every node validating or executing the AA), a single crafted setup (two oracle AAs whose unstable data-feed-emitting responses land at identical level/latest_included_mc_index, referenced together by a third AA's `data_feed()` oracle list) could crash any node that attempts to execute/validate that AA response — a network-wide denial of service preventing confirmation of new units, which satisfies the "network unable to confirm new units" impact bar.

### Likelihood Explanation
Exploitability requires an attacker to: (1) deploy or use two existing AAs (or a single attacker-controlled AA that posts two data feeds from different addresses simultaneously) as oracles referenced by a `data_feed()` call in a third AA definition, and (2) arrange for their `data_feed` messages to be emitted in a way that produces exactly matching `level` and `latest_included_mc_index`, which is plausible for units created from the same trigger/parent set within the same DAG round but is not guaranteed on every attempt — some crafting/timing is needed. This makes the likelihood moderate rather than trivial, but the trigger is fully reachable by an ordinary AA/trigger author with no special privilege.

### Recommendation
Remove the `throw` in the comparator in `readDataFeedValue()` (data_feeds.js:266) and replace it with a deterministic, total-order tie-breaker (e.g., compare by `unit` string) instead of raising an exception, mirroring the `bIncludeAllUnstable` branch's fallback behavior. Additionally, wrap AA formula evaluation / oracle resolution in defensive error handling so that any future unexpected throw inside `evaluate()`/`getDataFeed()` is converted into an AA bounce rather than propagating as an uncaught exception that can crash the node process.

### Proof of Concept
1. Deploy two "oracle" AAs, A1 and A2 (or a single account posting to both addresses used as `oracles`).
2. Deploy a third AA, T, whose formula includes: `data_feed(oracles=[A1_address, A2_address], feed_name="x", ifseveral="last")` — with no `ifnone`/`abort` handling.
3. Trigger A1 and A2 such that both post `data_feed` messages for feed `x` as part of units that end up unstable with identical `level` and `latest_included_mc_index` (e.g., both are secondary AA responses to the same primary trigger unit, built from the same parent set at the same DAG depth).
4. Post a trigger to T while both A1's and A2's `data_feed` units are still unstable.
5. During T's formula evaluation, `readDataFeedValue()` finds two candidates with identical `latest_included_mc_index`/`level`, hits the `throw Error("can't sort candidates ...")` branch inside `Array.prototype.sort`, and — if uncaught anywhere in the call chain up to unit processing — crashes the executing node process.

Note: I was unable to fully verify, within the available tooling, whether `aa_composer.js`'s `handleTrigger`/`evaluateAA` (or a higher-level caller in `writer.js`/`main_chain.js`) wraps formula evaluation in a try/catch that would convert this throw into a graceful bounce rather than a fatal process crash. Confirming that guard (or its absence) requires reviewing the full call stack from `evaluateAA` up through unit/response processing, which should be checked directly in the repository before treating this as a certain full-node crash.

### Citations

**File:** data_feeds.js (L205-273)
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
		if (arrCandidates.length === 1) {
			var feed = arrCandidates[0];
			objResult.value = feed.value;
			objResult.unit = feed.unit;
			objResult.mci = feed.mci;
			if (ifseveral === 'last')
				return handleResult(objResult);
		}
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
			objResult.value = feed.value;
			objResult.unit = feed.unit;
			objResult.mci = feed.mci;
			return handleResult(objResult);
		}
```

**File:** formula/evaluation.js (L646-646)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
```
