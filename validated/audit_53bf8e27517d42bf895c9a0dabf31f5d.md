## Title
AA execution reads unconfirmed (in-memory, timing-dependent) data feeds and definitions, causing non-deterministic AA responses and node disagreement - (File: `data_feeds.js`, `storage.js`)

### Summary
The reported CKB bug is caused by consensus-critical code (`load_cell_data`) consulting mempool/local memory state for an input cell that is not yet confirmed, so different nodes — depending on what they happen to have in their local mempool at validation time — reach different validity conclusions, causing bans and a network split. ocore has an architecturally analogous pattern: Autonomous Agent (AA) trigger execution reads data feeds and AA definitions not from the confirmed/stable database, but from an in-process cache of "unstable" messages (`storage.assocUnstableMessages`) that is populated purely by the order/timing in which each node has *locally received* units, not by a value that is deterministically fixed once the relevant MCI is stable.

### Finding Description
When an MCI is marked stable, `handleAATriggers()` is invoked and, for every primary trigger, `handleTrigger()` executes the AA with `objValidationState.last_ball_mci = mci` fixed to the just-stabilized MCI [1](#0-0) [2](#0-1) .

During formula evaluation, `data_feed` / `in_data_feed` opcodes call `dataFeeds.readDataFeedValue(...)` / `dataFeeds.dataFeedExists(...)` with `bAA` (whether we're inside an AA) passed as the `unstable_opts` flag and `max_mci = mci` (the just-stabilized MCI) [3](#0-2) [4](#0-3) .

Inside `data_feeds.js`, when `unstable_opts` is truthy, the code iterates the in-memory `storage.assocUnstableMessages` map — which contains messages of **every unit the node currently knows about that isn't yet stable**, regardless of when it was received — and includes any AA-authored message whose `latest_included_mc_index` falls within `[min_mci, max_mci]`: [5](#0-4) 

The same in-memory, arrival-order-dependent lookup pattern also backs AA definitions via `getUnconfirmedAADefinition()`, which scans `assocUnstableMessages` for a `definition` message matching an address [6](#0-5) .

`assocUnstableMessages` entries are appended synchronously as soon as any unit (stable or not) is written locally via `writer.saveJoint()`, i.e. purely a function of *when this particular node received the unit*, not a function of the DAG state that is already fixed once an MCI is stable [7](#0-6) .

Consequently, whether a given not-yet-stable AA-posted data feed unit `U` (with `latest_included_mc_index <= mci`) is present in the candidate set at the moment trigger execution runs depends entirely on network-propagation timing: a node that has already received `U` before executing the trigger includes it; a node that stabilizes the same MCI and executes the same trigger microseconds earlier (before `U` propagates to it) does not. The code even acknowledges genuine ambiguity is possible ("still ambiguous, sort randomly (it's OK outside AAs)" and an explicit `throw Error("can't sort candidates...")` for the in-AA tie case) [8](#0-7) , but this only guards against ties *within* an already-identical candidate set — it does nothing about the candidate *set itself* differing across nodes.

### Impact Explanation
Because the candidate set of "unstable AA-authored data feeds/definitions" is not deterministically pinned to the stabilized DAG but instead to each node's local, timing-dependent view, two honest, correctly-running nodes can execute the identical primary AA trigger at the identical MCI and compute different data-feed values (or a different/absent AA definition). This changes the AA's computed response (amount, bounce/non-bounce, or referenced sub-AA), producing different response unit content/hashes on different nodes. Since AA response units are themselves committed to the DAG deterministically by the executing node and then propagated, nodes that computed a different response will reject the propagated response unit as invalid (hash/content mismatch), leading to node disagreement on unit validity, inability to reach consensus on AA state, and potential loss or freezing of AA funds tied to the divergent execution.

### Likelihood Explanation
This requires two AAs (or an AA responding based on another still-unstable AA's data feed) interacting within the same MC round with propagation delay between the data-feed-posting unit and independent nodes' local stabilization/trigger-execution timing — a realistic and fairly common scenario for chained/cascading AAs, which is an explicitly supported design feature (secondary AA triggers reading peer AA outputs before full stabilization). No malicious actor input is even strictly required beyond ordinary network latency, though an attacker can deliberately delay/accelerate propagation of a data-feed-posting unit to specific nodes to trigger the divergence deterministically.

### Recommendation
Do not source data feeds/AA definitions used during trigger execution from a purely-local, timing-dependent in-memory cache (`assocUnstableMessages`). Instead, bound the candidate set to something computed identically for all nodes independent of arrival order — e.g., only include unstable units that are provably included in the ancestry of the current MC state via `graph.determineIfIncludedOrEqual`-style checks (as already done for unstable payment inputs in `validation.js`), or defer visibility of any not-yet-stable data feed until it is guaranteed to be part of every node's view at the moment the MCI stabilizes.

### Proof of Concept
1. AA `A` posts a `data_feed` message `U` referencing MCI `M` (`latest_included_mc_index = M`), but `U` itself is not yet stable.
2. Simultaneously, `M` becomes stable across the network, and a primary trigger `T` to AA `B` (which reads `A`'s feed with `unstable_opts`/`bAA=true`) becomes due for execution via `handleAATriggers()`.
3. Node X receives and applies `U` before executing `T`; node Y executes `T` before receiving `U`.
4. `readDataFeedValue`/`dataFeedExists` on node X includes `U` in `arrCandidates` (`data_feeds.js:213-241`); node Y's `arrCandidates` does not.
5. AA `B`'s formula branches differently (e.g., `otherwise`/`in data feed` condition), producing a different response payload/amount on X vs Y.
6. Each node commits its own version of the AA response unit; when propagated, the two networks reject each other's response unit as invalid, causing a chain split / disagreement on AA state and fund handling.

### Citations

**File:** main_chain.js (L1676-1691)
```javascript
	function calcCommissions(){
		if (mci === 0)
			return handleAATriggers();
		async.series([
			function(cb){
				profiler.start();
				headers_commission.calcHeadersCommissions(conn, cb);
			},
			function(cb){
				profiler.stop('mc-headers-commissions');
				paid_witnessing.updatePaidWitnesses(conn, cb);
			}
		], handleAATriggers);
	}

	function handleAATriggers() {
```

**File:** aa_composer.js (L446-462)
```javascript
	var bounce_fees = template.bounce_fees || {base: constants.MIN_BYTES_BOUNCE_FEE};
	if (!bounce_fees.base)
		bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
//	console.log('===== trigger.outputs', trigger.outputs);
	var objValidationState = {
		last_ball_mci: mci,
		last_ball_timestamp: objMcUnit.timestamp,
		mc_unit: objMcUnit.unit,
		assocBalances: {},
		number_of_responses: arrResponses.length,
		arrPreviousAAResponses: arrResponses.map(objAAResponse => ({
			unit_obj: objAAResponse.objResponseUnit || false,
			trigger_unit: objAAResponse.trigger_unit,
			trigger_address: objAAResponse.trigger_address,
			aa_address: objAAResponse.aa_address,
		})),
	};
```

**File:** formula/evaluation.js (L646-646)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
```

**File:** formula/evaluation.js (L745-745)
```javascript
						dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, mci, bAA, cb);
```

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

**File:** data_feeds.js (L255-273)
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
			var feed = arrCandidates[arrCandidates.length - 1];
			objResult.value = feed.value;
			objResult.unit = feed.unit;
			objResult.mci = feed.mci;
			return handleResult(objResult);
		}
```

**File:** storage.js (L862-880)
```javascript
function getUnconfirmedAADefinition(address) {
	for (var unit in assocUnstableMessages) {
		var objUnit = assocUnstableUnits[unit] || assocStableUnits[unit]; // just stabilized
		if (!objUnit)
			throw Error("unstable unit " + unit + " not in assoc");
		if (objUnit.sequence !== 'good')
			continue;
		var messages = assocUnstableMessages[unit];
		for (var i = 0; i < messages.length; i++) {
			var message = messages[i];
			if (message.app !== 'definition')
				continue;
			var payload = message.payload;
			if (payload.address === address)
				return payload.definition;
		}
	}
	return null;
}
```

**File:** writer.js (L603-613)
```javascript
			if (objUnit.messages) {
				objUnit.messages.forEach(function(message) {
					if (['data_feed', 'definition', 'system_vote', 'system_vote_count'].includes(message.app)) {
						if (!storage.assocUnstableMessages[objUnit.unit])
							storage.assocUnstableMessages[objUnit.unit] = [];
						storage.assocUnstableMessages[objUnit.unit].push(message);
						if (message.app === 'system_vote' && !objValidationState.bDryRun)
							eventBus.emit('system_var_vote', message.payload.subject, message.payload.value, arrAuthorAddresses, objUnit.unit, 0);
					}
				});
			}
```
