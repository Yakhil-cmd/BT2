### Title
Unbounded growth of `storage.assocUnstableMessages` enables linear-scan DoS on data-feed lookups reachable from any AA trigger - (File: `data_feeds.js`, `writer.js`, `storage.js`)

### Summary
Any unprivileged unit poster can attach a cheap `data_feed` (or `definition`/`system_vote`/`system_vote_count`) message to a unit. Every such unit's message is appended to the in-memory global dictionary `storage.assocUnstableMessages` and is only removed once that unit's MCI becomes stable. `dataFeedExists()` and `readDataFeedValue()` in `data_feeds.js`, which are invoked on the hot path of AA formula evaluation (`in data feed`/`data feed value` oscript expressions), do a full `for (var unit in storage.assocUnstableMessages)` linear scan plus a `_.intersection()` call for every entry, on every single AA trigger that uses a data-feed condition. This mirrors the reported bug class: a cheap, unprivileged, repeatable action grows an unbounded structure that is checked with an O(n) scan on every future operation, degrading/denying service to legitimate users.

### Finding Description
`writer.js` unconditionally appends every `data_feed`/`definition`/`system_vote`/`system_vote_count` message of a newly-saved unit to `storage.assocUnstableMessages[unit]`, regardless of who posted it: [1](#0-0) 

This dictionary is only cleaned up when the unit's MCI becomes stable, inside `markMcIndexStable` → `saveUnstablePayloads()`, which iterates the stored messages and finally does `delete storage.assocUnstableMessages[unit]`: [2](#0-1) 

Until stabilization happens (which depends on witnessing/MC progress and can be delayed under load, forks, or by an attacker who keeps flooding the DAG with more units), every additional single-authored unit containing a `data_feed` message adds one more entry that must be scanned.

`dataFeedExists()` (used by `in data feed` conditions during AA-context evaluation with `bAA=true`) and `readDataFeedValue()` (used by `data feed` value lookups with `unstable_opts`) both iterate the *entire* `storage.assocUnstableMessages` object on every single call, performing a `_.intersection()` and inner message loop for each unstable unit found: [3](#0-2) [4](#0-3) 

Because posting a unit with a `data_feed` message costs only ordinary TPS/size fees (no `MIN` value requirement and only per-message field-length limits — `MAX_DATA_FEEDS_PER_MESSAGE`, `MAX_DATA_FEED_NAME_LENGTH`, `MAX_DATA_FEED_VALUE_LENGTH`, verified in `constants.js:53-55`), an attacker can cheaply and repeatedly post many small, single-author units each containing a minimal `data_feed` message and keep the unstable-message set large by sustaining a stream of new units (each unit stays "unstable" for some real time before being included and stabilized on the main chain). Similar O(n) full-dictionary scans exist elsewhere over the same structure, e.g. `storage.getUnconfirmedAADefinition()`: [5](#0-4) 

This is directly analogous to the reported bug: an unprivileged actor (any single unit author, or an AA trigger sender indirectly, since data feed messages are typically posted by oracles but nothing prevents any address from posting them) performs cheap, repeated operations that grow an unbounded in-memory collection which is linearly scanned by a shared, security-critical code path (AA data-feed condition evaluation) reachable by every other AA trigger in the network.

### Impact Explanation
As `storage.assocUnstableMessages` grows, every AA trigger unit that evaluates an `in data feed`/`data feed value` oscript expression must pay increasing CPU/time cost proportional to the number of outstanding unstable data-feed/definition/vote messages, because `dataFeedExists`/`readDataFeedValue` scan the whole structure on every call regardless of relevance to the querying address. Sustained flooding can materially slow down or effectively deny legitimate AA executions relying on data feeds — a shared resource used by many independent AAs/oracles — degrading throughput and potentially preventing new units (AA responses depending on timely data-feed evaluation) from being processed within expected time/gas-equivalent (formula execution/complexity) budgets. This matches the "network unable to confirm new units in a timely manner" / AA fund-loss-through-freezing class of impact, since AA logic gated on data feeds could stall or time out under load.

### Likelihood Explanation
Likelihood is moderate: crafting and broadcasting many minimal single-author units with `data_feed` messages requires only normal fees (no privileged role, no special asset/AA setup), and the codebase imposes no per-address or global rate limit on how many *distinct* units carrying such messages can be outstanding (unstable) simultaneously — only per-message field-size limits exist. The severity is bounded by normal fee/TPS-fee costs and by how long units stay unstable before MC stabilization, which somewhat limits window size compared to the original permanently-growing on-chain array, but a sustained/parallel flood (many parallel non-conflicting units) can still keep the unstable set large for extended periods, making this a realistic, medium-likelihood DoS vector on nodes running AAs that consume data feeds.

### Recommendation
- Replace the `for (var unit in storage.assocUnstableMessages)` full scans in `dataFeedExists`/`readDataFeedValue` (`data_feeds.js`) with an index keyed by `(feed_name)` or `(author_address, feed_name)` so lookups don't need to touch unrelated units.
- Consider bounding the number of concurrently-tracked unstable `data_feed`/`definition`/`system_vote` messages, or applying a stricter TPS-fee multiplier specifically to `data_feed` messages proportional to current unstable backlog size, to make sustained flooding economically costly.
- Add a maintained secondary index (e.g., `assocUnstableDataFeedsByName`) updated in `writer.js` alongside `assocUnstableMessages`, and consumed by `data_feeds.js`, to make the AA-context lookup O(1)/O(log n) instead of O(n) in the total count of outstanding unstable special messages.

### Proof of Concept
1. Attacker controls or creates many distinct addresses (or authors many messages) with minimal balances sufficient to pay standard fees.
2. Attacker rapidly broadcasts many parallel, non-conflicting single-authored units, each containing one `data_feed` message with a short feed name/value (well within `MAX_DATA_FEED_NAME_LENGTH`/`MAX_DATA_FEED_VALUE_LENGTH`).
3. Because units require time to become included and stabilized on the main chain, a sustained stream keeps thousands of entries in `storage.assocUnstableMessages` at any given time (each entry persists from `writer.js:603-613` until removed in `main_chain.js:1550-1584`).
4. Any legitimate AA that evaluates an `in data feed` or `data feed` formula expression triggers `dataFeedExists`/`readDataFeedValue` in `data_feeds.js`, which must iterate the entire bloated `assocUnstableMessages` object plus run `_.intersection()` per entry, increasing execution latency for every subsequent AA trigger that depends on data feeds.
5. As the flood continues, AA response times for all data-feed-dependent AAs increase, potentially causing timeouts/delays in AA execution and, in the worst case, congesting the node's ability to process new units in a timely fashion.

### Citations

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

**File:** main_chain.js (L1550-1584)
```javascript
								async function saveUnstablePayloads() {
									let arrUnstableMessages = storage.assocUnstableMessages[unit];
									if (!arrUnstableMessages)
										return cb();
									if (objUnitProps.sequence === 'final-bad'){
										delete storage.assocUnstableMessages[unit];
										return cb();
									}
									for (let message of arrUnstableMessages) {
										const { app, payload } = message;
										switch (app) {
											case 'data_feed':
												addDataFeeds(payload);
												break;
											case 'definition':
												// before the fix, re-inserting recalculated aa_balances to pick up non-AA payments received between definition and stabilization
												if (objUnitProps.is_aa_response && mci >= constants.pemCurvesFixMci)
													continue; // already inserted in writer.js with the correct balance
												const objLastBallUnitProps = await storage.readUnitProps(conn, objUnitProps.last_ball_unit);
												const definer_last_ball_mci = objLastBallUnitProps.main_chain_index;
												await storage.insertAADefinitions(conn, [payload], unit, mci, definer_last_ball_mci, false);
												break;
											case 'system_vote':
												await saveSystemVote(payload);
												break;
											case 'system_vote_count': // will be processed later, when we finish this mci
												if (!voteCountSubjects.includes(payload))
													voteCountSubjects.push(payload);
												break;
											default:
												throw Error("unrecognized app in unstable message: " + app);
										}
									}
									delete storage.assocUnstableMessages[unit];
									cb();
```

**File:** data_feeds.js (L13-44)
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
			storage.assocUnstableMessages[unit].forEach(function (message) {
```

**File:** data_feeds.js (L211-225)
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
