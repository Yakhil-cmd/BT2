### Title
Non-atomic data-feed reads let the same `data_feed[[...]]` query return different values within a single AA trigger evaluation - (File: data_feeds.js, formula/evaluation.js)

### Summary
`readDataFeedValue`/`dataFeedExists` in `data_feeds.js` answer queries for unstable oracle posts by scanning the live, mutable global cache `storage.assocUnstableMessages` at the exact moment they are called, rather than against a snapshot fixed at the start of AA-trigger evaluation. Because a single AA response is composed through many chained asynchronous callbacks (`conn.query`, `async.eachSeries`, etc.), the Node.js event loop can process and record a newly-arrived unit (including a new `data_feed` message from the same oracle/feed_name) into `storage.assocUnstableMessages` between two separate `data_feed[[...]]` evaluations that occur in different parts of the same AA formula (e.g., one in an `if`/`init` block and another later in a `messages`/`state` block). This mirrors the reported Solidity bug where `currentDailyRate` is fetched once but a later step in the same logical operation ends up using a changed value.

### Finding Description
`readDataFeedValue` (and `dataFeedExists`) are invoked from `formula/evaluation.js` for the `data_feed` / `in_data_feed` opcodes: [1](#0-0) 

When `unstable_opts`/`bAA` is set (true for AA formula evaluation), the function iterates the live global object `storage.assocUnstableMessages` to find qualifying oracle posts: [2](#0-1) 

This iteration is not based on a frozen snapshot passed into the evaluation; it directly reads whatever is currently in `storage.assocUnstableMessages` at call time: [3](#0-2) 

An AA's oscript can legitimately invoke `data_feed[[...]]` for the same oracle/feed multiple times in different sections of the same trigger response composition — for example, once to gate an `if` condition and again later to compute a payment amount, as seen in the futures-contract sample: [4](#0-3) 

Because AA-trigger processing in `aa_composer.js` (`handleTrigger`) is fully asynchronous — evaluating `if`, `init`, and `messages` sections through a chain of DB callbacks — Node's single-threaded event loop can interleave the processing of another incoming joint (which registers a new unstable unit into `storage.assocUnstableUnits`/`storage.assocUnstableMessages`) between the two `data_feed[[...]]` evaluations belonging to the *same* AA response composition. The second read can then observe an additional candidate unit that the first read did not see, producing two different values for what the oscript author intended to be the "current" oracle value within one atomic trigger execution.

### Impact Explanation
If two reads of the same oracle/feed inside one AA execution disagree, the AA can compute internally inconsistent results (e.g., a condition passes with price A but the payout is computed with a different, newly-arrived price B). More importantly, whether the second unit has been received and merged into `storage.assocUnstableMessages` at the moment of the second read depends on real-time network/event-loop timing that differs from node to node. Two honest full nodes validating/composing the exact same AA response could therefore derive different response units (different bounce decision or different payout amount) for the identical trigger unit, i.e., node disagreement on AA response validity — a consensus-breaking condition for a DAG ledger where deterministic execution across all nodes is a hard correctness requirement. This falls squarely into the accepted "node disagreement on validity" impact category and can also translate into AA fund loss (over/under payment) depending on which branch was chosen.

### Likelihood Explanation
The window is real but narrow: it requires (a) an AA oscript that reads the same oracle feed more than once within different phases of one trigger response, and (b) a new matching data-feed unit from that oracle arriving on the P2P network and being processed by the node in between those two internal evaluation steps. Because AA responses are typically evaluated quickly, the race window is small, but any active price oracle publishing feeds frequently (a normal, expected usage pattern for AAs like the futures/market-maker examples in this very codebase) increases the probability of a collision, especially under network load or when many units are queued for hub processing. This is a timing-dependent bug rather than an attacker-controlled deterministic exploit, so likelihood is Medium, but the impact (consensus divergence / miscomputed AA funds) is High.

### Recommendation
Snapshot the set of qualifying unstable units (or at minimum, the resolved value for a given `(oracles, feed_name, relation, value, min_mci, max_mci)` tuple) once at the start of AA-trigger evaluation, and reuse that snapshot/cache for every subsequent identical `data_feed[[...]]`/`in_data_feed[[...]]` lookup performed during the same trigger's response composition (including across `if`, `init`, and `messages`/`state` phases, and across chained/secondary AA invocations triggered by the same top-level trigger). This guarantees that all data-feed reads for the same query parameters within a single deterministic AA execution return an identical, time-invariant value, eliminating cross-node divergence caused by unrelated network timing.

### Proof of Concept
1. Deploy an AA whose oscript calls `data_feed[[oracles=O, feed_name='F']]` twice within the composition of a single response — once inside an `if`/`init` block that gates behavior, and again inside a later `messages`/`state` block that computes a payout amount (this pattern already exists in `futures_contract.oscript` and the uniswap-like sample, which read prices/values at multiple points of the same response).
2. Trigger the AA with a unit from an unprivileged address.
3. While the node is asynchronously composing the AA response (between the first and second `data_feed[[...]]` evaluation), have the oracle broadcast a new `data_feed` unit for the same `(oracles, feed_name)` that is still unstable but satisfies the `min_mci`/`max_mci` bounds used by the AA's query.
4. Because `readDataFeedValue`/`dataFeedExists` scan the live `storage.assocUnstableMessages` at call time (`data_feeds.js:211-241`, `34-44`) rather than a frozen snapshot, the second `data_feed[[...]]` call can pick up the newly-arrived oracle post while the first call did not, causing the two reads inside the same trigger execution to disagree.
5. Since arrival timing of the new oracle unit relative to the two evaluation points differs per node, some nodes will compute the AA response using the old value throughout, while others compute it using the mixed old/new values, producing different response units for the same trigger unit — a node-disagreement/consensus-divergence condition.

### Citations

**File:** formula/evaluation.js (L646-646)
```javascript
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
```

**File:** data_feeds.js (L34-44)
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

**File:** test/samples/futures_contract.oscript (L60-60)
```text
				if: `{ trigger.data.blackswan AND !var['blackswan'] AND data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA']] < 25 AND timestamp < 1556668800 }`,
```
