Confirmed — `storage.resetMemory()` clears `assocUnstableUnits` synchronously via `resetUnstableUnits()` and only repopulates it via an asynchronous `initUnstableUnits()` query, but it never touches `assocUnstableMessages` (except for the single failed unit, deleted separately in `writer.js`). This leaves a real window in which `assocUnstableMessages` still references units for which `assocUnstableUnits[unit]` is empty.

### Title
Unhandled crash from destructuring `storage.assocUnstableUnits[unit]` during the async cache-reset window in vote counting - ([File: main_chain.js])

### Summary
`main_chain.js`'s `getUnstableVotes()` (used by `hasUnstableOpVoteCount()` and by `countVotes()` for emergency OP-list recounting) iterates `storage.assocUnstableMessages` and unconditionally destructures the corresponding entry from `storage.assocUnstableUnits[unit]` [1](#0-0) . This mirrors the CVE-2026-62432 bug class: a check (`hasUnstableOpVoteCount()`) is evaluated against shared, mutable state without holding the lock that actually protects consistency of that state, and it can race with a "reset" operation (`storage.resetMemory()`) that clears and asynchronously rebuilds the same cache, leading to a dereference of a missing/undefined object.

### Finding Description
`storage.resetMemory(conn)` is invoked from `writer.js` whenever `saveJoint()` hits an error while committing a unit [2](#0-1) . It calls `resetUnstableUnits()`, which **synchronously deletes every key** of `assocUnstableUnits` and `assocBestChildren`, then calls `initUnstableUnits(conn)`, which repopulates `assocUnstableUnits` only after an **asynchronous** DB query completes [3](#0-2) [4](#0-3) . Crucially, `assocUnstableMessages` (which stores `data_feed`/`definition`/`system_vote`/`system_vote_count` messages per unit) is **not cleared** by `resetMemory()` — only the single unit that failed to save has its entry deleted in `writer.js` [2](#0-1) . During the gap between the synchronous delete and the async repopulation, `assocUnstableUnits` is empty while `assocUnstableMessages` still contains entries for other, previously-known unstable units.

`hasUnstableOpVoteCount()` (called in `determineIfStableInLaterUnitsAndUpdateStableMcFlag()` before acquiring the `["handleJoint"]` lock, i.e., without any lock protecting the cache) and `getUnstableVotes()` (called from `countVotes()` during emergency OP-list vote counting, and again from the `get_system_var_votes` network handler) both loop over `storage.assocUnstableMessages` and destructure `storage.assocUnstableUnits[unit]` [5](#0-4) [1](#0-0) [6](#0-5) . If invoked while `assocUnstableUnits` is mid-reset, `storage.assocUnstableUnits[unit]` is `undefined`, and the destructuring `const { timestamp, author_addresses, sequence, level } = storage.assocUnstableUnits[unit];` throws `TypeError: Cannot destructure property ... of undefined`, an unhandled exception that crashes the Node.js process (no try/catch wraps this code path).

An unprivileged unit poster can trigger the reset path by causing a `writer.saveJoint()` failure (e.g., any error branch reached under normal validated-unit processing, including races the node itself can hit under load), and separately post units carrying `system_vote`/`system_vote_count` for `op_list` so that `assocUnstableMessages` is populated. Any concurrent request that exercises `getUnstableVotes()`/`hasUnstableOpVoteCount()` (vote counting during stabilization, or the `get_system_var_votes` P2P/API request) during the reset window can crash the node.

### Impact Explanation
A crash of the full node process is a network-availability issue: repeated triggering prevents the node from confirming new units, and if exploited broadly could be used to degrade the network's ability to reach consensus/stability (analogous to the "network unable to confirm new units" acceptance criterion). It also risks divergent behavior between nodes that crash/restart at different points versus nodes that don't, potentially causing disagreement on OP-list/system-var state after restart-driven cache reinitialization.

### Likelihood Explanation
The trigger conditions (a `saveJoint` error causing `resetMemory`, combined with unstable `system_vote_count`/`system_vote` messages and a concurrent read of the vote-counting caches) are plausible in normal operation without requiring a malicious peer or any special privilege — only ordinary unit posting and the natural asynchronous timing of Node.js's event loop. However, the exact window is narrow (bounded by a single DB query's round-trip), so reliably triggering it may require some effort/timing, which is why this is best characterized as a race condition rather than a deterministic crash.

### Recommendation
- Ensure `storage.resetMemory()`/`resetUnstableUnits()` also resets or protects `assocUnstableMessages` consistently, or perform the delete-then-repopulate cycle atomically with respect to any code that reads `assocUnstableUnits` in conjunction with `assocUnstableMessages`.
- Guard `getUnstableVotes()` (and `hasUnstableOpVoteCount()`) to skip/tolerate units missing from `assocUnstableUnits` instead of unconditionally destructuring, e.g., `if (!storage.assocUnstableUnits[unit]) continue;`.
- Ensure any cache-reset operation is performed under the same mutex (`["handleJoint"]` or `["write"]`) that guards all readers of `assocUnstableUnits`/`assocUnstableMessages`, closing the TOCTOU window.

### Proof of Concept
1. Node A processes a unit whose `saveJoint()` triggers an error path (any validated-unit write failure), causing `await storage.resetMemory(conn)` to run: `assocUnstableUnits` is synchronously cleared [3](#0-2) , then repopulated asynchronously via a DB query [4](#0-3) .
2. Before that DB query callback fires, some other previously-received unstable unit `U` that posted a `system_vote`/`system_vote_count` message still has an entry in `storage.assocUnstableMessages[U]` (not cleared by `resetMemory`), while `storage.assocUnstableUnits[U]` is now `undefined`.
3. During this window, a concurrent call reaches `getUnstableVotes()` (e.g., via `countVotes()`'s emergency op-list recount path, or the `get_system_var_votes` network request handler) [1](#0-0) [6](#0-5) .
4. The destructuring `const { timestamp, author_addresses, sequence, level } = storage.assocUnstableUnits[unit];` throws on `undefined`, crashing the process since nothing catches this exception.

### Citations

**File:** main_chain.js (L1206-1206)
```javascript
		const bOpListCanChange = hasUnstableOpVoteCount();
```

**File:** main_chain.js (L1915-1933)
```javascript
function getUnstableVotes(emergency_count_command_timestamp) {
	let votes = [];
	for (let unit in storage.assocUnstableMessages) {
		for (let m of storage.assocUnstableMessages[unit]) {
			if (m.app === 'system_vote' && m.payload.subject === 'op_list') {
				const { timestamp, author_addresses, sequence, level } = storage.assocUnstableUnits[unit];
				if (sequence !== 'good')
					continue;
				if (emergency_count_command_timestamp - timestamp < constants.EMERGENCY_COUNT_MIN_VOTE_AGE) {
					console.log('unstable vote from', author_addresses, 'is too young');
					continue;
				}
				const arrOPs = m.payload.value;
				votes.push({ timestamp, level, author_addresses, arrOPs });
			}
		}
	}
	return votes;
}
```

**File:** writer.js (L708-713)
```javascript
								if (err) {
									var headers_commission = require("./headers_commission.js");
									headers_commission.resetMaxSpendableMci();
									delete storage.assocUnstableMessages[objUnit.unit];
									await storage.resetMemory(conn);
								}
```

**File:** storage.js (L2300-2337)
```javascript
function initUnstableUnits(conn, onDone){
	if (!onDone)
		return new Promise(resolve => initUnstableUnits(conn, resolve));
	conn = conn || db;
	conn.query(
		"SELECT unit, level, latest_included_mc_index, main_chain_index, is_on_main_chain, is_free, is_stable, witnessed_level, headers_commission, payload_commission, sequence, timestamp, GROUP_CONCAT(address) AS author_addresses, COALESCE(witness_list_unit, unit) AS witness_list_unit, best_parent_unit, last_ball_unit, tps_fee, max_aa_responses, count_aa_responses, count_primary_aa_triggers, is_aa_response, version \n\
			FROM units \n\
			JOIN unit_authors USING(unit) \n\
			WHERE is_stable=0 \n\
			GROUP BY +unit \n\
			ORDER BY +level",
		function(rows){
		//	assocUnstableUnits = {};
			rows.forEach(function(row){
				var best_parent_unit = row.best_parent_unit;
			//	delete row.best_parent_unit;
				row.count_primary_aa_triggers = row.count_primary_aa_triggers || 0;
				row.bAA = !!row.is_aa_response;
				delete row.is_aa_response;
				row.tps_fee = row.tps_fee || 0;
				if (parseFloat(row.version) >= constants.fVersion4)
					delete row.witness_list_unit;
				delete row.version;
				row.author_addresses = row.author_addresses.split(',');
				assocUnstableUnits[row.unit] = row;
				if (assocUnstableUnits[best_parent_unit]){
					if (!assocBestChildren[best_parent_unit])
						assocBestChildren[best_parent_unit] = [];
					assocBestChildren[best_parent_unit].push(row);
				}
			});
			console.log('initUnstableUnits 1 done');
			if (Object.keys(assocUnstableUnits).length === 0)
				return onDone ? onDone() : null;
			initParenthoodAndHeadersComissionShareForUnits(conn, assocUnstableUnits, onDone);
		}
	);
}
```

**File:** storage.js (L2500-2508)
```javascript
function resetUnstableUnits(conn, onDone){
	Object.keys(assocBestChildren).forEach(function(unit){
		delete assocBestChildren[unit];
	});
	Object.keys(assocUnstableUnits).forEach(function(unit){
		delete assocUnstableUnits[unit];
	});
	initUnstableUnits(conn, onDone);
}
```

**File:** network.js (L3464-3470)
```javascript
					for (let unit in storage.assocUnstableMessages) { // undefined order of iteration, we might handle unstable votes from the same address in the wrong order
						const arrUnstableMessages = storage.assocUnstableMessages[unit];
						for (let message of arrUnstableMessages) {
							if (message.app !== 'system_vote')
								continue;
							const { subject, value } = message.payload;
							const { author_addresses, timestamp, sequence } = storage.assocUnstableUnits[unit];
```
