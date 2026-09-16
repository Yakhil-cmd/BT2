This is a strong analog. `applyEmergencyOpListChange` in `main_chain.js` is the ocore equivalent of Derby's `blacklistProtocol`: an "emergency" safety valve meant to unstick the network when normal OP (order-provider/witness) list voting has stalled, but it unconditionally calls `countVotes(..., is_emergency=1, ...)` [1](#0-0) , and that function `throw`s a hard, uncaught `Error` if the emergency tally doesn't produce exactly `constants.COUNT_WITNESSES` distinct OP addresses [2](#0-1) .

### Title
Emergency OP-list vote count (`applyEmergencyOpListChange`/`countVotes`) throws instead of degrading gracefully, crashing the node exactly when the emergency mechanism is needed - (File: main_chain.js)

### Summary
`applyEmergencyOpListChange` is invoked from `writer.js` after a `system_vote_count` message is included in a stable, good unit, specifically to break a stall in main-chain advancement by force-counting order-provider (OP/witness) votes early [3](#0-2) . Like `Vault.blacklistProtocol`, this is an emergency-only code path that is supposed to work reliably precisely in abnormal conditions (the network stuck because normal voting hasn't produced a valid new OP list in time). But its implementation, `countVotes(conn, mci, 'op_list', 1, timestamp)`, unconditionally requires the result set to contain exactly `COUNT_WITNESSES` (12) distinct addresses, or it throws a hard `Error`, aborting the whole write/stabilization transaction instead of handling the "not enough consensus yet" case gracefully [4](#0-3) .

### Finding Description
`applyEmergencyOpListChange(conn, emergency_count_command_timestamp, cb)` is called from inside `saveJoint`'s post-commit pipeline whenever a stable unit carries a `system_vote_count` message for `op_list` [3](#0-2) . Its only guard is a time-based check (`EMERGENCY_OP_LIST_CHANGE_TIMEOUT`); once that passes it directly calls `countVotes` with `is_emergency=1` [1](#0-0) .

Inside `countVotes`, for `subject === 'op_list'`, the emergency branch builds a temporary votes table combining stable `op_votes` with any sufficiently-aged unstable votes (`getUnstableVotes`), then aggregates the top `COUNT_WITNESSES` OP addresses by voted balance within the lookback window (`since_timestamp`) [5](#0-4) . If, in this emergency scenario, fewer than `COUNT_WITNESSES` distinct OP addresses have accumulated enough eligible votes (a very plausible situation if voting is exactly the reason the chain is stuck, e.g., voter balances have shifted, some previously-eligible OPs dropped below the participation threshold, or the vote timeframe expansion loop hasn't yet reached enough voters), the code throws:
```
if (ops.length !== constants.COUNT_WITNESSES)
    throw Error(`wrong number of voted OPs: ` + ops.length);
``` [6](#0-5) 

This throw is not caught anywhere in the call chain — `applyEmergencyOpListChange` does not wrap the `await countVotes(...)` in a try/catch [7](#0-6) , and the caller in `writer.js` runs it as a plain array entry inside `async.series(arrOps, ...)`, invoked from deep within the unit-commit/`markMcIndexStable` pipeline, with no error-handling wrapper visible around this specific op [8](#0-7) . An uncaught throw at this point crashes the node process (this is the same idiom used throughout the codebase for "unreachable"/fatal invariant violations, e.g. `throwError` in the same file [9](#0-8) ).

This mirrors the Derby bug precisely: an emergency/recovery function couples a critical state transition (installing a corrected OP list to unstick main-chain progress) with an unconditional operation (requiring a full clean tally of exactly 12 OPs) that can fail specifically because of the very condition the emergency path exists to fix (insufficient/stalled voting). Instead of applying a best-effort partial update or safely no-op'ing and retrying later, the code throws and takes down the node.

### Impact Explanation
Because `applyEmergencyOpListChange` runs synchronously as part of committing a stable unit (inside `saveJoint`/`markMcIndexStable`), an uncaught throw here does not just fail one emergency-vote attempt — it crashes every node that processes this unit, right at the moment the network is already stuck and depending on the emergency mechanism to recover. This can turn a temporary stall into a network-wide inability to confirm new units (nodes crash/repeatedly crash on restart when re-processing the same stable unit), which matches the "network unable to confirm new units" impact class. Because the emergency path is specifically designed for exceptional/abnormal circumstances, this is the scenario where robustness is most needed and least present.

### Likelihood Explanation
Triggering this requires the main chain to actually stall long enough for `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` to elapse and for a valid `system_vote_count` message to be included and stabilize (i.e., the exact scenario the emergency mechanism targets) while voted balances for OPs are split such that fewer than exactly `COUNT_WITNESSES` addresses clear the vote-aggregation query. This is a narrower, more privileged trigger than a plain unit post (only reachable via the AA/OP governance path and requiring an emergency to already be underway), but it is a realistic outcome of the OP set having low or non-uniform participation, which is a normal condition to expect during a stall rather than an edge case.

### Recommendation
`countVotes`'s emergency branch should not `throw` when fewer than `COUNT_WITNESSES` OPs qualify. Instead:
- If the emergency tally cannot produce a full slate, `applyEmergencyOpListChange`/`countVotes` should return an error/no-op result and let the timeout-and-retry mechanism try again later (as intended by the periodic `system_vote_count` design), rather than raising an uncaught exception that terminates the node.
- Wrap the `countVotes` call in `applyEmergencyOpListChange` (and/or the `arrOps` entry in `writer.js`) in explicit error handling so a shortfall in emergency votes degrades to "not enough votes yet, try again next attempt" instead of propagating a fatal, unit-processing-halting exception.

### Proof of Concept
1. Main chain stalls because the current OP-list vote threshold (`SYSTEM_VOTE_MIN_SHARE`/participation) is not being met under normal (non-emergency) `countVotes` counting.
2. `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` elapses; a `system_vote_count` message for `op_list` is posted and stabilizes, triggering `writer.js`'s `main_chain.applyEmergencyOpListChange(conn, objUnit.timestamp, cb)` [10](#0-9) .
3. `applyEmergencyOpListChange` calls `countVotes(conn, main_chain_index - 1, 'op_list', 1, emergency_count_command_timestamp)` [11](#0-10) .
4. Because voted balances are split across more than `COUNT_WITNESSES` candidate OP addresses, or aged-unstable-vote inclusion still leaves the top slate short of 12 distinct addresses meeting the `since_timestamp` window, `op_rows` returns `ops.length !== constants.COUNT_WITNESSES`.
5. `countVotes` throws `Error("wrong number of voted OPs: " + ops.length)` [6](#0-5) , which is unhandled up through `applyEmergencyOpListChange` and the `arrOps`/`async.series` pipeline in `writer.js`, crashing the node while it is processing/committing this unit — and any node re-syncing past this same stable unit will crash identically, since the condition is deterministic given the ledger state.

Note: I could not fully trace every caller of `writer.js`'s `arrOps`/`async.series(arrOps, ...)` error path to confirm there is no outer catch that converts the crash into a recoverable no-op; this would benefit from execution tracing or a Devin session with full repository access to confirm definitively whether any wrapping try/catch exists elsewhere in the process (e.g., in the top-level event loop) that limits the blast radius to something less than a full node crash.

### Citations

**File:** main_chain.js (L1826-1862)
```javascript
			const votes_table = is_emergency ? 'op_votes_tmp' : 'op_votes';
			if (is_emergency) { // add unstable votes for OPs
				await conn.query(`CREATE TEMPORARY TABLE ${votes_table} AS SELECT address, op_address, timestamp FROM op_votes`);
				// the order of iteration is undefined, so we'll first collect the messages and then sort them. The order matters only when the same address sends multiple unstable votes
				let votes = unstable_votes || getUnstableVotes(emergency_count_command_timestamp);
				console.log('unsorted unstable votes', votes);
				votes.sort((v1, v2) => {
					const dt = v1.timestamp - v2.timestamp;
					if (dt !== 0)
						return dt;
					return v1.level - v2.level;
				});
				console.log('sorted unstable votes', votes);
				for (let { timestamp, author_addresses, arrOPs } of votes) {
					// apply each vote separately as a new unstable vote from the same user would override the previous one
					await conn.query(`DELETE FROM ${votes_table} WHERE address IN (?)`, [author_addresses]);
					let values = [];
					for (let address of author_addresses)
						for (let op_address of arrOPs)
							values.push(`(${db.escape(address)}, ${db.escape(op_address)}, ${timestamp})`);
					console.log('unstable votes', values);
					await conn.query(`INSERT INTO ${votes_table} (address, op_address, timestamp) VALUES ` + values.join(', '));
				}
			}
			const op_rows = await conn.query(`SELECT op_address, SUM(balance) AS total_balance
				FROM ${votes_table}
				CROSS JOIN voter_balances USING(address)
				WHERE timestamp>=?
				GROUP BY op_address
				ORDER BY total_balance DESC, op_address
				LIMIT ?`,
				[since_timestamp, constants.COUNT_WITNESSES]
			);
			console.log(`total votes for OPs`, op_rows);
			let ops = op_rows.map(r => r.op_address);
			if (ops.length !== constants.COUNT_WITNESSES)
				throw Error(`wrong number of voted OPs: ` + ops.length);
```

**File:** main_chain.js (L1936-1946)
```javascript
async function applyEmergencyOpListChange(conn, emergency_count_command_timestamp, cb) {
	// last stable unit
	const [{ timestamp, main_chain_index }] = await conn.query("SELECT timestamp, main_chain_index FROM units WHERE is_stable=1 AND is_on_main_chain=1 ORDER BY main_chain_index DESC LIMIT 1");
	if (emergency_count_command_timestamp < timestamp + constants.EMERGENCY_OP_LIST_CHANGE_TIMEOUT) {
		console.log(`too early to apply emergency OP list change yet`);
		return cb();
	}
	console.log(`applying emergency vote count after being stuck at mci ${main_chain_index}`);
	await countVotes(conn, main_chain_index - 1, 'op_list', 1, emergency_count_command_timestamp);
	cb();
}
```

**File:** main_chain.js (L1965-1971)
```javascript
function throwError(msg){
	debugger;
	if (typeof window === 'undefined')
		throw Error(msg);
	else
		eventBus.emit('nonfatal_error', msg, new Error());
}
```

**File:** writer.js (L639-653)
```javascript
							if (objValidationState.bHasSystemVoteCount && objValidationState.sequence === 'good') {
								const m = objUnit.messages.find(m => m.app === 'system_vote_count');
								if (!m)
									throw Error(`system_vote_count message not found`);
								if (m.payload === 'op_list')
									arrOps.push(cb => main_chain.applyEmergencyOpListChange(conn, objUnit.timestamp, cb));
							}
							arrOps.push(function(cb){
								console.log("updating MC after adding "+objUnit.unit);
								main_chain.updateMainChain(conn, batch, null, objUnit.unit, objValidationState.bAA, (_arrStabilizedMcis, _bStabilizedAATriggers) => {
									arrStabilizedMcis = _arrStabilizedMcis;
									bStabilizedAATriggers = _bStabilizedAATriggers;
									cb();
								});
							});
```
