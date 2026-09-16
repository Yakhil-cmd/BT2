### Title
System-var vote counting mutates in-memory `storage.systemVars` cache before the corresponding DB write is committed - ([File: main_chain.js])

### Summary
`countVotes()` in `main_chain.js` first mutates the in-process cache `storage.systemVars[subject]` and only afterwards persists the same value with an `await conn.query(...INSERT/REPLACE INTO system_vars...)` inside the same DB transaction. This is structurally the same bug class as the Furnace `setRatio` finding: a piece of state that governs future protocol behavior (there: `ratio`/`lastPayout`; here: `op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) is updated in one place unconditionally while a dependent/paired persistence step can still fail, leaving the in-memory and on-disk representations of the same logical state permanently out of sync.

### Finding Description
`countVotes(conn, mci, subject, ...)` is triggered whenever any unprivileged unit author posts a `system_vote_count` message (validation.js explicitly allows this for any non-AA author) [1](#0-0) , which is processed and finally executed from `markMcIndexStable` → `stabilizeMci`, itself wrapped in a single `BEGIN…COMMIT` transaction [2](#0-1) .

Inside `countVotes`, for `op_list` the code computes the new OP list and immediately mutates the shared, long-lived in-memory array before the DB row is written: [3](#0-2) 

For the numeric subjects (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) the same pattern is used — `storage.systemVars[subject].unshift(...)` happens synchronously, well before the actual DB persistence: [4](#0-3) 

The DB write for both branches happens several lines later, as a separate `await conn.query(...)` call that can still throw (e.g. duplicate-key violation on `PRIMARY KEY (subject, vote_count_mci DESC)` if the same `(subject, mci)` pair is processed twice, or any other transient DB error): [5](#0-4) 

Because `storage.systemVars` is a process-global cache read directly by `getSystemVar()`/`getOpList()` without touching the DB [6](#0-5) , any consensus-critical decision made after the mutation but before (or instead of) a successful commit — witness list selection, `threshold_size`-based oversize-fee computation, TPS fee parameters — will use the new value even if the underlying transaction that was supposed to persist it is rolled back or throws before `COMMIT`. Unlike the AA state-var mechanism, which is deliberately made atomic via `SAVEPOINT`/`ROLLBACK TO SAVEPOINT` and an explicit `bBouncing` guard before any state mutation is flushed [7](#0-6) , this vote-counting cache has no equivalent rollback/rollback-guard: the in-memory array is never reverted if the surrounding transaction fails.

### Impact Explanation
If the DB write in `countVotes` fails after the in-memory `storage.systemVars` mutation (transaction rollback, thrown error caught upstream without process restart, or partial execution), the node continues to operate believing the new `op_list`/`threshold_size`/`base_tps_fee`/etc. are in effect while the persisted `system_vars` table still holds the old value. This produces exactly the class of harm called out in the rules: nodes can disagree on validity/witness selection (a node with the stale-but-cached OP list will validate/witness against a different active set than one that reloaded from DB, e.g., after a restart), and fee/threshold computations (`getOversizeFee`, TPS fee calculations) used throughout unit validation would diverge from the persisted ground truth — a consensus-relevant divergence that can partition nodes on validity of otherwise-identical units.

### Likelihood Explanation
The `system_vote_count` message can be posted by any unprivileged wallet address (not an AA) once system voting is active, satisfying the "unprivileged unit poster" trigger requirement. Reaching the actual DB-write failure requires an additional trigger (duplicate primary-key insert from a re-processed MCI, transient DB error, or any exception raised between the `unshift()` and the `INSERT/REPLACE` statement), which is a narrower window than the Furnace case (where any "frozen" call reliably reproduces the bug). This makes the likelihood Medium: the code path is reachable by ordinary users, but the divergence-causing failure additionally depends on a secondary DB error/exception occurring at the precise point between the cache mutation and the persisted write.

### Recommendation
Only mutate `storage.systemVars[subject]` after the corresponding `INSERT/REPLACE INTO system_vars` query has been confirmed successful (i.e., move the `unshift()` calls after the `await conn.query(...)` at the end of `countVotes`), or wrap the whole sequence so that any failure explicitly reverts the in-memory array (`shift()`/pop the just-added entry) before the error propagates, mirroring the SAVEPOINT/rollback discipline already used for AA state vars.

### Proof of Concept
1. An unprivileged address posts valid `system_vote` messages for `op_list` (or any numeric subject) followed by a `system_vote_count` message, both of which validation.js permits for ordinary authors [1](#0-0) .
2. When the MCI carrying that message stabilizes, `stabilizeMci` opens a transaction and calls `countVotes`, which computes the new value and immediately does `storage.systemVars.op_list.unshift(...)` (or `storage.systemVars[subject].unshift(...)`) [8](#0-7) [9](#0-8) .
3. If the subsequent `conn.query('INSERT ... INTO system_vars ...')` fails (e.g., a duplicate `(subject, vote_count_mci)` row already exists from a re-triggered vote count on the same MCI, or a transient DB failure) [5](#0-4) , and the surrounding transaction/error handling does not force a full process restart (which is the only mechanism that re-syncs `storage.systemVars` from `system_vars` via `initSystemVars`) [10](#0-9) , the node keeps operating with an in-memory `systemVars` value that was never actually committed to the database — causing it to diverge from nodes that reloaded from the (unchanged) DB state.

**Uncertainty note:** I was not able to fully trace, within the available iterations, the exact error-propagation path of `stabilizeMci`/`markMcIndexStable` (i.e., whether an exception thrown mid-transaction here is always caught by an outer handler that triggers a full process restart, which would re-sync `storage.systemVars` from disk and mask the bug in practice, or whether execution can continue with the stale in-memory cache). Confirming the exact reachability of the DB-write failure window and the surrounding error handling would benefit from starting a Devin session with full repository access.

### Citations

**File:** validation.js (L1913-1923)
```javascript
		case "system_vote_count":
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci && !constants.bDevnet)
				return callback("cannot count votes for system params yet");
			if (objValidationState.bAA)
				return callback("AA cannot trigger system vote count");
			if (objValidationState.bHasSystemVoteCount)
				return callback("can be only one system vote count");
			objValidationState.bHasSystemVoteCount = true;
			if (!["op_list", "threshold_size", "base_tps_fee", "tps_interval", "tps_fee_multiplier"].includes(payload))
				return callback("unknown subject in vote count");
			return callback();
```

**File:** main_chain.js (L1263-1276)
```javascript
async function stabilizeMci(mci) {
	const conn = await db.takeConnectionFromPool();
	await conn.query("BEGIN");
	const batch = kvstore.batch();
	const count_aa_triggers = await markMcIndexStable(conn, batch, mci);
	await util.promisify(batch.write.bind(batch))({ sync: true });
	await conn.query("COMMIT");
	conn.release();
	if (count_aa_triggers > 0) {
		console.log(`executing ${count_aa_triggers} AA triggers after stabilizing MCI ${mci}`);
		// every trigger takes its own db connection
		const aa_composer = require("./aa_composer.js");
		await aa_composer.handleAATriggers();
	}
```

**File:** main_chain.js (L1859-1876)
```javascript
			console.log(`total votes for OPs`, op_rows);
			let ops = op_rows.map(r => r.op_address);
			if (ops.length !== constants.COUNT_WITNESSES)
				throw Error(`wrong number of voted OPs: ` + ops.length);
			ops.sort();
			if (constants.bTestnet && [3547796, 3548896, 3548898].includes(mci)) // workaround a bug
				ops = ["2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX", "2GPBEZTAXKWEXMWCTGZALIZDNWS5B3V7", "4H2AMKF6YO2IWJ5MYWJS3N7Y2YU2T4Z5", "DFVODTYGTS3ILVOQ5MFKJIERH6LGKELP", "ERMF7V2RLCPABMX5AMNGUQBAH4CD5TK4", "F4KHJUCLJKY4JV7M5F754LAJX4EB7M4N", "IOF6PTBDTLSTBS5NWHUSD7I2NHK3BQ2T", "O4K4QILG6VPGTYLRAI2RGYRFJZ7N2Q2O", "OPNUXBRSSQQGHKQNEPD2GLWQYEUY5XLD", "PA4QK46276MJJD5DBOLIBMYKNNXMUVDP", "RJDYXC4YQ4AZKFYTJVCR5GQJF5J6KPRI", "WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"];
			if (mci === 0) {
				storage.resetWitnessCache();
				storage.systemVars.op_list = []; // reset
			}
			storage.systemVars.op_list.unshift({ vote_count_mci: mci === 0 ? -1 : mci, value: ops, is_emergency });
			value = JSON.stringify(ops);
			if (is_emergency) {
				storage.resetWitnessCache();
				await conn.query(conn.dropTemporaryTable(votes_table));
			}
			break;
```

**File:** main_chain.js (L1892-1903)
```javascript
			let accumulated = 0;
			for (let { value: v, total_balance } of rows) {
				accumulated += total_balance;
				if (accumulated >= total_voted_balance / 2) {
					value = v;
					break;
				}
			}
			if (value === undefined)
				throw Error(`no median value for ` + subject);
			storage.systemVars[subject].unshift({ vote_count_mci: mci, value, is_emergency });
			break;
```

**File:** main_chain.js (L1908-1912)
```javascript
	console.log(`new`, subject, value);
	// a repeated emergency vote on the same mci would overwrite the previous one
	await conn.query(`${is_emergency || mci === 0 ? 'REPLACE' : 'INSERT'} INTO system_vars (subject, value, vote_count_mci, is_emergency) VALUES (?, ?, ?, ?)`, [subject, value, mci === 0 ? -1 : mci, is_emergency]);
	await conn.query(conn.dropTemporaryTable('voter_balances'));
	eventBus.emit('system_vars_updated', subject, value);
```

**File:** storage.js (L1132-1141)
```javascript
function getSystemVar(subject, mci) {
	for (let { vote_count_mci, value } of systemVars[subject])
		if (mci > vote_count_mci)
			return value;
	throw Error(subject + ` not found for mci ` + mci);
}

function getOpList(mci) {
	return getSystemVar('op_list', mci);
}
```

**File:** storage.js (L2474-2484)
```javascript
async function initSystemVars(conn) {
	const rows = await conn.query("SELECT subject, value, vote_count_mci, is_emergency FROM system_vars ORDER BY vote_count_mci DESC");
	if (rows.length === 0)
		throw Error("no system vars");
	for (let { subject, value, vote_count_mci, is_emergency } of rows)
		systemVars[subject].push({ vote_count_mci, value: subject === 'op_list' ? JSON.parse(value) : +value, is_emergency });
	for (let subject in systemVars)
		if (systemVars[subject].length === 0)
			throw Error(`no ${subject} system vars`);
	console.log('system vars', systemVars);
}
```

**File:** aa_composer.js (L1759-1783)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
```
