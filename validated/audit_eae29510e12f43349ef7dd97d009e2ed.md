### Title
Unbounded voter-address set in `countVotes()` allows DoS of main-chain stabilization - (File: main_chain.js)

### Summary
`countVotes()` in `main_chain.js` counts votes on system parameters (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) by first pulling **every distinct address that has ever voted on a subject** from `system_votes`, with no cap on how many addresses that can be, then builds an in-memory JS string/array and a giant SQL `IN(...)` list from it before running further balance/vote aggregation queries. [1](#0-0) 

### Finding Description
Any unprivileged unit poster can cast a `system_vote` message from an arbitrary, freshly generated address — the only checks performed at validation time are on the payload shape (`subject`, `value`, sorted/valid `op_list`, numeric ranges), not on the number of distinct addresses that have voted for a subject: [2](#0-1) 

Because address generation is free and each new address is allowed exactly one row per `subject` in `system_votes` (`PRIMARY KEY (unit, address, subject)`), a low-cost attacker can post many minimal-fee units, each authored by a brand-new address, each casting a `system_vote`. Every vote from a stable unit is persisted into `system_votes` unconditionally in `saveSystemVote()`: [3](#0-2) 

When votes are finally tallied (via a `system_vote_count` command, processed once per MCI after stabilization in `markMcIndexStable`): [4](#0-3) 

`countVotes()` executes:
- `SELECT DISTINCT address FROM system_votes WHERE subject=?` with **no LIMIT**, growing linearly with the number of attacker-controlled voting addresses.
- Builds `strAddresses = addresses.map(db.escape).join(', ')` and interpolates it directly into a raw SQL query (`WHERE outputs.address IN(${strAddresses})`), and inserts every address/balance pair into a temporary table via a single `INSERT ... VALUES` statement built by string concatenation (`values.join(', ')`). [5](#0-4) 

This is functionally identical to the reported bug class: an unbounded, permissionlessly-growable collection (`system_votes` addresses, analogous to `marketsForPayout`/`marketsForQuote`) is iterated/embedded wholesale by a protocol-critical function, with no pruning or cap, so the cost of the operation scales with attacker-supplied inputs rather than with legitimate voter counts.

Unlike a purely client-side or peer-reachable DoS, `countVotes()` runs as part of `markMcIndexStable`, which is executed deterministically by **every full node** as the main chain advances past the MCI containing the `system_vote_count` command. This makes it a consensus-critical function, not an optional query — the audit rule explicitly reaches "DAG parents and stability" and "AA definitions/triggers" style protocol logic, and this is squarely in the unit-validation/stabilization path.

### Impact Explanation
If the address set for a subject grows large enough:
- The generated SQL string (`IN(${strAddresses})` and the `INSERT INTO voter_balances VALUES ...` list) can become extremely large, risking hitting SQL engine limits (e.g., SQLite's default `SQLITE_MAX_SQL_LENGTH` / max terms in a compound query, MySQL `max_allowed_packet`), causing the query to throw.
- Because `countVotes()` is `await`-ed synchronously inside `markMcIndexStable()`'s stabilization pipeline with no error containment shown here (any thrown/rejected promise propagates), a failure here would abort MC-index stabilization on **every node** that reaches this MCI, since all nodes process the same deterministic `system_votes` data at the same MCI. This can freeze main-chain stability progression, i.e. the network becomes unable to advance and confirm new units, matching the "network unable to confirm new units" acceptance criterion.
- Even short of an outright query failure, the unbounded work (single big query + big balance aggregation + big INSERT) executed once per node at a deterministic MCI is a shared, guaranteed cost that scales with attacker-controlled address count, which is a genuine resource-exhaustion vector distinct from ordinary spam (it specifically targets the vote-counting logic that determines `op_list`/witness set and TPS fee parameters).

### Likelihood Explanation
Likelihood is constrained by the cost of creating and funding enough distinct addresses to author enough `system_vote` units to blow up the address count, and by the fact that `system_vote_count` is a rare, deliberate trigger action, and vote-timeframe expansion logic partly self-limits by requiring a minimum voted balance share (`SYSTEM_VOTE_MIN_SHARE`) before the loop over years stops: [6](#0-5) 
However, address creation itself is free (no minimum balance is required merely to author a `system_vote` unit — only enough bytes to pay the tiny headers/payload commission), so the number of *distinct addresses* recorded in `system_votes` (which is what `countVotes` unconditionally loads and embeds into SQL) can be inflated cheaply regardless of the balance-share safety valve.

### Recommendation
- Cap the number of distinct addresses considered per subject in `countVotes()` (e.g., only the top-N addresses by balance, selected via SQL `ORDER BY balance DESC LIMIT N` before doing further aggregation), instead of loading every historical voter address unconditionally.
- Avoid building unbounded SQL strings via `.map(db.escape).join(', ')` / `values.join(', ')`; use parameterized `IN (?)` queries with driver-level array binding and enforce a hard maximum array size, returning a controlled error rather than allowing arbitrary growth to reach the query executor.
- Consider requiring a minimum stake/balance at the time a `system_vote` is cast (rather than only at counting time) so that low-value addresses cannot cheaply inflate the `system_votes` address cardinality.
- Ensure any failure inside `countVotes()` during `markMcIndexStable` is handled gracefully (e.g., retried with a bounded voter set) rather than being allowed to abort main-chain stabilization outright.

### Proof of Concept
1. Attacker generates a large number of throwaway addresses (only bytes-level fee needed per address to post a unit).
2. From each address, attacker posts a single, minimally-funded unit containing a valid `system_vote` message for the same `subject` (e.g., `threshold_size`), which passes all current validation checks in `validation.js` (subject/value type checks only, no cap on number of distinct voter addresses). [7](#0-6) 
3. Once these units stabilize, each address's vote is written unconditionally into `system_votes` via `saveSystemVote()`. [3](#0-2) 
4. When a `system_vote_count` command for that subject is next processed at MC stabilization, `countVotes()` loads `SELECT DISTINCT address FROM system_votes WHERE subject=?` — now containing every attacker address — and builds oversized SQL strings/`IN()` clauses and a bulk `INSERT ... VALUES` list sized to the attacker's chosen address count, executed by every node performing that stabilization step. [8](#0-7)

### Citations

**File:** main_chain.js (L1619-1636)
```javascript
								async function saveSystemVote(payload) {
									console.log('saveSystemVote', payload);
									const { subject, value } = payload;
									const objStableUnit = storage.assocStableUnits[unit];
									if (!objStableUnit)
										throw Error("no stable unit " + unit);
									const { author_addresses, timestamp } = objStableUnit;
									const strValue = subject === "op_list" ? JSON.stringify(value) : value;
									for (let address of author_addresses)
										await conn.query("INSERT INTO system_votes (unit, address, subject, value, timestamp) VALUES (?,?,?,?,?)", [unit, address, subject, strValue, timestamp]);
									let sqlValues = [];
									switch (subject) {
										case "op_list":
											const arrOPs = value;
											await conn.query("DELETE FROM op_votes WHERE address IN (?)", [author_addresses]);
											for (let address of author_addresses)
												sqlValues = sqlValues.concat(arrOPs.map(op_address => `(${db.escape(unit)}, ${db.escape(address)}, ${db.escape(op_address)}, ${timestamp})`));
											await conn.query("INSERT INTO op_votes (unit, address, op_address, timestamp) VALUES " + sqlValues.join(', '));
```

**File:** main_chain.js (L1656-1660)
```javascript
					},
					async function() {
						// vote count must be processed last, after all system_votes, and once for the entire mci
						for (let subject of voteCountSubjects)
							await countVotes(conn, mci, subject);
```

**File:** main_chain.js (L1737-1805)
```javascript
async function countVotes(conn, mci, subject, is_emergency = 0, emergency_count_command_timestamp = 0) {
	console.log('countVotes', mci, subject, is_emergency, emergency_count_command_timestamp);
	if (is_emergency && subject !== "op_list")
		throw Error("emergency vote count supported for op_list only, got " + subject);
	const address_rows = await conn.query("SELECT DISTINCT address FROM system_votes WHERE subject=?", [subject]);
	let addresses = address_rows.map(r => r.address);
	const unstable_votes = (is_emergency && mci >= constants.pemCurvesFixMci) ? getUnstableVotes(emergency_count_command_timestamp) : null;
	if (unstable_votes) {
		for (let { author_addresses } of unstable_votes) {
			for (let address of author_addresses)
				addresses.push(address);
		}
		addresses = _.uniq(addresses);
	}
	const strAddresses = addresses.map(db.escape).join(', ');
	let balances = {};
	// Count all stable-good outputs that have no stable-good spender.
	// This correctly handles outputs whose only spending unit was propagated to final-bad
	// (leaving is_spent=1 in the DB while no good unit claims the output), which the
	// previous two-query approach (bal_rows + spent_rows) silently undercounted.
	const bal_rows = await conn.query(`
		SELECT outputs.address, SUM(outputs.amount) AS balance
		FROM outputs
		JOIN units ON outputs.unit = units.unit
		WHERE outputs.address IN(${strAddresses})
			AND outputs.asset IS NULL
			AND units.is_stable = 1 AND units.sequence = 'good'
			AND NOT EXISTS (
				SELECT 1 FROM inputs
				JOIN units AS su ON inputs.unit = su.unit
				WHERE inputs.src_unit = outputs.unit
					AND inputs.src_message_index = outputs.message_index
					AND inputs.src_output_index = outputs.output_index
					AND su.sequence = 'good'
					AND su.is_stable = 1
			)
		GROUP BY outputs.address`);
	console.log('bal rows', bal_rows)
	for (let { address, balance } of bal_rows) {
		balances[address] = balance;
	}
	let values = [];
	for (let address in balances)
		values.push(`(${db.escape(address)}, ${balances[address]})`);
	if (values.length === 0)
		return console.log(`no voters for ${subject}, skipping vote count`);

	const [mc_row] = await conn.query("SELECT timestamp FROM units WHERE main_chain_index=? AND is_on_main_chain=1", [mci]);
	if (!mc_row)
		throw Error(`no MC unit on just stabilized MCI ` + mci);
	const mc_timestamp = mc_row.timestamp;
	
	const [activation_row] = await conn.query("SELECT timestamp FROM units WHERE main_chain_index=? AND is_on_main_chain=1", [constants.v4UpgradeMci]);
	if (!activation_row)
		throw Error(`no MC unit on OP vote activation MCI ` + constants.v4UpgradeMci);
	let activation_timestamp = activation_row.timestamp;

	if (mci >= constants.pemCurvesFixMci) {
		const [first_vote_row] = await conn.query("SELECT timestamp FROM system_votes WHERE subject=? ORDER BY timestamp ASC LIMIT 1", [subject]);
		if (!first_vote_row)
			throw Error(`no votes for subject ${subject}`);
		activation_timestamp = first_vote_row.timestamp;
	}

	await conn.query(`CREATE TEMPORARY TABLE voter_balances (
		address CHAR(32) NOT NULL PRIMARY KEY,
		balance BIGINT NOT NULL
	)`);
	await conn.query(`INSERT INTO voter_balances (address, balance) VALUES ` + values.join(', '));
```

**File:** main_chain.js (L1807-1821)
```javascript
	// Vote timeframe. If too small share has voted in the previous year, expand the period to 2 years. If still small, expand to 3 years, and so on.
	let since_timestamp = mc_timestamp;
	while (true) {
		since_timestamp -= 365 * 24 * 3600;
		if (since_timestamp <= activation_timestamp)
			break;
		const [{ total_balance }] = await conn.query(`SELECT SUM(balance) AS total_balance 
			FROM voter_balances
			WHERE address IN (
				SELECT DISTINCT address FROM system_votes WHERE subject=? AND timestamp>=?
			)`,
			[subject, since_timestamp]);
		if (total_balance >= constants.SYSTEM_VOTE_MIN_SHARE * constants.TOTAL_WHITEBYTES)
			break;
	}
```

**File:** validation.js (L1844-1867)
```javascript
		case "system_vote":
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci && !constants.bDevnet)
				return callback("cannot vote for system params yet");
			if (objValidationState.bAA)
				return callback("AA cannot cast system vote");
			if (objValidationState.bHasSystemVote)
				return callback("can be only one system vote");
			objValidationState.bHasSystemVote = true;
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["subject", "value"]))
				return callback("unknown fields in " + objMessage.app);
			if (typeof payload.subject !== "string")
				return callback("subject must be string");
			if (!payload.value)
				return callback("no value in " + objMessage.app);
			switch (payload.subject) {
				case "op_list":
					const arrOPs = payload.value;
					if (!isArrayOfLength(arrOPs, constants.COUNT_WITNESSES))
						return callback("OP list must be an array of " + constants.COUNT_WITNESSES);
					if (!arrOPs.every(isValidAddress))
						return callback("all OPs must be valid addresses");
					let prev_op = arrOPs[0];
```

**File:** validation.js (L1884-1892)
```javascript
				case "threshold_size":
					if (!isPositiveInteger(payload.value))
						return callback(payload.subject + " must be a positive integer");
					if (!constants.bTestnet || objValidationState.last_ball_mci > 3543000) {
						if (payload.value < 1000)
							return callback(payload.subject + " must be at least 1000");
					}
					callback();
					break;
```
