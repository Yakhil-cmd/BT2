Confirmed: `system_vote` is an unprivileged message type any address can post (validated in `validation.js:1844-1911`), and votes are tallied using **current balance at counting time** rather than a balance snapshot taken when the vote was cast, per `countVotes()` in `main_chain.js:1737-1913`.

### Title
System-parameter vote tallying uses current balance instead of a vote-time snapshot, enabling last-minute vote-weight inflation - (File: main_chain.js)

### Summary
Ocore's on-chain governance for `op_list` (the 12 order/witness providers), `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` lets any address cast a `system_vote` message [1](#0-0) . When a vote count is triggered, `countVotes()` computes each voter's weight from their **current** unspent stable-good byte balance at the moment of tallying, not the balance held when the vote was originally cast [2](#0-1) . Analogous to the reported ERC20VotesUpgradeable removal, there is no historical balance checkpoint tied to the vote itself, so voting power can be manipulated between the time a vote is submitted and the time it is counted.

### Finding Description
`countVotes(conn, mci, subject, ...)` selects `DISTINCT address FROM system_votes WHERE subject=?` to determine who is eligible, then computes `voter_balances` as each address's current stable-good, unspent balance as of the MCI being stabilized: [3](#0-2) 

It then expands the counting window (`since_timestamp`) backward by whole years until enough share of `voter_balances` has an associated vote timestamp within the window: [4](#0-3) 

For `op_list`/numerical subjects, the tally sums `voter_balances` joined to the *latest* recorded vote per address, weighted by whatever balance that address happens to hold **right now**: [5](#0-4) 

Because the weight is bound to present-day balance rather than a balance recorded at (or shortly after) the moment the vote message was posted, an address can cast (or simply retain) an old, still-in-window vote and then acquire additional bytes just before the vote count executes, inflating its counted weight without needing to re-cast the vote. Since `since_timestamp` can stretch back multiple years (`since_timestamp -= 365*24*3600` repeatedly), an attacker's old, cheaply-cast vote from long ago remains eligible and its weight simply tracks the current balance, meaning the "vote" is really a standing proxy that silently re-weights itself as tokens move — this is the functional equivalent of the missing "historical balances so that voting power is retrieved from past snapshots" protection described in the external report.

### Impact Explanation
`op_list` directly determines the Order Provider / witness set that establishes DAG stability and the main chain, and `threshold_size`/`tps_*` parameters govern fee economics and throughput limits network-wide. If voting weight can be inflated at counting time (e.g., by concentrating coins into one voting address shortly before an emergency or scheduled vote count, then dispersing them again), an attacker with transient access to a large stake (e.g., via short-term acquisition or coordination) could push a malicious `op_list` or fee parameter into `system_vars`, which is consumed by every full node (`storage.getOpList`, `storage.systemVars`) for consensus-critical decisions such as witness selection and stability determination. This can lead to network-wide disagreement on validity/stability or degraded ability to confirm new units — a High/Critical impact class matching "node disagreement on validity or stability" / "network unable to confirm new units".

### Likelihood Explanation
Any address can submit `system_vote` messages at any time at negligible cost (a standard message type, no special privilege required) [1](#0-0) . The counting logic is deterministic and triggered by `system_vote_count` messages or emergency timeout [6](#0-5) , so the timing of a count is at least partially predictable/forceable, giving an attacker a window to move balance into a voting address just before tally. This requires capital (temporarily) but no protocol privilege, making it a realistic economic/governance-manipulation attack rather than a purely theoretical one.

### Recommendation
Snapshot each voter's balance at the time the `system_vote` unit becomes stable (or at vote-casting time) and store that snapshot balance alongside the vote in `system_votes`/`op_votes`/`numerical_votes`, instead of recomputing balance from current `outputs` at count time in `countVotes()`. This mirrors the OpenZeppelin `ERC20VotesUpgradeable` checkpoint approach the external report references, and prevents voting weight from being altered after a vote is cast.

### Proof of Concept
1. Attacker address A casts a `system_vote` for `op_list`/`threshold_size` while holding a small balance (cheap to do, and remains "in window" per the multi-year `since_timestamp` expansion logic in `main_chain.js:1807-1821`).
2. Shortly before a `system_vote_count` unit stabilizes (or before the `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` emergency path fires per `applyEmergencyOpListChange` in `main_chain.js:1936-1946`), the attacker consolidates a large amount of bytes into address A from other addresses/exchanges.
3. `countVotes()` computes A's `voter_balances` entry using A's now-large current balance [7](#0-6) , and this inflated weight is applied to A's old, cheaply-cast vote when tallying `op_list`/parameter medians [5](#0-4) .
4. After the count, the attacker disperses the bytes again, having influenced `system_vars` (e.g., `op_list`) with capital held only momentarily.

### Citations

**File:** validation.js (L1844-1859)
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
```

**File:** main_chain.js (L1741-1777)
```javascript
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

**File:** main_chain.js (L1850-1902)
```javascript
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
		
		case "threshold_size":
		case "base_tps_fee":
		case "tps_interval":
		case "tps_fee_multiplier":
			const rows = await conn.query(`SELECT value, SUM(balance) AS total_balance
				FROM numerical_votes
				CROSS JOIN voter_balances USING(address)
				WHERE timestamp>=? AND subject=?
				GROUP BY value
				ORDER BY value`,
				[since_timestamp, subject]
			);
			console.log(`total votes for`, subject, rows);
			const total_voted_balance = rows.reduce((acc, row) => acc + row.total_balance, 0);
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
