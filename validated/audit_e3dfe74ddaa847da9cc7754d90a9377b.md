## Analysis

The Salty.io finding is about a governance system that (1) snapshots a static `requiredQuorum` threshold at proposal-creation time but (2) tallies voting power dynamically from the voter's *current* stake balance at vote-casting/finalization time — letting a voter inflate their counted power after the threshold was already fixed, by staking/unstaking around the proposal window.

`ocore` has an analogous on-chain governance mechanism: `system_vote` / `system_vote_count`, which lets addresses vote (by posting `system_vote` messages) on system parameters (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`), tallied later by `countVotes()` in `main_chain.js`.

Critically, `countVotes()` does **not** snapshot a voter's balance at the time their vote (`system_vote`) was cast. Instead, when the count is finally executed (triggered by any `system_vote_count` message), it reads each voter's **current** byte balance as of the moment of counting: [1](#0-0) 

This balance — computed at count time, not vote time — is then used both to determine whether the `SYSTEM_VOTE_MIN_SHARE` quorum is met over an expanding lookback window, and to weight the tally itself (majority balance for numerical subjects, top balance sum for `op_list`): [2](#0-1) [3](#0-2) 

An address only needs to have cast a `system_vote` at some point within the lookback window (validated once at broadcast time in `validation.js`), and its weight is whatever its balance happens to be when `countVotes` executes — which can be triggered by anyone sending a `system_vote_count` message at will: [4](#0-3) 

This is exactly the "partial snapshot" bug class from the report: the vote timestamp/eligibility is locked in early, but the *voting power* is evaluated later from a mutable state (balance), so an attacker can:
1. Vote with a small balance (cheap, satisfies eligibility/timestamp requirements).
2. Later receive/acquire a large byte balance (e.g., a large self-transfer or exchange deposit) just before triggering `system_vote_count`.
3. Have that inflated balance counted for their earlier vote, tilting the median/majority for `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`, or the `op_list` witness selection — without needing broad community consensus.

This can let a single well-funded actor unilaterally push through a network-wide parameter change (e.g., set `base_tps_fee`/`tps_interval`/`tps_fee_multiplier` to disruptive values, or manipulate the elected order-provider list), which is a node-disagreement/consensus-parameter-integrity impact — matching the "Medium" bar (AA fund loss/freezing via fee manipulation, or network agreement issues) required by the validation rules.

### Title
Vote tally uses voter's balance at count-time rather than at vote-cast-time, allowing balance inflation to manipulate `system_vote` outcomes - (File: main_chain.js)

### Summary
`countVotes()` in `main_chain.js` computes each voter's weight from their *current* stable byte balance at the moment the count executes, not from the balance held when they cast their `system_vote`. Because counting can be triggered at will via a `system_vote_count` message, an address can cast a cheap early vote and later inflate its balance just before triggering the count, gaining outsized influence over system parameters (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`).

### Finding Description
`saveSystemVote()` records the vote with the timestamp of the unit that carried it, but no balance is snapshotted at that time [5](#0-4) . When counting happens, `countVotes()` selects the set of addresses that ever voted on the subject and then queries their balance from the current UTXO set: [6](#0-5) 

The counting is driven purely by which addresses are in `system_votes`/`numerical_votes`/`op_votes` within a lookback window starting at `since_timestamp`, expanding year-by-year until `SYSTEM_VOTE_MIN_SHARE` of `TOTAL_WHITEBYTES` participates: [2](#0-1) 

Then the vote is tallied by summing/median-ing the **current** `voter_balances`: [7](#0-6) 

Any address can send a `system_vote_count` message at any time to trigger this counting (subject only to the checks in `validation.js`) [4](#0-3) , and vote-counting for `op_list` can also be forced via the emergency path [8](#0-7) .

Because the balance used for the tally is read live at counting time rather than pinned to the vote's timestamp, a voter can:
1. Cast a `system_vote` with a small balance (satisfying eligibility cheaply).
2. Move/receive a large amount of bytes into that same address (a self-transfer is sufficient since only the address's balance matters, not the source).
3. Broadcast (or wait for someone else to broadcast) a `system_vote_count` message.
4. Have their old vote counted with the newly inflated balance, dominating the median/majority calculation for a numerical subject, or the top-`COUNT_WITNESSES` sum for `op_list`.

This mirrors the report's Attack Vector 1 (staking additional funds after the "proposal"/vote is created but before the vote power is locked in) — the counting mechanism is the analog of "finalize" in the Salty case, and it uses live balance instead of a value pinned at vote-creation time.

### Impact Explanation
An attacker with enough bytes (even temporarily, via a self-transfer just before counting) can single-handedly:
- Push `base_tps_fee`, `tps_interval`, or `tps_fee_multiplier` to disruptive values, causing AA/transaction fee miscalculation or network-wide fee/timing dislocation affecting all users and AAs.
- Manipulate the elected `op_list` (order providers/witnesses), affecting main-chain stability determination network-wide — a fundamental consensus parameter.

Because this changes global `system_vars` used by every node and every AA fee calculation, it is a network-wide integrity issue, not a self-harm-only action, satisfying the "concrete... node disagreement on validity or stability... network unable to confirm new units" bar from the validation rules (fee/tps parameter changes affect the entire network's ability to price and process units, and `op_list` capture affects main-chain stability consensus).

### Likelihood Explanation
Medium. It requires the attacker to accumulate/redirect a large enough byte balance right before triggering the count, and the `SYSTEM_VOTE_MIN_SHARE`/lookback logic provides some friction, but any address can trigger `system_vote_count` at will, and self-transfers to inflate balance right before counting are cheap and require no cooperation from other participants — unlike the honest quorum-building intended by the design.

### Recommendation
Snapshot each voter's stable balance at the time their `system_vote` (or the most recent update to it) is recorded, rather than reading it live during `countVotes()`. Store the balance alongside `unit`/`address`/`subject`/`value`/`timestamp` in `system_votes`/`numerical_votes`/`op_votes` at vote-insertion time (in `saveSystemVote`, using the balance as of that unit's `last_ball_mci`), and have `countVotes()` sum from that stored balance column instead of re-querying `outputs` for current balance. This prevents post-hoc balance inflation from influencing an already-cast vote.

### Proof of Concept
Conceptual PoC (cannot be executed without a live/test network, but the flow is fully supported by the code paths cited above):
1. Address A holds a small balance (e.g., 1000 bytes) and sends a `system_vote` message voting `tps_fee_multiplier = 1000` (the max allowed per validation) — this gets recorded in `numerical_votes` with A's vote timestamp [9](#0-8) .
2. Before any `system_vote_count` for `tps_fee_multiplier` executes, A receives a very large self-transfer (e.g., millions of bytes) increasing A's stable, unspent balance.
3. A (or anyone) broadcasts a `system_vote_count` message with `payload = "tps_fee_multiplier"`.
4. `countVotes()` queries A's balance live from `outputs`/`units` at that moment [10](#0-9) , using the inflated value to compute `SYSTEM_VOTE_MIN_SHARE` participation and the median value, giving A disproportionate influence over the resulting `tps_fee_multiplier` system variable [7](#0-6) .

### Citations

**File:** main_chain.js (L1619-1628)
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
```

**File:** main_chain.js (L1638-1646)
```javascript
										case "threshold_size":
										case "base_tps_fee":
										case "tps_interval":
										case "tps_fee_multiplier":
											await conn.query("DELETE FROM numerical_votes WHERE subject=? AND address IN (?)", [subject, author_addresses]);
											for (let address of author_addresses)
												sqlValues.push(`(${db.escape(unit)}, ${db.escape(address)}, ${db.escape(subject)}, ${value}, ${timestamp})`);
											await conn.query("INSERT INTO numerical_votes (unit, address, subject, value, timestamp) VALUES " + sqlValues.join(', '));
											break;
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
