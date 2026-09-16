### Title
System votes for critical network parameters (op_list, threshold_size, base_tps_fee, etc.) are weighted by instantaneous balance snapshot rather than time-weighted average balance held during the voting window - ([File: main_chain.js])

### Summary
`countVotes()` in `main_chain.js` tallies `system_vote` messages for governance subjects (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) by weighting each voter's vote with a single, instantaneous balance read taken at the moment the counting MCI stabilizes, instead of a time-weighted average of the balance held by the voter over the whole voting window. This mirrors the Beanstalk Seed Gauge bug: using an instantaneous, manipulable balance snapshot instead of a time-integrated value to drive a protocol-critical parameter update.

### Finding Description
When a vote-count is triggered for a `subject` (e.g. `op_list`, which determines the Order Providers/witness list used for DAG stability, or `threshold_size`/`base_tps_fee`/`tps_interval`/`tps_fee_multiplier`, which govern fee and confirmation parameters), `countVotes()` collects every address that has ever cast a `system_vote` for that subject and looks up a single snapshot of each address's current spendable balance: [1](#0-0) 

That balance query sums currently-unspent, stable, good outputs for the address as of the moment the counting MCI becomes stable — it is not a time-weighted average of the balance the address held while its vote (cast at `timestamp`) was outstanding: [2](#0-1) 

The tally itself then multiplies each vote by this instantaneous balance to select the winning `op_list` (top-K addresses by summed balance) or the median value for numeric subjects: [3](#0-2) 

Because the weighting balance is read once, at count time, rather than integrated over the "since_timestamp" window that the code otherwise uses to select which votes are eligible, a voter's *current* balance — not the balance they actually held while the network relied on their vote — determines their influence. An address can cast (or already have cast) a `system_vote`, then shortly before the vote-counting MCI is expected to stabilize, receive a large payment (self-funded, borrowed, or via a cooperating counterparty) increasing its spendable balance, and move/spend the funds away again once the vote is counted and `system_vars` is written via `INSERT ... vote_count_mci` / `REPLACE`: [4](#0-3) 

This is directly analogous to the reported Beanstalk issue: Gauge Points (a supply-distribution parameter) were derived from the *instantaneous* deposited BDV at the moment `stepGauge` ran, rather than a time-weighted average over the prior period, enabling manipulation via a large deposit immediately before, and withdrawal immediately after, the triggering call. Here, `op_list`/`threshold_size`/`base_tps_fee` are derived from the *instantaneous* balance at the moment `countVotes` runs, rather than a time-weighted average balance held over the voting period, enabling manipulation via a large balance inflow immediately before, and outflow immediately after, vote counting.

### Impact Explanation
`op_list` directly replaces the witness list used to compute best-parent/witnessed-level and MC stability once `main_chain_index >= constants.v4UpgradeMci` (via `storage.getOpList`/`readWitnesses`), so a manipulated vote count can bias which addresses control DAG stability determination — a core consensus parameter. `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` directly control fee levels and the network's ability to process/confirm units under load. Corrupting any of these via balance-snapshot manipulation can bias witness/OP selection toward attacker-favorable or malicious addresses, or push fee parameters to disrupt normal confirmation — i.e., node disagreement on validity/stability or a network unable to confirm new units in the affected configuration.

### Likelihood Explanation
Vote counting occurs infrequently (only at specific mci events / emergency triggers), and normal (non-emergency) balance manipulation would require the attacker to have funds available and move them across confirmed, stable units around the exact counting MCI, which is easier to time-predict than an EVM same-block manipulation because stabilization is deterministic based on MC advancement, making the attack window somewhat more foreseeable than the analog Ethereum case. This raises likelihood relative to a strictly random trigger, though it still requires capital and correct timing to inflate balance right up to the snapshot and withdraw right after. Given `op_list`/fee-parameter votes are rare, security-sensitive events, even a single successful manipulation has outsized and durable effect (an OP list controls witnessing until the next vote), unlike Beanstalk's per-season, bounded ±1 point drift — the impact-per-manipulation here is proportionally higher, offsetting the lower attack frequency.

### Recommendation
Replace the instantaneous balance lookup in `countVotes()` with a time-weighted average balance of each voter computed over the full "since_timestamp" window (or at minimum over a fixed lookback preceding the count), analogous to the recommended mitigation in the report: track/accumulate balance-seconds per address (updating on every output-creating/spending event) and use that integral, sampled up to the end of the previous stable unit, to prevent last-moment balance injection from swaying `op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` votes.

### Proof of Concept
1. Address A casts a `system_vote` for `op_list` (or `base_tps_fee`, etc.) while holding a small balance, satisfying the minimum-share/eligibility scan in `countVotes` (`since_timestamp` loop): [5](#0-4) 
2. Shortly before the MCI at which `countVotes` will run (predictable by observing MC advancement / triggering conditions such as `applyEmergencyOpListChange`'s timeout check), address A receives a large payment output, inflating its balance as read by the `bal_rows` query: [6](#0-5) 
3. `countVotes` runs, weighting A's vote by this inflated balance, potentially tipping the top-K `op_list` selection or the numeric median toward A's chosen value: [3](#0-2) 
4. Once `system_vars` is updated, address A spends/moves the funds away, restoring its original low balance, having paid only transaction/timing cost for a durable change to a consensus-critical parameter: [4](#0-3)

### Citations

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

**File:** main_chain.js (L1801-1821)
```javascript
	await conn.query(`CREATE TEMPORARY TABLE voter_balances (
		address CHAR(32) NOT NULL PRIMARY KEY,
		balance BIGINT NOT NULL
	)`);
	await conn.query(`INSERT INTO voter_balances (address, balance) VALUES ` + values.join(', '));

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

**File:** main_chain.js (L1910-1912)
```javascript
	await conn.query(`${is_emergency || mci === 0 ? 'REPLACE' : 'INSERT'} INTO system_vars (subject, value, vote_count_mci, is_emergency) VALUES (?, ?, ?, ?)`, [subject, value, mci === 0 ? -1 : mci, is_emergency]);
	await conn.query(conn.dropTemporaryTable('voter_balances'));
	eventBus.emit('system_vars_updated', subject, value);
```
