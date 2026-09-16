### Title
Governance vote weighting uses balance-at-count-time instead of balance-at-vote-time, allowing transient balance inflation to hijack `op_list`/system parameter votes - (File: main_chain.js)

### Summary
The `countVotes` function in `main_chain.js`, which tallies `system_vote` messages to determine the witness list (`op_list`) and other consensus parameters (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`), weights every counted vote by the voting address's **current** GBYTE balance at the moment the tally runs, not by the balance the address held when it cast the vote. This mirrors the reported bug class in the external report: rewards/voting power computed from a point-in-time balance snapshot rather than a balance that was actually held for the relevant period, letting an attacker who transiently inflates their balance just before the snapshot capture a disproportionate share of influence, then move the funds away immediately afterward.

### Finding Description
Any address can post an `app: 'system_vote'` message in a unit. Once the unit stabilizes, `saveSystemVote` records the vote in `system_votes` and updates the "latest vote" tables `op_votes` / `numerical_votes`, keyed only by `(address, subject)`: [1](#0-0) 

When a `system_vote_count` command later stabilizes, `countVotes` computes the weight of every historical voter for that `subject` using their **balance at the time the query runs**, not their balance when the vote was cast: [2](#0-1) 

The `since_timestamp` expanding window is used only to decide *which* voter addresses' latest votes are eligible (based on the timestamp of their last vote), while the actual voting *weight* applied is always `voter_balances.balance`, sourced from the address's stable-good unspent outputs at the moment of counting: [3](#0-2) [4](#0-3) [5](#0-4) 

Because the address list, once it has ever voted, remains eligible for as long as its vote timestamp falls within the (possibly multi-year) lookback window, an attacker only needs one previously-cast vote to remain "active." The attacker can then, right before a `system_vote_count` unit stabilizes, receive a large GBYTE payment into the voting address, let it become stable, have it counted at full weight in `countVotes`, and immediately spend/transfer the funds away afterward — never having held the balance for any meaningful duration, and without the funds being tied up during the voting period itself. This is the on-chain governance analogue of the TroveManager exploit: reward/weight calculated from an instantaneous, manipulable balance query rather than a duration/time-weighted stake.

### Impact Explanation
`op_list` votes directly determine the witness set that anchors main-chain stability and consensus in ocore, and the numerical votes control critical network parameters (fee formulas, TPS thresholds). An attacker able to cheaply and transiently inflate their counted balance at exactly the moment `countVotes` executes can bias or seize control of the witness list or fee/consensus parameters without long-term economic commitment, directly enabling the "node disagreement on validity/stability" and "network unable to confirm new units" impact categories: a maliciously composed `op_list` can partition consensus or degrade the network's ability to reach stability, and manipulated fee/TPS parameters can be weaponized for spam or fee-based DoS.

### Likelihood Explanation
Posting `system_vote` messages is permissionless and reachable by any unprivileged unit poster; no minimum holding period or time-weighting is enforced on the counted balance. The only friction is: the attacker must already have one recorded vote for the targeted subject within the applicable lookback window, and must time the balance inflow to land as a stable-good output before the `system_vote_count` unit they (or anyone) triggers becomes stable. Both are within reach of a single actor coordinating payment timing with vote-count triggering, making this practically exploitable, though it requires enough capital (even briefly) to outweigh legitimate voters — similar to the flash-loan-style capital requirement described in the original report.

### Recommendation
Compute voting weight from the balance the address actually held at (or held continuously through) the time of the vote, e.g., by recording and using the balance at vote-cast time (already available via `last_ball_mci`/stable-good balance at that MCI) instead of re-querying current balance at count time, or by requiring a minimum holding/lock period before a balance snapshot counts toward `countVotes`. Alternatively, use a time-weighted average balance over the eligibility window rather than a single point-in-time balance.

### Proof of Concept
Conceptually (no dedicated ocore governance test harness was found in the indexed files to produce a runnable script):
1. Address `A` casts a `system_vote` for `op_list` (or a numerical subject) at time `T0`, establishing an entry in `op_votes`/`numerical_votes` with `timestamp=T0` and `system_votes` log — this keeps `A` in the eligible address set indefinitely (subject to the expanding lookback window).
2. At a later time `T1`, shortly before a `system_vote_count` unit for that subject is expected to stabilize, `A` receives a large GBYTE payment (e.g., from an exchange or DEX swap-back) into a stable-good, unspent output.
3. When `countVotes` runs (main_chain.js:1737-1909), the `bal_rows` query computes `A`'s balance as of `T1`'s large deposit (per [6](#0-5) ), and this inflated balance is used as `A`'s full voting weight for the (possibly stale) vote cast at `T0`.
4. `A` immediately spends/transfers the funds out in the next unit, incurring no real illiquidity cost, while having swung the `op_list`/parameter tally with the temporarily inflated stake.

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

**File:** main_chain.js (L1850-1858)
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
```

**File:** main_chain.js (L1882-1899)
```javascript
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
```
