## Analog Found

### Title
Flashloan-style manipulation of system-parameter and witness-list votes via transient balance inflation in `countVotes` — ([File: main_chain.js])

### Summary
The Derby report describes an attacker using a flashloan to temporarily inflate the funds used to weight a governance decision (protocol allocation), executing the borrow → vote/allocate → repay sequence atomically so the weighting reflects borrowed, not owned, capital. Ocore has a structurally identical weighting mechanism for its on-chain governance of `op_list` (the witness/order-provider list) and numeric network parameters (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`): a voter's influence is weighted by whatever *current* base-asset balance the counting query finds for their address at the moment the vote tally runs, not by a balance held continuously since the vote was cast.

### Finding Description
A `system_vote` message lets any non-AA address cast a vote for a subject/value pair, recorded in `system_votes`/`op_votes`/`numerical_votes` with only light payload validation and no balance or bond requirement at cast time [1](#0-0) . When a `system_vote_count` message stabilizes, `countVotes()` computes each voter's weight from a fresh query over the current UTXO set: the SUM of stable-good, base-asset outputs at that address that have no stable-good spender yet [2](#0-1) . This balance is looked up at counting time, completely independent of when or with what balance the address originally submitted its `system_vote`.

Because the query only excludes an output once a *stable* spending unit exists, any temporarily-received funds that are still only in an *unstable* return/repay transaction at the moment of counting are fully counted toward the voter's weight [3](#0-2) . This is the same pattern as the flashloan report: an address can (1) cast a cheap `system_vote` for a desired `op_list`/parameter value while holding little capital, (2) shortly before/at the MCI where `countVotes` executes for that subject, receive a large transient balance (e.g., via a loop of payments, an exchange withdrawal, or coordinated funding), (3) let that balance settle to stable+unspent status so it is captured in the `bal_rows` query, and (4) immediately spend it away again — the outgoing spend only removes it from future tallies once *that* spend itself becomes stable, which is after this MCI's count already happened. The vote-count trigger (`system_vote_count`) and the underlying balance are both attacker-controlled/timeable inputs, exactly mirroring the "call two functions atomically to exploit a balance snapshot" pattern in the Derby bug.

The affected subjects are directly security-critical: `op_list` selects the top `constants.COUNT_WITNESSES` order-provider addresses by summed voter balance [4](#0-3) , and the numeric subjects set the network's TPS-fee economics via a balance-weighted median [5](#0-4) .

### Impact Explanation
Manipulating `op_list` lets an attacker seat malicious or colluding addresses as order providers/witnesses, directly threatening main-chain stability determination and consensus (a "node disagreement on validity or stability" class impact). Manipulating `base_tps_fee`/`tps_interval`/`tps_fee_multiplier`/`threshold_size` can push network-wide spam-protection economics to values that either open the network to spam or price out legitimate users, degrading the network's ability to confirm new units. Both are high-severity governance-integrity issues even though they require some capital access to stage the transient balance.

### Likelihood Explanation
Exercising this requires the attacker to coordinate the timing of a temporary balance and the stabilization of a specific MCI, which is timing-sensitive but achievable since MCI stabilization and vote counting are deterministic and observable, and `system_vote`/`system_vote_count` are cheap, permissionless message types available to any address. The `SYSTEM_VOTE_MIN_SHARE` quorum-expansion loop [6](#0-5)  raises the bar somewhat (enough total voted balance must exist), but does not prevent a single well-funded voter's weight from being transiently inflated at the exact counting moment.

### Recommendation
Weight votes by a balance that cannot be manipulated by same-epoch transient transfers, e.g., use a time-averaged or minimum balance held continuously since the vote was cast (or since some lock-in period before the counting MCI) rather than the instantaneous "stable output with no stable spender" balance at counting time. Alternatively, require voters to lock/bond the balance backing their vote until after counting, so it cannot be borrowed and returned within the same counting window.

### Proof of Concept
1. Address A submits `system_vote` for `op_list` (or a numeric subject) while holding negligible balance; the vote is recorded in `system_votes`/`op_votes` (or `numerical_votes`) with no balance check [7](#0-6) .
2. Shortly before the target MCI (the one at which a `system_vote_count` unit will stabilize and trigger `countVotes` for that subject) stabilizes, A receives a large temporary payment that becomes a stable, unspent base-asset output.
3. `countVotes` runs at that MCI's stabilization and includes A's inflated balance in `voter_balances`, disproportionately swinging the `op_list` top-N selection or the numeric-subject median toward A's preferred value [8](#0-7) .
4. A immediately spends the borrowed funds onward; because that spending unit is not yet stable at count time, it did not reduce A's counted balance, completing the flashloan-style manipulation with no net capital committed.

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

**File:** main_chain.js (L1619-1646)
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
											break;
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

**File:** main_chain.js (L1752-1777)
```javascript
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

**File:** main_chain.js (L1850-1863)
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
```

**File:** main_chain.js (L1882-1903)
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
			if (value === undefined)
				throw Error(`no median value for ` + subject);
			storage.systemVars[subject].unshift({ vote_count_mci: mci, value, is_emergency });
			break;
```
