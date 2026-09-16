### Title
Governance vote weight is calculated from an instantaneous balance snapshot, letting an attacker briefly park bytes to manipulate `op_list`/system-parameter votes - (File: `main_chain.js`)

### Summary
`countVotes()` calculates a voter's influence over on-chain governance (the `op_list` of Order Providers/witnesses, and numeric system parameters like `base_tps_fee`, `threshold_size`, `tps_interval`, `tps_fee_multiplier`) purely from the address's *current* stable-good byte balance at the exact MCI the vote is tallied, not from balance held throughout the intended voting period. This is the same bug class as "timing stakes around an off-chain snapshot": a user can move a large balance into a voting address immediately before the counting MCI, have their vote fully counted with that weight, then move the funds away right after — capturing outsized governance influence without ever bearing the economic exposure the stake-weighted design intends.

### Finding Description
`countVotes(conn, mci, subject, ...)` is invoked once a `system_vote_count` message becomes stable at MCI `mci` [1](#0-0) . It computes each voting address's weight as its current unspent, stable-good, base-asset balance: [2](#0-1) 

This balance is stored into a temporary `voter_balances` table and used directly to weigh both the OP-list vote and numeric system-var votes: [3](#0-2) [4](#0-3) 

The only temporal control is `since_timestamp`, which filters *which votes* are counted (expanding the window until enough voting weight participated), but it does **not** require that a voting address's balance was actually held throughout that window — only that the address cast (or previously cast, and never overrode) a `system_vote` before `since_timestamp`. The comment in the schema confirms the counting semantics are point-in-time: "Votes are counted after the MCI is completed... All votes and balance updates up to and including this MCI are taken into account" [5](#0-4) .

`system_vote` messages themselves are ordinary unit messages any address can post (recorded in `system_votes`/`op_votes`/`numerical_votes`, with a new vote from the same address overriding the prior one) [6](#0-5) . A `system_vote_count` message from any unit author schedules the tally for whatever MCI stabilizes it [7](#0-6) .

Because the weight is read fresh from `outputs` at tally time rather than from a time-integrated or minimum-holding-period balance, an attacker can:
1. Post (or have previously posted and left standing) a `system_vote` for `op_list` (or a numeric subject) from address A.
2. Shortly before a `system_vote_count` unit is expected to stabilize, transfer a large amount of bytes into A (e.g., via a same-block payment, DEX swap, or looping funds from another address the attacker controls).
3. Once the count executes at that MCI, A's vote is weighted by the inflated balance.
4. A moves the funds back out immediately afterward.

This is functionally identical to the reported vulnerability class: gaming a periodic, deterministic "snapshot" event by timing capital around it, rather than genuinely holding the asset that the mechanism is meant to measure.

### Impact Explanation
`op_list` directly determines the Order Providers (successor mechanism to witnesses) that anchor main-chain stability and unit ordering; the numeric subjects (`base_tps_fee`, `threshold_size`, `tps_interval`, `tps_fee_multiplier`) govern network-wide fee/congestion economics. Because voting weight can be manufactured transiently instead of reflecting genuine sustained stake, an attacker with temporary access to a large amount of bytes (their own liquidity, a flash-style transfer, or coordinated timing with an exchange withdrawal) can disproportionately sway who becomes an Order Provider or what fee parameters apply, without the capital lock-up the plutocratic voting model is designed to require. A manipulated `op_list` is a node-disagreement/consensus-integrity risk: it changes which addresses control main-chain progression and stability determination network-wide.

### Likelihood Explanation
Reachable by any unprivileged address that can post ordinary units (`system_vote` and `system_vote_count` app messages) — no operator or node privileges are required. The only obstacles are (a) needing enough transient balance to meaningfully move `since_timestamp`-window totals above `SYSTEM_VOTE_MIN_SHARE * TOTAL_WHITEBYTES`, and (b) predicting/timing when the count MCI stabilizes, which is feasible since `system_vote_count` is itself an ordinary message the attacker (or a colluding party) can post to trigger the tally right after inflating the balance.

### Recommendation
Weight votes by a time-integrated or minimum-holding-duration balance (e.g., average balance held over the entire `since_timestamp` window, or require the balance to have existed continuously since some point before the vote), rather than the balance at the single counting MCI. Alternatively, snapshot balances at multiple historical points across the voting window and use the minimum, so momentary balance inflation cannot dominate the tally.

### Proof of Concept
1. Address A posts a `system_vote` for `op_list` (or a numeric subject) with a small balance; this is stored in `system_votes`/`op_votes` (or `numerical_votes`) per `main_chain.js:1619-1650`.
2. Shortly before a `system_vote_count` unit for that subject is expected to stabilize, the attacker sends a large payment of bytes into A from another address they control (or via a swap), so A now shows a large stable-good, unspent balance.
3. A `system_vote_count` message becomes stable at MCI `mci`; `countVotes()` runs and computes A's `voter_balances` weight from the current `outputs` state per `main_chain.js:1752-1777`, without checking whether A held this balance earlier in the `since_timestamp` window (`main_chain.js:1807-1821`).
4. A's oversized vote is included in the `op_rows`/numeric aggregation and can tip the outcome of `op_list` or a numeric system variable (`main_chain.js:1850-1902`).
5. Immediately after the count, the attacker moves the funds out of A, having captured outsized governance influence for only the duration needed to span one MCI's stabilization.

### Citations

**File:** main_chain.js (L1572-1578)
```javascript
											case 'system_vote':
												await saveSystemVote(payload);
												break;
											case 'system_vote_count': // will be processed later, when we finish this mci
												if (!voteCountSubjects.includes(payload))
													voteCountSubjects.push(payload);
												break;
```

**File:** main_chain.js (L1619-1650)
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
										default:
											throw Error("unknown subject after stability: " + subject);
									}
									eventBus.emit('system_var_vote', subject, value, author_addresses, unit, 1);
```

**File:** main_chain.js (L1657-1665)
```javascript
					async function() {
						// vote count must be processed last, after all system_votes, and once for the entire mci
						for (let subject of voteCountSubjects)
							await countVotes(conn, mci, subject);
						// next op
						updateRetrievable();
					}
				);
			}
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

**File:** initial-db/byteball-mysql.sql (L970-978)
```sql
-- new record added after system_vote_count. Votes are counted after the MCI is completed, therefore counted only once per MCI even if there are two system_vote_count commands on this MCI. All votes and balance updates up to and including this MCI are taken into account, even if they happen after system_vote_count on its MCI.
CREATE TABLE system_vars (
	subject VARCHAR(50) NOT NULL,
	value TEXT NOT NULL,
	vote_count_mci INT NOT NULL, -- applies since the next mci
	is_emergency TINYINT NOT NULL DEFAULT 0,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (subject, vote_count_mci DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```
