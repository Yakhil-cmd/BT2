### Title
Governance vote-weight uses attacker-controllable "current balance at count time" instead of a locked balance-at-vote-time snapshot - ([File: main_chain.js])

### Summary
The Velodrome finding is a class of bug where reward/weight accounting uses a balance value sampled at the wrong instant (the boundary/first-second-of-next-epoch instead of the actual balance held during the period being rewarded), letting an attacker move funds in just before the snapshot to inflate their share and then move the funds away afterward. `countVotes()` in `main_chain.js` exhibits the same root-cause pattern for Obyte's system-variable governance votes (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`): a voter's influence is weighted by whatever balance they hold **at the moment the vote count executes**, not by a balance locked at the time the `system_vote` was posted.

### Finding Description
`countVotes()` collects every address that ever posted a `system_vote` for a subject, and then computes each voter's weight from their **current** stable, unspent, good balance: [1](#0-0) 

This balance is completely decoupled from the timestamp of the vote itself; `system_votes.timestamp` is only used to decide whether a vote falls inside the trailing lookback window (`since_timestamp`), not to determine how much balance backed the vote: [2](#0-1) [3](#0-2) 

`countVotes` is invoked once per MCI, right after all messages on that MCI are processed, whenever a `system_vote_count` message is included in a stabilizing unit: [4](#0-3) 

Because an unprivileged unit poster fully controls (a) when to post a `system_vote` and (b) when to post `system_vote_count` (or trigger the emergency path), and because the balance used is read live at count time rather than checkpointed at vote time, the attacker can:
1. Post a `system_vote` for a subject from an address holding a negligible balance (satisfying the "has voted" existence check).
2. Just before/at the MCI that will process `system_vote_count`, move a large payment balance into that same address (a same-block/adjacent-unit payment is trivial to construct and get included at the same MCI).
3. Let `countVotes` read the now-inflated balance for that address and count it in full toward the vote.
4. Move the funds back out (or to another address to repeat the trick for a different vote value) immediately afterward, since nothing locks the balance for the vote's duration.

This mirrors exactly the second and third abuse patterns in the reference report: "depositing a negligible amount... before attempting to deposit a larger amount" and reward/vote weight manipulation by injecting balance right at the snapshot boundary and withdrawing afterward, because the snapshot point does not correspond to the balance actually held throughout the voting period.

### Impact Explanation
`countVotes` sets binding, protocol-wide system variables: the operator/witness list (`op_list`), `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier`. An attacker who can cheaply inflate voting weight at the exact counting instant can bias or unilaterally decide these values (e.g., stack the `op_list` with attacker-controlled operators, or set fee parameters favorable to the attacker), which affects consensus-critical parameters for the whole network — this is a governance-integrity / fund-safety issue at the protocol level, not merely a UX bug.

### Likelihood Explanation
Exploitability depends on being able to move a large stable, unspent, non-private byte balance into the voting address in the same MCI window the count executes, and system-vote counting is not triggered every MCI (via `system_vote_count` message or the emergency path), so the attacker needs to control or predict the counting MCI. This is achievable by an unprivileged unit poster since `system_vote_count` and `system_vote` are ordinary messages sent by any address; the emergency path (`is_emergency`) uses `getUnstableVotes(emergency_count_command_timestamp)` and could shrink the window further. However, exploitation requires access to the vote-counting trigger timing and a chunk of liquid, stable balance, so likelihood is moderate rather than trivial, and I was not able to fully trace all callers of `countVotes` (e.g. the emergency invocation path in writer.js) within the available context, so the exact minimum time window for the flash-balance attack is not fully confirmed.

### Recommendation
Weight votes by the balance the voter actually held at (or continuously since) the time they cast their `system_vote`, not by the balance at count time. Concretely, checkpoint and store the voter's balance (or a balance history usable for point-in-time lookups, similar to the `getPriorBalanceIndex`/`supplyCheckpoints` pattern recommended in the reference fix) at the moment `system_votes` is written, and use that stored, immutable balance in `countVotes`'s `SUM(balance)` aggregations instead of live-querying current UTXOs. If a live balance must be used for efficiency, require a minimum holding-period (e.g., balance must have existed unchanged since some `min_mci`/`min_timestamp` before the count) to prevent same-block/near-instant balance injection from being counted.

### Proof of Concept
1. Attacker controls address `A` with balance ~0 and address `B` (funding source) with a large stable balance.
2. Attacker sends a `system_vote` message from `A` for `subject="op_list"` (or any numeric subject), satisfying `INSERT INTO system_votes` — this only requires posting one message, no balance check is enforced at vote time [5](#0-4) .
3. Shortly before the MCI where `system_vote_count` for that subject is expected to be processed, attacker sends a payment from `B` to `A`, getting it stable and "good" by the counting MCI.
4. `countVotes` executes, aggregates `A`'s now-large balance from `outputs`/`units` with `is_stable=1 AND sequence='good'` [6](#0-5)  and applies it in full to `A`'s vote in the `op_rows`/`rows` aggregation that determines the elected `op_list` or median numeric value [7](#0-6) .
5. Attacker moves the funds from `A` back to `B` (or another voting address) immediately after the count, repeating the process for subsequent counting rounds or other subjects, achieving outsized influence over consensus-critical system variables with only transient capital.

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

**File:** main_chain.js (L1657-1663)
```javascript
					async function() {
						// vote count must be processed last, after all system_votes, and once for the entire mci
						for (let subject of voteCountSubjects)
							await countVotes(conn, mci, subject);
						// next op
						updateRetrievable();
					}
```

**File:** main_chain.js (L1753-1777)
```javascript
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

**File:** main_chain.js (L1850-1899)
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
```
