### Title
Governance vote weighting uses live balance at counting time instead of a snapshot at vote-cast time, enabling last-moment balance top-ups to bias `op_list`/system-parameter elections - (File: main_chain.js)

### Summary
The Alchemix report shows that `Bribe.totalVoting` is captured only when `distribute()` runs, so a deposit made just before that call — rather than a deposit held throughout the epoch — determines the weight used for reward distribution, letting an attacker manipulate the outcome by timing a deposit. The analogous weakness in ocore is in `countVotes()`: witness-list (`op_list`) and numerical system-variable (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) elections weight each voting address by its **current** byte balance measured at the moment the electing MCI stabilizes, not by the balance the address actually held while its vote was outstanding.

### Finding Description
`countVotes()` selects every address that ever cast a `system_vote` for a subject, then computes each address's balance live, at count time: [1](#0-0) 

This balance query (`bal_rows`) sums all currently-unspent stable-good outputs for the voter addresses **at the time `countVotes` executes** (triggered when the MCI containing the `system_vote_count` message stabilizes), not at the time each address's vote (`system_vote` message) was posted: [2](#0-1) 

The resulting `voter_balances` temporary table is then joined against `op_votes`/`numerical_votes` to compute `SUM(balance)` per candidate/value and pick the winner: [3](#0-2) 

Nothing in `validateInlinePayload`'s `system_vote` handling, nor in `countVotes`, requires that the balance being counted was held continuously since the vote was cast, or averages the balance over the voting window. An address can cast a `system_vote` (op_list or a numerical subject) while holding a trivial balance, and then — timed to land before the MCI that triggers `system_vote_count` becomes stable — receive/self-transfer a large amount of bytes. That transient balance is what gets counted as "voting power" once `countVotes` runs, exactly mirroring the reported bug class where `Bribe.totalVoting`/reward share is fixed by whatever state exists at the instant the periodic aggregation function executes, rather than by sustained participation.

Because `system_vote_count` executes deterministically as part of MCI stabilization (`markMcIndexStable` → `countVotes`), and unit authors control both the timing of their `payment` (balance top-up) and their prior `system_vote`, and unit ordering within/around an MCI is attacker-influenced (an attacker chooses when to post the balance-increasing unit relative to the main chain's progress), the same "deposit right before the aggregation point" technique from the Alchemix report applies directly here.

### Impact Explanation
`op_list` determines the set of order-providing witnesses used to determine the main chain and unit stability; `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` are consensus-critical network parameters stored in `system_vars` and read by all full nodes. If an attacker can inflate their counted voting weight via a momentary balance spike instead of genuinely sustained economic stake, they can bias these elections disproportionately to their real, held stake — this is a direct manipulation of a governance vote's outcome (the same impact category flagged in the source report), and because `op_list`/system vars affect what every node treats as valid/stable, a successfully skewed election can cause different nodes to diverge on which witness list or fee/threshold parameters are canonical, risking disagreement on validity/stability of the DAG.

### Likelihood Explanation
Exploitation requires the attacker to control the precise timing of when a payment unit that increases their balance becomes part of the DAG relative to the MCI that will trigger `system_vote_count`/stabilization — this is influenced by, but not perfectly deterministic under, an attacker's control of unit posting and DAG growth, and the `SYSTEM_VOTE_MIN_SHARE` (10% of `TOTAL_WHITEBYTES`) participation threshold in `countVotes` raises the capital bar for `op_list`/numeric elections to actually flip outcomes. This makes it a Medium-likelihood issue rather than trivially or continuously exploitable, but the underlying design flaw (weighting by point-in-time balance rather than a stake-holding-period snapshot) is concretely present and reachable by any unprivileged address that posts `system_vote` and payment units.

### Recommendation
Snapshot/weight voter balance based on holdings at (or continuously since) the time each `system_vote` unit's MCI, rather than re-querying live balances at the moment `countVotes` executes — e.g., use the balance as of the vote's own `last_ball_mci`/timestamp, or require the balance to have been held for a minimum duration prior to the count, similar to time-weighted voting designs used to defeat flash-balance vote manipulation.

### Proof of Concept
Conceptual reproduction path (mirrors the reported PoC's "deposit before distribute" sequencing) — could not be executed against a live/testable node with the tools available, so this is presented as a reachability walkthrough rather than an executed exploit:
1. Attacker address `A` posts a `system_vote` unit for subject `op_list` (or a numerical subject) while holding a minimal balance — recorded via `saveSystemVote` into `system_votes`/`op_votes`/`numerical_votes`, keyed only by address, not by balance at vote time: [4](#0-3) 
2. Shortly before the MCI carrying a `system_vote_count` command becomes stable, `A` receives (or self-sends) a large byte payment, inflating `A`'s current stable-good, unspent balance.
3. When that MCI stabilizes, `markMcIndexStable` invokes `countVotes(conn, mci, subject)`, which queries `A`'s balance live via the `bal_rows` query and uses it to weight `A`'s previously-cast vote: [1](#0-0) 
4. `A`'s vote is now counted with the inflated balance in the `SUM(balance)` aggregation that selects the winning `op_list`/numeric value: [3](#0-2) 
5. `A` can move the funds away immediately after the count, having paid only transaction fees for the temporary balance window, while having swayed a governance outcome disproportionately to sustained stake.

### Citations

**File:** main_chain.js (L1622-1650)
```javascript
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
