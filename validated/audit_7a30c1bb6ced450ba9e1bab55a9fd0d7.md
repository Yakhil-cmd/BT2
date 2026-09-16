### Title
Governance vote weight is snapshotted at count-time instead of vote-time, allowing flash-balance manipulation of `op_list`/network-parameter votes - ([File: main_chain.js])

### Summary
Obyte's on-chain governance (`system_vote` / `system_vote_count` messages) elects the order-providers (`op_list`) and sets core network parameters (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) by weighting each voter's ballot with that voter's **current** base-asset balance, read fresh at the moment the vote is counted, not the balance held when the vote was cast or held for any minimum duration. This mirrors the RocketPool bug class: a "reward"/influence metric is computed from a point-in-time snapshot rather than time-weighted stake, so anyone can inflate their balance immediately before the counting trigger fires and withdraw it immediately afterward, at zero cost of capital lock-up (worse than RocketPool's 14-day stake lock, since here there is no lock at all).

### Finding Description
Any unprivileged address can post a `system_vote` message (validated in `validation.js` around the `case "system_vote":` block) to record a vote for `op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, or `tps_fee_multiplier`, and later a `system_vote_count` message that triggers tallying via `countVotes()`: [1](#0-0) 

The tally reads the **current** unspent balance of every address that has ever voted, at the exact moment the counting unit stabilizes — not the balance the voter held when casting the vote: [2](#0-1) 

This balance table (`voter_balances`) is then joined against `op_votes` / `numerical_votes` to compute the winning `op_list` (weighted by summed balance per candidate) and the median value for numerical parameters: [3](#0-2) [4](#0-3) 

Because the weight is derived from `outputs`/`units` state as of the counting MCI rather than from a balance frozen at the time of the `system_vote`, a voter's influence is unpredictable and can be inflated arbitrarily right before the count: the voter (or a collaborator) can send themselves a large amount of bytes just before the `system_vote_count` unit becomes stable, then move the funds away immediately afterward, exactly analogous to RocketPool's "add stake just before `claim()`" front-running issue, but with no lock-up requirement whatsoever (Obyte funds are fully liquid and can be moved in/out within the same MCI window).

### Impact Explanation
- `op_list` governs the actual order-providers/witnesses that establish main-chain ordering and stability; manipulating its election lets a well-funded but otherwise uninvolved actor push their own or colluding addresses into the OP set, directly threatening consensus on validity/stability of the network (a listed unacceptable-but-critical outcome: "node disagreement on validity or stability").
- `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` govern fee economics and throughput; skewing their median can be used to grief the network's fee market or throughput limits network-wide, again a systemic parameter affecting the ability of the network to confirm units economically.
- Unlike RocketPool's variant (where at least a 14-day RPL lock and Minipool creation cost is required), here the "stake" (byte balance) requires no lock-up at all — the attacker can flash the balance in and out within the same block/MCI window, making the attack cheaper and more repeatable.

### Likelihood Explanation
Exploitability depends on being able to time balance inflows so they are reflected as stable, unspent outputs at the exact MCI when `system_vote_count` stabilizes, and on economic capital to temporarily hold a large byte balance (loan/flash-style capital is feasible on Obyte since bytes are the base asset and highly liquid). No special privilege is required — any unit poster can submit `system_vote` and `system_vote_count`. The main practical constraint is timing precision around MCI stabilization and coordination with the counting trigger, which is a general engineering/timing challenge rather than a cryptographic or protocol barrier.

### Recommendation
Weight votes by the balance the voter held at (or for a sustained period leading up to) the time of casting the `system_vote`, not by a balance re-read at count time. Options:
- Snapshot and store the voter's balance at the moment the `system_vote` unit becomes stable (similar to how `earned_headers_commission_recipients` freezes distribution shares at unit-creation time), and use that stored snapshot in `countVotes()`.
- Alternatively, require a minimum holding duration (e.g., balance held stable for N days prior to the vote) analogous to the RocketPool fix requiring RPL to be locked before it counts toward stake, rather than re-querying live balances at arbitrary future counting moments.

### Proof of Concept
1. Attacker address `A` casts a `system_vote` for `op_list` (or a numerical subject) with a small existing balance, so the vote is recorded in `system_votes`/`op_votes`.
2. Shortly before a `system_vote_count` unit for that subject is posted and becomes stable, attacker transfers a very large amount of bytes into `A` (or spends from a temporarily large holding).
3. When `countVotes()` runs at MCI stabilization, `main_chain.js:1751-1777` sums `A`'s current unspent good outputs — including the just-added large balance — into `voter_balances`, giving `A`'s prior vote outsized influence on the OP list election or numerical-parameter median.
4. Immediately after the count, attacker moves the funds back out of `A`, restoring the original balance, at negligible cost besides transaction fees, having achieved the desired swing in `op_list`/parameters.
5. This can be repeated for each subsequent `system_vote_count`, similar to the RocketPool exploit sequence of staking-just-before-`claim()`-then-withdrawing.

### Citations

**File:** main_chain.js (L1737-1741)
```javascript
async function countVotes(conn, mci, subject, is_emergency = 0, emergency_count_command_timestamp = 0) {
	console.log('countVotes', mci, subject, is_emergency, emergency_count_command_timestamp);
	if (is_emergency && subject !== "op_list")
		throw Error("emergency vote count supported for op_list only, got " + subject);
	const address_rows = await conn.query("SELECT DISTINCT address FROM system_votes WHERE subject=?", [subject]);
```

**File:** main_chain.js (L1751-1777)
```javascript
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

**File:** main_chain.js (L1878-1899)
```javascript
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
