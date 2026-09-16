### Title
System-parameter and OP-list votes are weighted by the voter's balance *at count time*, allowing transient balance inflation to hijack governance outcomes - ([File: main_chain.js])

### Summary
`ocore`'s on-chain governance for `op_list` (witness/order-provider list), `threshold_size`, `base_tps_fee`, `tps_interval` and `tps_fee_multiplier` works exactly like the Pyth-governance pattern flagged in the external report: a voter's influence is derived from a balance that can be read at one point in time (vote-count time) even though the "vote" itself was cast earlier, with no lock, no snapshot-at-vote-time, and no minimum holding period. Any unprivileged unit poster can register as a voter with a trivial `system_vote` message and later — right before someone (anyone) submits a `system_vote_count` trigger — receive a large, temporary transfer of bytes into the voting address, inflating the tallied weight of their (old, already-registered) vote, then move the funds back out immediately afterward.

### Finding Description
Votes are recorded permanently in `system_votes`/`op_votes`/`numerical_votes` when a `system_vote` message stabilizes [1](#0-0) . Counting happens later, whenever any (unprivileged) unit contains a `system_vote_count` message and that unit's MCI stabilizes [2](#0-1) [3](#0-2) .

The weight used to tally the vote is *not* the balance the voter held when casting the `system_vote`, nor a snapshot fixed at that time — it is the address's live GBYTE balance, queried fresh at the moment `countVotes()` executes: [4](#0-3) 

This balance is then multiplied against every historical vote from that address that falls in an expanding lookback window (`since_timestamp`), and the window only expands based on the *aggregate* weight, never validating that any individual voter's balance corresponds to when they actually voted: [5](#0-4) 

For `op_list`, the address's `op_address` votes accumulated over the lookback window are summed by current balance and the top `COUNT_WITNESSES` win: [6](#0-5) 

For numeric subjects (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) a weighted median is computed the same way, using current balance as weight: [7](#0-6) 

Crucially, `system_vote_count` can be triggered by **any non-AA author** — there is no restriction to OPs, witnesses, or the original voter: [2](#0-1) 

This is structurally identical to the reported bug class: a resolution threshold/outcome is computed from a balance/supply figure that can differ between the time a "vote" is cast and the time it is finally used to resolve/settle the outcome, and nothing pins the weight to the moment of voting or requires the balance to have been locked/held continuously.

### Impact Explanation
An attacker who has ever cast one `system_vote` (a trivial, cheap unit) permanently owns a voting slot for that subject. To exploit:
1. Register the voting address once with a `system_vote` for `op_list` (or any numeric subject) — this is a `system_vote` recorded in `system_votes`/`op_votes`/`numerical_votes` forever, regardless of balance at the time.
2. Wait for (or induce) a `system_vote_count` trigger unit to be composed.
3. Just before/while that trigger unit's MCI stabilizes, receive a large temporary transfer of bytes into the voting address (e.g., a counterparty loan, an atomic swap, or self-funding from another address), so the balance read by `countVotes()` is far larger than the attacker's genuine long-term holdings.
4. After the count executes and `system_vars` (or `op_list`) is updated, move the funds back out.

Because the tally uses "current balance" as weight for votes cast at any time within the lookback window, this lets an attacker with only a small fraction of true, sustained GBYTE ownership sway:
- `op_list` — the witness/order-provider set that underpins main-chain stability and consensus on unit validity; a manipulated `op_list` is a direct path to **node disagreement on validity/stability** or handing control of the network's ordering nodes to an attacker.
- `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`, `threshold_size` — core fee/throughput parameters; an attacker could drive fees to extremes or manipulate the flood-protection threshold, potentially rendering the **network unable to confirm new units economically** or causing fee/consensus-parameter disputes across nodes.

This is a Medium/High-severity governance-integrity issue: it undermines the "one byte, one (persistent) vote" assumption of the whole system-vote mechanism using only a temporary balance, not a genuine stake.

### Likelihood Explanation
- `system_vote` and `system_vote_count` are ordinary, unprivileged messages any wallet can post; no OP/witness/AA privilege required [2](#0-1) .
- The count logic performs a single, synchronous balance query with no historical/locked-balance requirement outside the emergency `op_list` path (`EMERGENCY_COUNT_MIN_VOTE_AGE` only guards the emergency-unstable-vote branch, not the normal stable-balance weighting) [8](#0-7) .
- Executing the attack requires only that a large balance be stable at the exact MCI that stabilizes the `system_vote_count` trigger, which is achievable by controlling both the funding transaction and the trigger unit's timing (attacker can submit both).
- The main friction is coordinating "receive funds → wait for stabilization of the count-trigger MCI → withdraw", but this is materially easier than the original Pyth PoC (no burn/loss of funds is even required — a temporary loan/swap suffices), making this arguably *more* practically exploitable than the reference bug.

### Recommendation
- Snapshot each voter's balance at the time the `system_vote` is cast (or at a fixed, pre-announced MCI) and store it alongside the vote, instead of re-reading current balance at count time.
- Alternatively, require votes to reflect balance sustained over the entire lookback window (e.g., minimum time-weighted average balance, or balance held continuously since the vote was cast) rather than an instantaneous read.
- Add a minimum "vote age"/balance-lock similar to `EMERGENCY_COUNT_MIN_VOTE_AGE` to the standard (non-emergency) counting path so that balance changes shortly before a count cannot be weighted.
- Consider restricting who can freely retrigger `system_vote_count` for a subject, or rate-limiting recounts, to reduce the attacker's ability to choose a favorable counting moment.

### Proof of Concept
1. Address `A` posts a `system_vote` for `subject: "op_list"` with `arrOPs` containing an attacker-controlled OP set; this permanently registers `A` in `op_votes`/`system_votes` (main_chain.js `saveSystemVote`).
2. `A`'s genuine long-term balance is small (e.g., a few thousand bytes) — an insignificant share of `TOTAL_WHITEBYTES`.
3. Immediately before submitting (or observing) a unit carrying `system_vote_count: "op_list"`, the attacker moves a very large sum of bytes into `A` from another address/exchange counterpart (a normal payment), and lets it stabilize.
4. As soon as the `system_vote_count` unit's MCI stabilizes, `countVotes()` runs, reads `A`'s balance via the query in `main_chain.js` lines 1757-1773, and counts `A`'s previously-registered vote for the attacker's OP set with this inflated weight.
5. `op_rows`/`ORDER BY total_balance DESC` (main_chain.js lines 1850-1863) may now place the attacker's chosen OPs into the winning `COUNT_WITNESSES` set even though `A` never held that balance except momentarily.
6. The attacker transfers the funds back out of `A` right after the count, restoring their original insignificant balance, while the manipulated `op_list`/`system_vars` entry persists in `storage.systemVars`.

### Citations

**File:** main_chain.js (L1575-1578)
```javascript
											case 'system_vote_count': // will be processed later, when we finish this mci
												if (!voteCountSubjects.includes(payload))
													voteCountSubjects.push(payload);
												break;
```

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

**File:** main_chain.js (L1741-1780)
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
	let values = [];
	for (let address in balances)
		values.push(`(${db.escape(address)}, ${balances[address]})`);
```

**File:** main_chain.js (L1794-1821)
```javascript
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

**File:** main_chain.js (L1878-1902)
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
			if (value === undefined)
				throw Error(`no median value for ` + subject);
			storage.systemVars[subject].unshift({ vote_count_mci: mci, value, is_emergency });
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
