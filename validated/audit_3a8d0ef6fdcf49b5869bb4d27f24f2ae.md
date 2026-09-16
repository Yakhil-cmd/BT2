## Title
Governance Vote Weight Uses Instantaneous Balance With No Minimum Holding Period, Allowing Temporary Stake Inflation to Hijack System Parameter Votes - (File: main_chain.js)

### Summary
`countVotes()` in `main_chain.js` weighs every address's `system_vote` for `op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` by that address's **current** stable base-asset balance at the moment the count is triggered, with no requirement that the balance be held for any minimum duration relative to when the vote was cast. This mirrors the GUAN report's flashloan pattern: voting power is derived from a snapshot balance rather than a time-locked/committed stake, so an actor can inflate their vote weight right before the count and withdraw the funds immediately after, obtaining outsized influence on network-critical parameters for a fraction of the true economic cost.

### Finding Description
Anyone (an "unprivileged unit poster") can cast a `system_vote` message and later trigger vote counting with a `system_vote_count` message; both are explicitly permitted for regular (non-AA) authors: [1](#0-0) [2](#0-1) 

When the vote-count unit becomes stable, `countVotes()` computes each voter's weight purely from the SUM of currently-unspent, stable, good outputs of base asset held by the voting address — with no check on how long the balance has been held, nor any tie to the balance the voter had when the vote was originally cast: [3](#0-2) 

The counting window ("since_timestamp") only looks back at *when the vote was cast* to decide which votes are eligible, but the balance used to weight an eligible vote is always read fresh, at count time: [4](#0-3) 

The tallies for `op_list` and for numerical subjects both multiply by this instantaneous balance: [5](#0-4) [6](#0-5) 

This is directly analogous to the reported GUAN bug: `_calculateVotingPower` grants voting power from `positionStake` regardless of whether the lock/commitment period has actually elapsed or is meaningful at the time of use, letting a flashloaned/borrowed balance be converted into decisive voting power for one transaction. In ocore, the same effect is achievable without literally using a same-block flashloan (funds must reach `is_stable=1`), but there is still no economic bonding period: a voter can cast a cheap vote today, and at any later point top up the same address with a large payment, wait only for that payment to stabilize, then immediately post `system_vote_count` (or wait for it to be triggered) while the balance is inflated, and move the funds out right after the count concludes. Nothing in `countVotes()` requires the balance to have existed at, or since, the time the vote was cast, nor does it require the balance to remain afterward.

### Impact Explanation
`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` are core consensus/economic parameters:
- Manipulating `op_list` shifts the order-provider witness set (subject to `checkWitnessesKnownAndGood`), which can affect stability determination and undermine the intended decentralization/consensus assumptions — a form of node disagreement over which units become stable.
- Manipulating `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`, or `threshold_size` directly changes network-wide fee/throughput economics; pushing these to their permitted extremes (validated only against wide bounds, e.g. `base_tps_fee` up to `1e8`, `tps_interval` down to `0.1`) can be used to disrupt normal fee levels or congestion handling for the entire network without the attacker maintaining any lasting economic stake.

This corresponds to the "node disagreement on validity or stability" / network-parameter-manipulation impact category, achieved by an unprivileged unit poster casting `system_vote`/`system_vote_count` messages and manipulating their own balance timing — no privileged role or protocol-level compromise is required.

### Likelihood Explanation
The attack requires only: (1) casting a low-cost `system_vote`, (2) later moving a large sum of already-owned or borrowed-and-repaid funds into the voting address and waiting for it to stabilize, and (3) triggering/waiting for `system_vote_count` while the balance is inflated, then moving the funds elsewhere. All of these are ordinary, permitted actions available to any user; the vote-timeframe expansion logic in `countVotes()` (falling back to older votes if turnout is low) makes an old, cheaply-cast vote eligible to be weighted by a balance acquired much later. Likelihood is Medium: it requires capital and precise timing around stabilization, but no special privileges or bugs beyond the missing holding-period requirement.

### Recommendation
Weight votes by a balance snapshot taken at (or shortly after) the time the vote was cast, or require a minimum holding/lock period before a balance can count toward vote weight (e.g., only count outputs whose creating unit has been stable for at least N days prior to `since_timestamp`/count time). This closes the gap between "temporary balance possession" and "voting power," analogous to fixing the `increaseAndStake`/`unstake` boundary and lock-duration checks in the referenced report.

### Proof of Concept
1. Address `V` casts `system_vote` for `base_tps_fee` (or `op_list`) while holding a negligible balance; the vote is recorded in `system_votes`/`numerical_votes` with `V`'s address and the vote timestamp. [7](#0-6) 
2. Some time later (still within the counting lookback window computed in `countVotes`), `V` receives a very large base-asset payment (from a coordinated party or a loan that will be repaid after), and waits for it to reach `is_stable=1`.
3. `V` (or anyone) posts `system_vote_count` for that subject; when this unit stabilizes, `countVotes()` reads `V`'s current large balance via the `bal_rows` query and uses it as vote weight, even though `V` did not hold this balance when the vote was cast and does not intend to keep it. [8](#0-7) 
4. Immediately after `system_vars` is updated with the new (attacker-skewed) parameter value, `V` spends the large balance away to another address, retaining outsized, one-time influence on the just-elected parameter without any lasting stake. [9](#0-8)

### Citations

**File:** validation.js (L1844-1851)
```javascript
		case "system_vote":
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci && !constants.bDevnet)
				return callback("cannot vote for system params yet");
			if (objValidationState.bAA)
				return callback("AA cannot cast system vote");
			if (objValidationState.bHasSystemVote)
				return callback("can be only one system vote");
			objValidationState.bHasSystemVote = true;
```

**File:** validation.js (L1913-1920)
```javascript
		case "system_vote_count":
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci && !constants.bDevnet)
				return callback("cannot count votes for system params yet");
			if (objValidationState.bAA)
				return callback("AA cannot trigger system vote count");
			if (objValidationState.bHasSystemVoteCount)
				return callback("can be only one system vote count");
			objValidationState.bHasSystemVoteCount = true;
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

**File:** main_chain.js (L1737-1780)
```javascript
async function countVotes(conn, mci, subject, is_emergency = 0, emergency_count_command_timestamp = 0) {
	console.log('countVotes', mci, subject, is_emergency, emergency_count_command_timestamp);
	if (is_emergency && subject !== "op_list")
		throw Error("emergency vote count supported for op_list only, got " + subject);
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

**File:** main_chain.js (L1850-1862)
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
```

**File:** main_chain.js (L1878-1912)
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
			break;
		
		default:
			throw Error("unknown subject in countVotes: " + subject);
	}
	console.log(`new`, subject, value);
	// a repeated emergency vote on the same mci would overwrite the previous one
	await conn.query(`${is_emergency || mci === 0 ? 'REPLACE' : 'INSERT'} INTO system_vars (subject, value, vote_count_mci, is_emergency) VALUES (?, ?, ?, ?)`, [subject, value, mci === 0 ? -1 : mci, is_emergency]);
	await conn.query(conn.dropTemporaryTable('voter_balances'));
	eventBus.emit('system_vars_updated', subject, value);
```
