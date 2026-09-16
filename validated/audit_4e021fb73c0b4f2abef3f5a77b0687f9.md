### Title
System Governance Vote Weighting Uses Current Balance At Count-Time Instead Of A Balance Checkpoint At Vote-Cast Time - (File: main_chain.js)

### Summary
`countVotes()` in `main_chain.js` tallies `system_vote` ballots (op_list, threshold_size, base_tps_fee, tps_interval, tps_fee_multiplier) by reading each voting address's balance at the moment the vote count runs, not the balance the address held when it actually cast its vote. This is the same root cause as the Anchor Governance finding: voting power is not check-pointed to the time of the voting action, so it can be skewed by balance changes that happen after voting.

### Finding Description
`countVotes(conn, mci, subject, ...)` selects all distinct addresses that have ever voted on a `subject` and computes their weight from the current stable-good, unspent-output balance, then joins that balance to each address's most recent vote to determine the outcome: [1](#0-0) 
This balance is captured once at the mci when `countVotes` executes, and is then applied uniformly to every historical vote made by that address, going back as much as several years thanks to the expanding vote-timeframe search: [2](#0-1) 
The final tally (e.g. for `op_list`) sums `balance` from this table joined to whichever `op_address` an address's *latest* stored vote points to: [3](#0-2) 
There is no mechanism that records or uses the balance an address had at the time it signed the `system_vote` unit — unlike the poll `staked_amount` snapshot in the Anchor report, here there isn't even a snapshot: the weight is always "whatever the address holds right now, at count time." Any address that cast a (possibly trivial) vote long ago and later receives a large balance — even a temporary one moved in shortly before the mci that triggers `countVotes` — will have that entire current balance counted toward its old vote's choice, since the SQL query reads today's balance and blindly attaches it to the pre-existing vote.

### Impact Explanation
`op_list` selects the ordering providers (witnesses) that anchor stability for the entire DAG; `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier` are consensus-critical network parameters written into `system_vars` and consumed everywhere fee/stability logic runs. Because voting weight is derived from current balance rather than balance-at-vote-time, an actor can cast a vote from an address holding little value, then, shortly before the vote is counted, temporarily route a large balance through that same address (e.g., via a self-payment/loan-style transfer that is later moved back out) to inflate its counted weight far beyond its real, sustained economic stake. This lets a comparatively small stakeholder disproportionately influence witness-list composition or fee parameters — the exact "disproportionate influence" class of bug described in the Anchor report, but manifesting in Obyte's own network-parameter governance rather than a token-staking DAO.

### Likelihood Explanation
Exploitation only requires ordinary payment capability (moving one's own funds to/through the voting address) and knowledge of when `countVotes` next executes for a subject (mci stabilization is publicly observable), so no privileged network position is needed — an unprivileged unit poster can reach this path entirely through normal payments and a `system_vote` message. The main mitigating factor is that vote counting happens once per stabilized mci per subject and the attacker must time the balance transfer precisely around that mci, which raises operational complexity but does not require any special access.

### Recommendation
Record a balance checkpoint at the time each `system_vote` unit is authored (e.g., the balance available in the unit's own inputs/outputs or the address's balance at that vote unit's `last_ball_mci`), and store that snapshot alongside the vote in `system_votes`/`op_votes`/`numerical_votes`. `countVotes()` should sum these stored, per-vote checkpointed balances rather than re-querying the address's live balance at count time, mirroring the recommended check-pointing approach from the Anchor report (Compound's `Comp.sol` balance-at-block-number pattern) adapted to Obyte's stable-balance model.

### Proof of Concept
1. Address `V` casts a `system_vote` for `op_list` value `X` while holding a negligible balance (e.g. 1 byte) — the vote is accepted per validation rules and recorded in `op_votes`/`system_votes`.
2. Shortly before the mci that will trigger the next `countVotes(conn, mci, 'op_list')` call (mci stabilization is observable off-chain), the attacker sends a large stable-good payment (e.g. hundreds of thousands of bytes) into address `V`.
3. When `countVotes` runs, `bal_rows` computes `V`'s *current* stable balance (now large) and inserts it into `voter_balances`: [4](#0-3) 
4. The `op_rows` aggregation joins `op_votes` (still pointing at `V`'s old vote for `X`) with this inflated `voter_balances` entry, so `X` receives credit for the large temporary balance even though `V` held only 1 byte when it actually voted: [3](#0-2) 
5. After the count, the attacker can move the large balance back out of `V`, having paid only transaction fees to have secured outsized influence over the `op_list`/parameter outcome relative to their real stake.

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
