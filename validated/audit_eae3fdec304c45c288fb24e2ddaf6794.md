### Title
Instantaneous-balance vote weighting in `countVotes` allows plutocratic takeover of the OP (witness) list and system parameters - ([File: main_chain.js])

### Summary
`ocore`'s on-chain governance for system parameters and the order-provider (`op_list`/witness) list weights every vote by the voter's **current** byte balance at the moment the vote is counted (`countVotes`), not by the balance held at the time the vote (`system_vote` message) was cast. This mirrors the BonkDAO incident, where an attacker bought enough governance tokens on the open market to acquire outsized voting power and pushed through a proposal draining the treasury—no contract exploit, just abuse of the DAO's own token-weighted voting.

### Finding Description
System votes are recorded per-unit in `system_votes`/`op_votes`/`numerical_votes` via the `system_vote` message type, validated in `validateInlinePayload` [1](#0-0) . When votes are tallied, `countVotes` computes voter balances by summing currently-unspent, stable-good, base-asset outputs owned by every address that has ever cast a vote for the subject — a live snapshot taken at the moment the MCI stabilizes, not a historical balance tied to the vote's timestamp: [2](#0-1) 

The subsequent tally for `op_list` (and for numerical subjects like `threshold_size`, `base_tps_fee`, etc.) ranks candidate values purely by `SUM(balance)` joined against this live `voter_balances` snapshot: [3](#0-2) [4](#0-3) 

There is no requirement that the balance backing a vote be held for any minimum duration prior to the vote or prior to the count. The only throttle is an expanding lookback window designed to guarantee *some* minimum participation share (`SYSTEM_VOTE_MIN_SHARE`) — it does not defend against a single actor amassing a large balance shortly before voting/counting: [5](#0-4) 

Because the balance check is a point-in-time query against `outputs`/`units` at counting time, an address that acquires a large amount of bytes just before the relevant MCI stabilizes gets its full new balance counted toward whatever `system_vote` it already broadcast (or broadcasts immediately after acquiring funds, then waits for confirmation). This is architecturally identical to the BonkDAO case: buy enough governance weight right before the vote closes, then use that weight to push a self-favoring outcome through the DAO's own legitimate voting mechanism.

### Impact Explanation
The `op_list` subject directly controls the network's witness/order-provider set, which underpins main-chain stability determination and consensus on unit validity throughout the codebase (see `checkWitnessesKnownAndGood`/`checkNoReferencesInWitnessAddressDefinitions` gating in `validation.js`, and the way `storage.systemVars.op_list` feeds witness selection). An attacker who transiently amasses enough byte balance to dominate the `voter_balances` snapshot at count time can:
- Force a change of `op_list` to addresses they control, compromising main-chain stability consensus (nodes could disagree on stability, or the attacker's witnesses could enable double-spend-favorable reorganizations).
- Alternatively manipulate `threshold_size`, `base_tps_fee`, `tps_interval`, or `tps_fee_multiplier` to values that stall fee mechanics or make the network unable to confirm new units economically.

This satisfies the "node disagreement on validity or stability" / "network unable to confirm new units" impact bar, and is Critical because it is a single-transaction, unprivileged-actor attack on core consensus parameters, directly analogous to the $20M BonkDAO treasury takeover via bought voting power.

### Likelihood Explanation
Likelihood is Medium: buying enough bytes/GBYTE to dominate the (typically small) pool of active system-vote participants is a real-world capital cost, similar to BonkDAO's ~$4M outlay to control ~$20M. Because `system_votes`/`op_votes`/`numerical_votes` currently have very few historical voters (per `initial_votes.js` preload lists), the total competing balance to overcome may be modest relative to total supply, making a well-funded attacker's task easier than it would be in a fully diversified voter base.

### Recommendation
Weight votes by a balance snapshot taken at (or shortly after) the time each `system_vote` unit was authored/stabilized, rather than by the live balance at count time — e.g., store/verify the author's balance as of the vote unit's own MCI, or require a minimum coin-age/holding period before a balance can count toward a vote. Consider also capping the influence any single address (or newly-funded address) can exert per vote-count cycle, and/or requiring votes to be re-affirmed over multiple stabilized MCIs to dampen last-minute balance manipulation.

### Proof of Concept
1. Attacker acquires a large quantity of bytes on-exchange or via OTC purchase, funding one or more addresses.
2. Attacker broadcasts `system_vote` units from those addresses with `subject: "op_list"` (or a numerical subject) choosing a malicious value, validated per `validation.js:1844-1883`.
3. Once the attacker's funding unit(s) and vote unit(s) stabilize, and a `system_vote_count` command triggers `countVotes` for that MCI/subject, the balance query in `main_chain.js:1757-1773` picks up the attacker's full current stable-good balance.
4. If this balance, combined with the expanding lookback window logic (`main_chain.js:1807-1821`), pushes the attacker's chosen `op_address` set (or numeric value) to the top of the `ORDER BY total_balance DESC` ranking (`main_chain.js:1850-1863` / `1882-1902`), `system_vars` is updated and `storage.systemVars.op_list` (or the numeric system var) is changed network-wide — achieved purely through the DAO-style token-weighted voting mechanism, with no smart-contract exploit required, mirroring the BonkDAO BIP-76 attack.

### Citations

**File:** validation.js (L1844-1883)
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
			switch (payload.subject) {
				case "op_list":
					const arrOPs = payload.value;
					if (!isArrayOfLength(arrOPs, constants.COUNT_WITNESSES))
						return callback("OP list must be an array of " + constants.COUNT_WITNESSES);
					if (!arrOPs.every(isValidAddress))
						return callback("all OPs must be valid addresses");
					let prev_op = arrOPs[0];
					for (let i = 1; i < arrOPs.length; i++){
						const op = arrOPs[i];
						if (op <= prev_op)
							return callback("OP list must be sorted and unique");
						prev_op = op;
					}
					checkNotAAs(conn, arrOPs, objValidationState.last_ball_mci, err => {
						if (err)
							return callback(err);
						checkWitnessesKnownAndGood(conn, objValidationState, arrOPs, err => {
							if (err)
								return callback(err);
							checkNoReferencesInWitnessAddressDefinitions(conn, objValidationState, arrOPs, callback);
						});
					});
					break;
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

**File:** main_chain.js (L1882-1902)
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
```
