### Title
Instantaneous, unlocked balance snapshot lets an attacker buy control of consensus-critical `system_vote` parameters (e.g. `op_list`) - (File: main_chain.js)

### Summary
The TSD incident is a bug class where an attacker accumulated disproportionate DAO voting weight and used it to push a proposal that let them mint unbacked supply. The closest reachable analog in this ocore codebase is the on-chain governance mechanism for system parameters (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`), which is driven entirely by unprivileged `system_vote` units and tallied by `countVotes()`. Voting weight is not staked/locked — it is the voter's *current, unlocked* base-asset balance measured at the moment the vote is tallied, not at the moment the vote was cast.

### Finding Description
Any address can post a `system_vote` message; validation only checks structural correctness of the payload, not that the voter has held any particular balance for any duration. [1](#0-0) 

When a main-chain index stabilizes, `countVotes()` recomputes voting power from scratch by reading the **current** stable balance of every address that has ever cast a vote for the subject, and inserts it into a temporary `voter_balances` table: [2](#0-1) 

The subsequent tally (both for `op_list`, which determines the witness/order-provider list, and for the numerical parameters) sums this instantaneous balance for whichever addresses voted inside the (possibly auto-expanding) lookback window: [3](#0-2) [4](#0-3) 

Nothing in this flow requires the voting balance to be locked, held for a minimum duration, or to be the same balance that existed when the address cast its vote. An address can cast (or have on file) a `system_vote`, then receive a large one-off transfer of bytes immediately before the main-chain index that triggers the tally stabilizes, be counted with that inflated balance, and move/spend the funds again right after the tally — analogous to a flash-loan governance attack. This mirrors the TSD pattern in which an attacker accumulated outsized (but not necessarily permanent) voting weight in the governance mechanism and used it to force through a change that the honest, long-term stakeholders did not actually endorse.

There is also an accelerated "emergency" path (`applyEmergencyOpListChange` / the `is_emergency` branch of `countVotes`) that additionally folds in still-unstable, just-broadcast votes weighted by the same instantaneous-balance model, further shrinking the time available to detect and counter a balance-timed takeover attempt. [5](#0-4) [6](#0-5) 

### Impact Explanation
`op_list` directly controls the set of order/witness providers used to determine main-chain stability. An attacker who can transiently dominate the balance-weighted vote can force a change of the witness list to addresses under their control. Once witnesses are attacker-controlled, they can manipulate main-chain ordering/stability determinations, enabling node disagreement on unit validity/stability, denial of confirmation for honest units, or double-spend opportunities — this satisfies the "node disagreement on validity or stability" / "network unable to confirm new units" impact bar. This is a High-severity, network-wide governance-integrity issue, structurally analogous to the DAO-vote takeover that let the TSD attacker mint 11.8B tokens.

### Likelihood Explanation
Executing this requires the attacker to marshal a large amount of bytes (≥ `SYSTEM_VOTE_MIN_SHARE` × `TOTAL_WHITEBYTES` of the recently-active voting cohort, per the auto-expanding lookback logic) at precisely the moment a main-chain index becomes stable and the vote is tallied. This is nontrivial but does not require permanently locking capital — only possessing/controlling it for a brief window — which is a materially lower bar than genuinely holding that share of supply long-term, and the emergency-vote path shortens the reaction window further. Any address (an "unprivileged unit poster") can participate without any prior registration.

### Recommendation
Require voting weight to be based on a balance snapshot taken at (or shortly after) the time the vote was cast rather than at tally time, or require voters to lock/bond the balance being used to vote for a minimum duration spanning the counting window. Consider time-weighting balances (e.g., average balance over the lookback window rather than instantaneous balance) to blunt last-moment balance injection, and add a minimum holding-age requirement before a balance can count toward `system_vote` tallies, especially for the emergency `op_list` change path.

### Proof of Concept
Conceptual sequence (not verifiable without a running network, but derivable directly from the code path):
1. Attacker address `A` posts a `system_vote` unit for `subject: "op_list"` with `value` = attacker-controlled witness list (validated per `validation.js:1844-1883`).
2. Shortly before the main-chain index containing enough turnover stabilizes (or before triggering the emergency-count timeout in `applyEmergencyOpListChange`), attacker moves a large quantity of bytes into address `A` (or into other already-voting addresses they control).
3. When `handleAATriggers`/`markMcIndexStable` stabilizes that MCI, `countVotes()` computes `voter_balances` from the *current* stable balance of `A` (main_chain.js:1757-1780), which now includes the freshly received bytes.
4. If the accumulated `total_balance` clears `SYSTEM_VOTE_MIN_SHARE * TOTAL_WHITEBYTES` for the lookback window (main_chain.js:1807-1821), the vote is finalized and `op_list` is overwritten with the attacker's list (main_chain.js:1850-1871), all while the attacker need not have held that balance before or after the tally.

Note: I was not able to fully verify the exact numeric values of `SYSTEM_VOTE_MIN_SHARE`, `TOTAL_WHITEBYTES`, `EMERGENCY_COUNT_MIN_VOTE_AGE`, and `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` from `constants.js` before running out of tool iterations, so the precise economic cost/threshold of this attack (how large a "flash" balance would need to be, and how tight the emergency timing window is) could not be confirmed and should be checked directly in `constants.js`.

### Citations

**File:** validation.js (L1844-1866)
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

**File:** main_chain.js (L1915-1933)
```javascript
function getUnstableVotes(emergency_count_command_timestamp) {
	let votes = [];
	for (let unit in storage.assocUnstableMessages) {
		for (let m of storage.assocUnstableMessages[unit]) {
			if (m.app === 'system_vote' && m.payload.subject === 'op_list') {
				const { timestamp, author_addresses, sequence, level } = storage.assocUnstableUnits[unit];
				if (sequence !== 'good')
					continue;
				if (emergency_count_command_timestamp - timestamp < constants.EMERGENCY_COUNT_MIN_VOTE_AGE) {
					console.log('unstable vote from', author_addresses, 'is too young');
					continue;
				}
				const arrOPs = m.payload.value;
				votes.push({ timestamp, level, author_addresses, arrOPs });
			}
		}
	}
	return votes;
}
```

**File:** main_chain.js (L1936-1946)
```javascript
async function applyEmergencyOpListChange(conn, emergency_count_command_timestamp, cb) {
	// last stable unit
	const [{ timestamp, main_chain_index }] = await conn.query("SELECT timestamp, main_chain_index FROM units WHERE is_stable=1 AND is_on_main_chain=1 ORDER BY main_chain_index DESC LIMIT 1");
	if (emergency_count_command_timestamp < timestamp + constants.EMERGENCY_OP_LIST_CHANGE_TIMEOUT) {
		console.log(`too early to apply emergency OP list change yet`);
		return cb();
	}
	console.log(`applying emergency vote count after being stuck at mci ${main_chain_index}`);
	await countVotes(conn, main_chain_index - 1, 'op_list', 1, emergency_count_command_timestamp);
	cb();
}
```
