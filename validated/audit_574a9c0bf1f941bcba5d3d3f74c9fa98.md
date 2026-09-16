### Title
Governance vote-counting uses instantaneous, unstable output balances that can be flash-loaded to hijack `op_list` / `threshold_size` / `tps_fee` system votes - ([File: main_chain.js])

### Summary
`ocore`'s on-chain governance mechanism (`system_vote` messages, counted in `countVotes()` in `main_chain.js`) lets any address vote on system-critical parameters — most importantly `op_list` (the order-provider list that underpins main-chain stability) — weighted by that address's *current* unspent base-asset balance at the moment the vote-counting MCI stabilizes. This is architecturally the same "voting-power = current token/asset balance" governance pattern that Term Finance's vaults used, where an attacker who transiently accumulates majority voting power can push through a proposal (there, disabling the timelock; here, changing the OP list or fee/threshold system vars) that other participants have no way to block in time.

### Finding Description
`countVotes()` computes voter balances directly from unspent, good, stable outputs at the time of counting: [1](#0-0) 
It then aggregates `system_votes` (and `numerical_votes`/`op_votes`) by these balances to decide the next `op_list` or numerical system variable (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`): [2](#0-1) 

There is no lock-up, staking delay, or historical-balance snapshot requirement analogous to a timelock: an address's voting weight is simply "whatever spendable base-asset balance it holds right now." Because ocore is a DAG-based ledger where balances can be moved in and back out within a very short span of stabilized MCIs, an attacker can:
1. Temporarily concentrate a large balance into one or few addresses (e.g., via a large payment that will be moved onward immediately after voting, similar to a flash loan),
2. Post `system_vote` messages from those addresses for a malicious `op_list` (replacing honest order providers with attacker-controlled ones) or for extreme `threshold_size`/fee parameters,
3. Move the funds away right after the vote is counted, retaining only the (much smaller) real, permanent balance.

The vote-timeframe expansion logic only expands *how far back* in time votes are counted if turnout is thin (`SYSTEM_VOTE_MIN_SHARE = 0.1`, i.e. 10% of `TOTAL_WHITEBYTES`), it does not protect against balance manipulation at counting time: [3](#0-2) 

The emergency `op_list` change path additionally allows an out-of-cycle vote count if the network has been "stuck" for `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days), further reducing the friction to force through a malicious `op_list` change once the attacker holds unusually large balances in voting addresses: [4](#0-3) [5](#0-4) 

Once `op_list` is changed, the set of order providers determining main-chain stability changes — this is the ocore analogue of "disabling the timelock and draining the vault": an attacker-controlled OP list can be used to bias/withhold witnessing, stall stabilization, or otherwise disrupt consensus on which units/balls are considered final, directly affecting confirmation of payments and AA triggers network-wide.

### Impact Explanation
A successful vote hijack changes `system_vars.op_list` (or fee/threshold parameters) network-wide, affecting every node's determination of stability and main-chain progression. Because these parameters are foundational to consensus, a malicious change constitutes node disagreement on validity/stability or a network unable to confirm new units in the way the OP set intends, matching the "Critical/High" bug classes in scope (governance capture leading to loss of protocol integrity). It does not require any peer/network-level compromise — it is reachable purely by posting ordinary `payment` and `system_vote` units as an unprivileged unit poster.

### Likelihood Explanation
Exploitability depends on an attacker being able to amass a large temporary base-asset balance across the small number of addresses used to vote, and on turnout among honest voters being low enough that the manipulated votes cross the 50%/`SYSTEM_VOTE_MIN_SHARE` thresholds used in `countVotes()`. Since real economic capital must be temporarily deployed (unlike a pure flash loan within a single atomic transaction, ocore's vote counting happens only at MCI stabilization, which takes real time), this raises the cost versus a single-block flash-loan attack, but it remains a real risk given that voting weight is based on spendable-balance-at-count-time rather than a locked/staked/vested amount, and no explicit anti-flash-balance protection (e.g., minimum holding period) is implemented in `countVotes()`.

### Recommendation
- Require voting weight to be based on a balance held continuously over a minimum window before the vote-count MCI (age-weighted or minimum holding period), rather than the instantaneous balance at stabilization.
- Consider requiring locked/staked deposits for governance voting (an actual "timelock"-style commitment) so voting power cannot be freely and rapidly reallocated.
- Add a minimum quorum and a cooldown/delay before applying `op_list`/system_var changes coming from votes, and require an additional stability confirmation window before the new `op_list` takes effect network-wide.
- Audit the emergency `op_list` change path (`applyEmergencyOpListChange`) to ensure it cannot be triggered opportunistically in coordination with a temporary balance spike.

### Proof of Concept
1. Attacker accumulates a very large base-asset balance in a set of addresses (via legitimate means or temporary transfers) shortly before the next vote-count MCI is expected to stabilize.
2. Attacker posts `system_vote` messages, e.g. `{app: 'system_vote', payload: {subject: 'op_list', value: [<attacker-controlled OP addresses>]}}` (validated per `validateInlinePayload`/`case "system_vote"` in `validation.js`) from those addresses.
3. When `main_chain.js`'s `countVotes()` runs at the next stabilized MCI, it computes `voter_balances` from the current unspent outputs (`main_chain.js:1757-1777`) and, if the attacker's aggregated balance crosses the majority/`SYSTEM_VOTE_MIN_SHARE` threshold among recent voters, `storage.systemVars.op_list` is replaced with the attacker's list (`main_chain.js:1866-1871`).
4. Attacker immediately transfers the balance out of the voting addresses, retaining only the altered `op_list`/system parameters as the lasting effect on network consensus.

### Citations

**File:** main_chain.js (L1757-1777)
```javascript
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

**File:** main_chain.js (L1878-1903)
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

**File:** constants.js (L18-19)
```javascript
exports.EMERGENCY_OP_LIST_CHANGE_TIMEOUT = 3 * 24 * 3600;
exports.EMERGENCY_COUNT_MIN_VOTE_AGE = 3600;
```
