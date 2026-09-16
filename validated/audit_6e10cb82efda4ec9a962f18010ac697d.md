### Title
Vote weight in system_vote counting is snapshotted from current balance, not held-through-period balance, letting an unprivileged voter instantly inflate their governance vote weight - ([File: main_chain.js])

### Summary
The audit finding describes a "future permission usable immediately" bug class: an actor is supposed to only gain a benefit (voting power) after a time condition is satisfied (the escrow `startTime`), but the contract fails to gate the action on that time condition, letting the holder use the full benefit the instant it is nominally granted. The closest reachable analog in ocore is `countVotes()` in `main_chain.js`, which computes voter weight for `system_vote` subjects (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) from the voter's **current** stable balance at the moment the vote count runs, rather than the balance the voter actually held while their vote was outstanding.

### Finding Description
Any address can cast a `system_vote` message (single posted unit, no special privilege) — validated generically as an inline app message in `validation.js` (`arrInlineOnlyApps` includes `"system_vote"`) [1](#0-0) .

When a subject's votes are tallied, `countVotes()` selects the set of addresses that have *ever* cast a vote for the subject, then computes each address's weight purely from its **current** unspent stable-good balance, with no requirement that this balance be the one held while the vote was cast, nor any minimum holding duration: [2](#0-1) [3](#0-2) 

The weighting logic then aggregates `voter_balances` against the `system_votes`/`numerical_votes`/`op_votes` tables purely by address, using this present-moment balance: [4](#0-3) [5](#0-4) 

There is a "vote timeframe" widening loop that expands the *lookback window for which addresses' votes are considered fresh enough to include* (`since_timestamp`), but this only controls whether an address's **vote** is old enough to be counted — it does nothing to ensure the **balance** attributed to that address was actually held throughout that same window: [6](#0-5) 

As a result, an address that cast a vote for a subject long ago (or even just before the mci stabilizes) can receive a large payment of bytes immediately before the counting mci stabilizes and have that entire new balance counted at full weight for a vote it cast with a trivial balance — the "voting power" (weight) attributed to the address is not gated by the time at which the balance was actually acquired relative to the vote, mirroring the reported bug's core defect (a time-bound right used before/without the intended holding-period check).

### Impact Explanation
`countVotes()` determines governance-critical `system_vars`, most importantly the `op_list` (order provider / witness list) that other nodes use to determine main-chain stability, and numeric TPS/fee parameters that affect fee validity across the whole network. If an attacker can inflate the weight of a stale vote by acquiring balance just before the counting mci stabilizes, they can bias `op_list` or `threshold_size`/`tps_interval`/`tps_fee_multiplier` outcomes without genuinely representing sustained economic stake. Because all full nodes derive `system_vars` deterministically from the same DB state when a mci stabilizes, this does not by itself directly split "good" nodes from each other (all nodes will see the same current balances at the moment of counting), but it defeats the intended stake-weighted governance model, letting a party who briefly holds byte balance (e.g., via a flash loan-like short-term transfer between own addresses, or receiving funds transiently) swing a system-wide vote that a genuinely long-term, larger holder base did not endorse. A maliciously-set `op_list` can materially affect stability/consensus properties of the network going forward.

### Likelihood Explanation
Likelihood is constrained by the requirement that: (1) the attacker (or a colluding party) must have previously cast at least one `system_vote` for the targeted subject from a chosen address, and (2) they must be able to move a large byte balance into that address and have it become stable-good exactly at (or shortly before) the moment the target mci for the vote count stabilizes. Since counting occurs at deterministic, network-visible moments (`markMcIndexStable`), and address-to-address transfers of bytes are trivial and unrestricted, this is straightforward to orchestrate for a well-resourced actor, though it does require some coordination around timing of stabilization.

### Recommendation
Weight `system_vote` participants by the balance they held continuously (or at minimum, at the time they cast/last updated their vote for the subject), not by the balance at the moment of counting. Concretely, snapshot and attribute balance based on the state as of each voter's vote timestamp (or as of `since_timestamp`, the start of the counting window), and disregard balance increases that occur after the vote was cast, analogous to how the recommendation in the reported bug requires gating a privileged action by an explicit time check (`startTime`) before use.

### Proof of Concept
1. Attacker address `A` casts `system_vote` for `subject = "op_list"` with a chosen `value` while holding a small balance (e.g., dust). This satisfies the "have voted at least once" filter in `countVotes()`'s `address_rows` query [7](#0-6) .
2. Shortly before the mci at which `countVotes()` will run stabilizes, attacker transfers a very large byte balance from other addresses they control into address `A`.
3. When the mci stabilizes, `handleAATriggers`/`markMcIndexStable` flow triggers `countVotes()`, which computes `bal_rows`/`balances` from `A`'s current stable-good, unspent outputs — now including the newly received large balance [8](#0-7) .
4. `A`'s vote for `op_list` (or a numerical subject) is now weighted with the full large balance, even though that balance was acquired only just before counting and was never held during the actual "vote period" being measured by `since_timestamp` [4](#0-3) .
5. This lets the attacker dominate the vote outcome for `op_list`/`threshold_size`/etc. despite not having sustained economic commitment, analogous to the reported issue of gaining a time-gated privilege (voting power) without satisfying the intended time/holding condition.

### Citations

**File:** validation.js (L1620-1622)
```javascript
	var arrInlineOnlyApps = ["address_definition_change", "data_feed", "definition_template", "asset", "asset_attestors", "attestation", "poll", "vote", "definition", "system_vote", "system_vote_count", "temp_data"];
	if (arrInlineOnlyApps.indexOf(objMessage.app) >= 0 && objMessage.payload_location !== "inline")
		return callback(objMessage.app+" must be inline");
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
