### Title
System-parameter vote weight is computed from the current instantaneous balance instead of a time‑held/locked stake, allowing an attacker to buy transient voting power - (File: main_chain.js)

### Summary
The `countVotes` routine in `main_chain.js` tallies votes for `op_list`, `threshold_size`, `base_tps_fee`, `tps_interval` and `tps_fee_multiplier` by looking up each historical voter's **current** unspent balance at the moment the count is executed, not the balance the voter actually held while their vote was outstanding. [1](#0-0)  This mirrors the reported MainVault.sol flaw: reward/weight is attributed based on a point‑in‑time snapshot rather than tracking how long value was actually held/contributed, which lets an actor acquire the underlying asset only briefly, capture an outsized share of the outcome, and then dispose of it immediately.

### Finding Description
Any unit author can cast a governance vote by posting an `app: 'system_vote'` message; the vote is durably recorded together with the voter's address and timestamp, regardless of the balance held at that time. [2](#0-1) 

When a (also unprivileged) unit later carries an `app: 'system_vote_count'` message for a subject (e.g. `op_list`, as shown in the composer helper used to build such units) [3](#0-2) , `countVotes()` is executed once that unit's MCI stabilizes. It gathers **all addresses that have ever cast a vote for the subject** and then computes their voting weight from the *current* stable unspent-output balance: [4](#0-3) 

This balance is read at the time of counting, completely decoupled from the timestamp of the corresponding `system_vote`. The subsequent aggregation weights each address's vote (within a rolling lookback window) by this instantaneous balance for both the witness list (`op_list`) and the numerical system parameters: [5](#0-4) [6](#0-5) 

Because the balance used is whatever is unspent in the address *right when the counting unit stabilizes*, an attacker who has an old, cheap `system_vote` on record for a subject can, immediately before triggering (or waiting for someone else to trigger) the `system_vote_count` unit's stabilization, move a large sum of bytes into that voting address, have it counted at full weight, and move the funds back out right after — exactly the "deposit right before the snapshot, withdraw right after" pattern from the reported bug, except here the asset being gamed is consensus-influence (which witnesses are trusted, or what fee/TPS parameters the network uses) rather than yield.

### Impact Explanation
`op_list` votes directly determine the network's witness set, and `threshold_size`/`base_tps_fee`/`tps_interval`/`tps_fee_multiplier` govern core fee/stability parameters. Because vote weight is not tied to a genuine, sustained economic stake but to a balance that can be acquired for only the few seconds needed to be captured by the counting query, a well-funded but economically uncommitted actor can disproportionately steer witness composition or fee parameters. This can lead to network disagreement on witness trust and downstream stability/validity assumptions that depend on `op_list`/system vars, i.e. a governance takeover risk without any real, lasting stake.

### Likelihood Explanation
The attack requires only the ability to move funds (a wallet with enough temporary liquidity, e.g. via a flash-style loan/exchange withdrawal or coordination with an exchange) between the votes' timestamps and the counting unit's stabilization, plus knowledge of when the `system_vote_count` triggering unit will stabilize (deterministic once posted, and stabilization delay is public/predictable). No special privilege is required beyond authoring ordinary units (`system_vote`, `system_vote_count`), making this reachable by any unit poster.

### Recommendation
Weight votes by a balance that reflects sustained holding rather than an instantaneous snapshot — e.g., use the minimum balance held by the address over the entire lookback window (or an average/time-weighted balance sampled at multiple points), analogous to snapshot-resistant governance designs (e.g., requiring the balance to have been present as of the vote's own timestamp, or requiring outputs to be older than some minimum age before they count toward vote weight).

### Proof of Concept
1. Attacker's address `A` posts a `system_vote` unit for `subject: "op_list"` with a chosen `value` while holding a negligible balance; this is stored in `system_votes` with `A`'s current timestamp. [2](#0-1) 
2. Attacker waits until conditions are ripe to post (or lets someone else post) a unit carrying `app: 'system_vote_count'` for `op_list`. [3](#0-2) 
3. Just before that counting unit's MCI stabilizes, attacker transfers a very large amount of bytes into address `A` (e.g., from an exchange or a temporary loan) so that `A`'s unspent, stable, good-sequence output balance is huge at query time.
4. When the counting unit stabilizes, `countVotes()` runs and reads `A`'s current balance via the `bal_rows` query, using it as `A`'s full voting weight for `op_list` (and any other subject `A` has an old vote for), potentially swinging the result. [7](#0-6) [5](#0-4) 
5. Immediately after stabilization, attacker moves the funds out of `A`; the vote's outsized influence is already locked in even though `A` held the funds only momentarily.

### Citations

**File:** main_chain.js (L1619-1637)
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
									let sqlValues = [];
									switch (subject) {
										case "op_list":
											const arrOPs = value;
											await conn.query("DELETE FROM op_votes WHERE address IN (?)", [author_addresses]);
											for (let address of author_addresses)
												sqlValues = sqlValues.concat(arrOPs.map(op_address => `(${db.escape(unit)}, ${db.escape(address)}, ${db.escape(op_address)}, ${timestamp})`));
											await conn.query("INSERT INTO op_votes (unit, address, op_address, timestamp) VALUES " + sqlValues.join(', '));
											break;
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

**File:** main_chain.js (L1878-1901)
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
```

**File:** composer.js (L256-266)
```javascript
	if (bGenesis && params.witnesses /*&& constants.v4UpgradeMci === 0*/) {
		arrMessages.push({
			app: 'system_vote',
			payload: {
				subject: 'op_list',
				value: params.witnesses.sort()
			}
		}, {
			app: 'system_vote_count',
			payload: 'op_list'
		});
```
