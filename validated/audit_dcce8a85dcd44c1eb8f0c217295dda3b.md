## Title
System-vote power calculation excludes witnessing/headers-commission balances - ([File: main_chain.js])

### Summary
`ocore`'s system governance mechanism (`system_vote` / `system_vote_count` messages) lets any address vote on consensus-critical parameters — `op_list` (witness list), `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`. The vote weight of each voting address is supposed to be its byte balance. However, `countVotes()` in `main_chain.js` only sums the `outputs` table (plain payment outputs) when building `voter_balances`, silently omitting balance held in `witnessing_outputs` and `headers_commission_outputs`. This is the same bug class as the reported "expired tokens excluded from voting power" issue: a category of legitimately-owned funds is dropped from the power/weight calculation used to decide a protocol-level outcome.

### Finding Description
`countVotes(conn, mci, subject, ...)` builds the voter balance table used to weigh every `system_vote`: [1](#0-0) 
This query sums only `outputs.amount` for `outputs.asset IS NULL`, i.e. plain byte payment outputs. It never includes `witnessing_outputs` or `headers_commission_outputs`, even though these are legitimate, spendable byte balances belonging to the same addresses.

Compare this with the wallet's own balance reader, which explicitly UNIONs `witnessing_outputs` and `headers_commission_outputs` into an address's stable balance: [2](#0-1) 
and the shared-address balance reader does the same: [3](#0-2) 

So the code base itself treats witnessing/headers-commission balances as part of an address's real byte holdings everywhere except in the vote-weighing logic. Witnesses and any address that has recently produced units accumulate substantial balances in these two tables (that's literally how they get paid), so this is not a corner case — it systematically underweights exactly the addresses (witnesses/active posters) that are most likely to participate in `op_list`/fee-parameter governance.

The computed `voter_balances` feed directly into:
- The minimum participation/vote-share gate that decides how far back in time to look for votes: [4](#0-3) 
- The actual `op_list` (witness list) vote tally: [5](#0-4) 
- The median-vote calculation for `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`: [6](#0-5) 

Notably, the project's own `tools/compare_vote_balances.js` was added specifically to audit vote-balance undercounting bugs (it fixes a different, already-patched zombie-spend issue via a `NOT EXISTS` correction), showing that the vote-balance-accuracy problem class is recognized as important enough to warrant a dedicated verification tool — yet it does not check for the witnessing/headers-commission omission: [7](#0-6) 

### Impact Explanation
`op_list` determines the network's witness set, and `threshold_size`/`base_tps_fee`/`tps_interval`/`tps_fee_multiplier` determine consensus-critical fee and stability parameters that every full node enforces identically to agree on unit validity. If voter balances are systematically undercounted for exactly the addresses that hold witnessing/header-commission income (active witnesses, order/attestor-style operators), then:
- The `SYSTEM_VOTE_MIN_SHARE` participation threshold may fail to be reached even though real economic backing exists, delaying or blocking legitimate `op_list`/parameter changes and leaving the network unable to update its witness set or TPS parameters in a timely manner.
- Conversely, votes from addresses whose balance is mostly in ordinary payment outputs are correctly weighted while active/witness addresses are underweighted, skewing the outcome of `op_list` elections and numeric-parameter medians away from the true economically-weighted preference, i.e., a wrong `op_list` or fee parameter can be adopted with less real backing than intended.
- Because `op_list`/fee parameters are enforced identically by every node from `system_vars`, an incorrect or manipulable outcome affects protocol-wide consensus rules, not just one user's funds — this is a governance/consensus integrity issue rather than a simple accounting display bug.

### Likelihood Explanation
Witnessing and headers-commission income is a normal, constant byproduct of running a witness or authoring/including units — it is not a rare edge case. Any address that both earns such commissions and participates in `system_vote` will trigger the undercount every single time `countVotes` runs (each time `system_vote_count` stabilizes for a subject). No special exploit is needed; the bug fires under completely ordinary operation of any witness address that also votes on `op_list` or fee parameters.

### Recommendation
Update the `bal_rows` query (and the underlying `voter_balances` construction) in `countVotes()` in `main_chain.js` to include stable, unspent `witnessing_outputs` and `headers_commission_outputs` balances for each voting address, mirroring the UNION approach already used in `balances.js:readBalance`/`readSharedBalance`. Extend `tools/compare_vote_balances.js` to also detect this discrepancy so future regressions are caught automatically.

### Proof of Concept
1. Address `W` is an active witness that also posts `system_vote` messages for `op_list`/`threshold_size`.
2. `W` accumulates a large balance in `witnessing_outputs`/`headers_commission_outputs` from block production over time, while holding comparatively little in plain `outputs`.
3. When `countVotes()` stabilizes a vote-count MCI, `bal_rows` (main_chain.js lines 1757-1773) computes `W`'s voter balance using only plain `outputs`, resulting in a small `voter_balances[W]` value that does not reflect `W`'s real byte holdings.
4. `W`'s vote on `op_list`/`threshold_size`/`base_tps_fee` is tallied with this artificially low weight in the `op_rows`/median-vote SQL (lines 1850-1902), while other voters whose funds sit in plain outputs are correctly weighted.
5. The resulting `op_list` or numeric system variable adopted network-wide does not reflect the true economically-weighted consensus of participants, and/or the `SYSTEM_VOTE_MIN_SHARE` participation threshold (lines 1807-1821) is harder to reach than intended, delaying critical governance updates.

### Citations

**File:** main_chain.js (L1753-1777)
```javascript
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

**File:** balances.js (L30-39)
```javascript
			db.query(
				"SELECT SUM(total) AS total FROM ( \n\
				SELECT SUM(amount) AS total FROM "+my_addresses_join+" witnessing_outputs "+using+" WHERE is_spent=0 AND "+where_condition+" \n\
				UNION ALL \n\
				SELECT SUM(amount) AS total FROM "+my_addresses_join+" headers_commission_outputs "+using+" WHERE is_spent=0 AND "+where_condition+" ) AS t",
				[walletOrAddress,walletOrAddress],
				function(rows) {
					if(rows.length){
						assocBalances["base"]["stable"] += rows[0].total;
					}
```

**File:** balances.js (L132-142)
```javascript
		db.query(
			"SELECT asset, address, is_stable, SUM(CAST(amount AS DOUBLE)) AS balance \n\
			FROM outputs CROSS JOIN units USING(unit) \n\
			WHERE is_spent=0 AND sequence='good' AND address IN("+strAddressList+") \n\
			GROUP BY asset, address, is_stable \n\
			UNION ALL \n\
			SELECT NULL AS asset, address, 1 AS is_stable, SUM(amount) AS balance FROM witnessing_outputs \n\
			WHERE is_spent=0 AND address IN("+strAddressList+") GROUP BY address \n\
			UNION ALL \n\
			SELECT NULL AS asset, address, 1 AS is_stable, SUM(amount) AS balance FROM headers_commission_outputs \n\
			WHERE is_spent=0 AND address IN("+strAddressList+") GROUP BY address",
```

**File:** tools/compare_vote_balances.js (L15-48)
```javascript
async function balancesOldWay(addresses) {
	const strAddresses = addresses.map(db.escape).join(', ');

	const bal_rows = await db.query(`
		SELECT address, SUM(amount) AS balance
		FROM outputs
		LEFT JOIN units USING(unit)
		WHERE address IN(${strAddresses}) AND is_spent=0 AND asset IS NULL AND is_stable=1 AND sequence='good'
		GROUP BY address`);

	const balances = {};
	for (const { address, balance } of bal_rows)
		balances[address] = balance || 0;

	const spent_rows = await db.query(`
		SELECT inputs.address, SUM(outputs.amount) AS spent_balance
		FROM units
		CROSS JOIN inputs USING(unit)
		CROSS JOIN outputs ON src_unit=outputs.unit AND src_message_index=outputs.message_index AND src_output_index=outputs.output_index
		CROSS JOIN units AS output_units ON outputs.unit=output_units.unit
		WHERE units.is_stable=0 AND +units.sequence='good'
			AND +output_units.is_stable=1 AND +output_units.sequence='good'
			AND inputs.address IN(${strAddresses}) AND type='transfer' AND inputs.asset IS NULL
		GROUP BY inputs.address`);

	for (const { address, spent_balance } of spent_rows) {
		if (balances[address])
			balances[address] += spent_balance;
		else
			balances[address] = spent_balance;
	}

	return balances;
}
```
