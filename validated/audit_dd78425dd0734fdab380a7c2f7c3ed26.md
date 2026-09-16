### Title
System vote weighting uses current stable balance instead of balance held during the vote's validity window, enabling balance-inflation manipulation of governance votes (op_list, tps fee parameters) - (File: main_chain.js)

### Summary
`countVotes()` in `main_chain.js` computes voter weights for `op_list`, `threshold_size`, `base_tps_fee`, `tps_interval` and `tps_fee_multiplier` votes by taking each voter address's **current** stable/unspent byte balance (queried at the moment the MCI stabilizes and vote counting runs) and applying that single snapshot value as the weight for **all** votes the address cast anywhere inside a multi-year lookback window. This mirrors the reported bug class: a "fee"/weight is derived from a present-time balance snapshot but applied retroactively over a whole elapsed period during which the balance may have changed dramatically, instead of being tied to the balance actually held when the vote (or accrual event) happened.

### Finding Description [1](#0-0) 
`countVotes` gathers all addresses that ever voted for a `subject` and queries their **current** balance:
```
SELECT outputs.address, SUM(outputs.amount) AS balance
FROM outputs JOIN units ON outputs.unit = units.unit
WHERE outputs.address IN(...) AND outputs.asset IS NULL
  AND units.is_stable = 1 AND units.sequence = 'good'
  AND NOT EXISTS (... spent by good/stable unit ...)
```
This is a live balance read at the instant `system_vote_count` stabilizes — not the balance that existed when the address actually posted its `system_vote`/`numerical_votes`/`op_votes` message. [2](#0-1) 
The code then determines an expanding lookback window (`since_timestamp`), going back a year at a time until enough voted balance is found:
```
let since_timestamp = mc_timestamp;
while (true) {
    since_timestamp -= 365 * 24 * 3600;
    ...
}
``` [3](#0-2) 
For `op_list`, the winning witnesses are chosen by summing the **current** balance of every address whose latest vote (of any age within the window) targets that OP:
```
const op_rows = await conn.query(`SELECT op_address, SUM(balance) AS total_balance
    FROM ${votes_table}
    CROSS JOIN voter_balances USING(address)
    WHERE timestamp>=?
    GROUP BY op_address ...`, ...);
``` [4](#0-3) 
The same current-balance weighting is used for the numerical system vars (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`), computing a weighted median from `voter_balances` regardless of what the balance was when the vote was cast.

Because the balance used for weighting is read only once, at vote-count time, and applied uniformly to a vote that may have been posted up to several years earlier, an address's vote weight can be trivially and temporarily inflated: an attacker casts a vote (e.g., for a rogue `op_list`, or extreme `tps_fee_multiplier`/`threshold_size` values) while holding a tiny balance (so it costs almost nothing and draws no attention), then — right before/at the MCI where `system_vote_count` for that subject stabilizes — moves a large amount of bytes into the voting address. `countVotes` will read this inflated balance and count it as if that stake had "voted" for the full multi-year lookback period, even though it held that stake for at most a few seconds. This is directly analogous to H-8's flaw: charging/weighting based on the balance present *at settlement time* rather than the balance actually held *during the period being priced/weighted*.

### Impact Explanation
`op_list` determines the set of Order Providers (witnesses) that anchor the main chain and stability determination; `base_tps_fee`/`tps_interval`/`tps_fee_multiplier`/`threshold_size` govern the fees required to get units accepted and the oversize-fee curve, directly affecting whether the network can economically confirm new units. An attacker who can transiently amass a large byte balance (borrowed, aggregated from many wallets, or briefly consolidated) at the exact stabilization point of a vote-count MCI can:
- Force a favorable `op_list` (witness set) change, undermining decentralization/witness selection guarantees and potentially seating malicious/compromised OPs, which affects stability determination for every node.
- Push `tps_fee`/`threshold_size` parameters to extreme values, degrading the network's ability to confirm new units economically (a network-wide availability/DoS-adjacent governance manipulation) or making fees free to bypass anti-spam protection.

This is a Medium/High severity governance-manipulation vector because it lets a comparatively small "true" stake (the vote itself, cast cheaply) exercise outsized, essentially free voting power by manipulating only the balance snapshot instant, rather than having to genuinely hold that stake throughout the voting period.

### Likelihood Explanation
This is exploitable in normal operation by any address able to post `system_vote` and `system_vote_count`/`op_votes`/`numerical_votes` messages (unprivileged unit posters, as seen composed in `composer.js` where `system_vote`/`system_vote_count` messages are added by ordinary units), and requires only the ability to time a large transfer to coincide with the MCI that stabilizes the vote-counting unit — main-chain progression and timing are observable/predictable to any network participant, making the attack feasible without any privileged or malicious-node access.

### Recommendation
Weight votes using the balance held by the voting address **at the time the vote was cast** (or an average/minimum balance held continuously since the vote was cast through the counting MCI), rather than re-reading the address's current balance at count time. Concretely, snapshot and persist the voter's balance alongside `system_votes`/`op_votes`/`numerical_votes` at the moment of voting (similar to how `tps_fees_balances` is snapshotted per-mci), and use that historical value—or a time-integrated value—in `countVotes`, invalidating/re-weighting a vote if the address's balance drops significantly, so no one can retroactively inflate the weight of an old, cheaply-cast vote by injecting funds only at settlement time.

### Proof of Concept
1. Address A posts a `system_vote` for `subject='op_list'` (or `numerical_votes` for `tps_fee_multiplier`) while holding a negligible balance (e.g., 1000 bytes) — this vote is recorded in `system_votes`/`op_votes`/`numerical_votes` with its timestamp, per [5](#0-4) .
2. Time passes; other legitimate high-balance voters vote for a different, honest set of parameters.
3. Just before/at the MCI where a `system_vote_count` message for that subject stabilizes, an attacker moves a very large stable balance into address A (e.g., via a large payment from an aggregated set of addresses, then letting it stabilize).
4. When `countVotes` executes [6](#0-5) , it reads A's now-large current balance and applies it as A's voting weight for the entire lookback window, even though A voted with negligible stake and only briefly held the large balance.
5. If A's inflated weight tips the sum for a malicious `op_address` (or an extreme numerical value) past the majority/median threshold in [7](#0-6) , the network permanently adopts the manipulated `op_list`/system variable.

### Citations

**File:** main_chain.js (L1619-1621)
```javascript
								async function saveSystemVote(payload) {
									console.log('saveSystemVote', payload);
									const { subject, value } = payload;
```

**File:** main_chain.js (L1751-1780)
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
	let values = [];
	for (let address in balances)
		values.push(`(${db.escape(address)}, ${balances[address]})`);
```

**File:** main_chain.js (L1806-1821)
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

**File:** main_chain.js (L1850-1902)
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
			if (constants.bTestnet && [3547796, 3548896, 3548898].includes(mci)) // workaround a bug
				ops = ["2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX", "2GPBEZTAXKWEXMWCTGZALIZDNWS5B3V7", "4H2AMKF6YO2IWJ5MYWJS3N7Y2YU2T4Z5", "DFVODTYGTS3ILVOQ5MFKJIERH6LGKELP", "ERMF7V2RLCPABMX5AMNGUQBAH4CD5TK4", "F4KHJUCLJKY4JV7M5F754LAJX4EB7M4N", "IOF6PTBDTLSTBS5NWHUSD7I2NHK3BQ2T", "O4K4QILG6VPGTYLRAI2RGYRFJZ7N2Q2O", "OPNUXBRSSQQGHKQNEPD2GLWQYEUY5XLD", "PA4QK46276MJJD5DBOLIBMYKNNXMUVDP", "RJDYXC4YQ4AZKFYTJVCR5GQJF5J6KPRI", "WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"];
			if (mci === 0) {
				storage.resetWitnessCache();
				storage.systemVars.op_list = []; // reset
			}
			storage.systemVars.op_list.unshift({ vote_count_mci: mci === 0 ? -1 : mci, value: ops, is_emergency });
			value = JSON.stringify(ops);
			if (is_emergency) {
				storage.resetWitnessCache();
				await conn.query(conn.dropTemporaryTable(votes_table));
			}
			break;
		
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
