### Title
Governance (OP list / system parameter) votes are weighted by instantaneous balance instead of a balance snapshot, allowing vote-weight to be minted and withdrawn to manipulate network-parameter outcomes - (File: `main_chain.js`)

### Summary
The `DEPLOYER` bug allowed a privileged role to temporarily inflate a voter's balance (`depositLP()`), let the vote happen, then drain it back out (`withdraw()`), swinging a DAO proposal without any lasting economic stake. `ocore` has a structurally identical weakness in its on-chain governance system (`system_vote` / `system_vote_count`, used to elect the Order Providers list and vote on `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`, `threshold_size`): the weight assigned to a vote is not the balance the voting address held when it cast the `system_vote`, but whatever balance that address happens to hold at the moment the votes are tallied. Any unprivileged unit poster can cast a vote from a nearly-empty address, then move a large sum into that same address just before/at the counting instant, and move the funds back out (or reuse them for another vote) immediately after, without ever putting capital at risk.

### Finding Description
`validation.js` lets any single-authored (non-AA) unit post a `system_vote` message for very little cost, from any address the author controls: [1](#0-0) 

When votes are tallied, `countVotes()` in `main_chain.js` determines each voter's weight by reading the address's **current** unspent, stable, good outputs — not a balance recorded at the time the `system_vote` unit was posted: [2](#0-1) 

These fresh balances are loaded into a temporary `voter_balances` table and then joined against `system_votes` / `op_votes` / `numerical_votes` purely to determine *which* addresses voted for *which* value within the lookback window; the actual weight contributed is always today's balance: [3](#0-2) [4](#0-3) 

Because there is no lock-up, bond, or "balance at the time of the vote" snapshot, an address only needs to hold funds at the single instant `countVotes` executes for a given `mci`/subject. `countVotes` is invoked once per stabilized `mci` for every pending `voteCountSubjects` entry (driven from `markMcIndexStable`) and can also be forced early via the `system_vote_count` mechanism referenced throughout `validation.js`/`main_chain.js`/`composer.js` (guarded only by `constants.SYSTEM_VOTE_COUNT_FEE`, i.e. payable by anyone, not a privileged role). This is the direct analog of the `DEPLOYER`'s `depositLP()` + `withdraw()` sequence: "deposit" weight right before the tally, then "withdraw" (spend/move) it right after.

### Impact Explanation
This lets any user manipulate consensus-critical network governance without economic cost proportional to influence:
- Sway election of the Order Provider (`op_list`) set, which determines main-chain stability and unit ordering.
- Sway `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`, and `threshold_size`, which control transaction fees and TPS-based congestion pricing network-wide.
By funneling the same coin stock through several addresses in sequence (each holding the funds only for the tally instant), an attacker can inflate the "total_balance" counted for a chosen value far beyond their real stake, then reuse the same coins to do it again for the next subject or the next OP-list re-vote, exactly as the `DEPLOYER` reused the DAOVault's own balance to swing votes and then reclaim it. This is a governance-manipulation / fund-freezing-adjacent impact on protocol parameters, not merely a UX quirk.

### Likelihood Explanation
Casting a `system_vote` and moving BYTES between one's own addresses are both fully permissionless, cheap, ordinary operations available to any unprivileged unit poster — no special role, no light-client/network trust assumption, no cross-repository dependency. The only requirement is timing the transfer to coincide with the `mci` at which `countVotes` executes for the desired subject, which is observable on-chain since MC stabilization is public.

### Recommendation
- Weight `system_vote` by the balance the voting address held at (or continuously since) the time it cast the vote, e.g. record the balance at vote-casting time in `system_votes`/`numerical_votes`/`op_votes`, or require the balance to be locked/unspent from vote time through count time.
- Alternatively, require a minimum holding period (e.g., balance must be unchanged for N stable MCIs before it counts) before it can contribute to `countVotes`.
- Consider requiring outputs used for vote weight to be provably unspent throughout the vote's active window rather than merely unspent at the counting instant.

### Proof of Concept
1. Attacker controls address `A` (near-zero balance) and address `B` (holds `X` BYTES).
2. `A` posts a `system_vote` message for subject `tps_fee_multiplier` with the attacker's preferred value (validated per `validation.js:1893-1907`).
3. Immediately before the `mci` at which `countVotes(conn, mci, 'tps_fee_multiplier')` will execute (i.e., before that MCI stabilizes), attacker sends a payment of `X` BYTES from `B` to `A`.
4. `countVotes` computes `A`'s balance via the query in `main_chain.js:1757-1773`, now including the freshly received `X` BYTES, and adds this to the tally for the attacker's chosen value (`main_chain.js:1882-1902`).
5. After the vote is counted and `system_vars` updated, attacker moves the `X` BYTES from `A` back to `B` (or another address `C`) and repeats the same maneuver to inflate a different vote (e.g., `op_list`) in a subsequent MCI, reusing the same capital with no lasting stake — mirroring the `DEPLOYER`'s `depositLP()` → vote → `withdraw()` cycle in the referenced report.

### Citations

**File:** validation.js (L1844-1852)
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
```

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
