### Title
Unbounded `system_vote_count` trigger vs. unachievable OP quorum causes consensus-halting crash in `countVotes()` - (File: main_chain.js)

### Summary
`BlackGovernor.sol`'s bug class — an unrestricted ability to *trigger* a governance action combined with a *quorum* metric computed over a different, drifting population that can become unachievable — has a direct analog in ocore's on-chain OP (order provider / witness list) voting mechanism. Any address can post a `system_vote_count` unit for `op_list` at any time with no minimum participation gate [1](#0-0) , but the counting logic in `countVotes()` requires exactly `constants.COUNT_WITNESSES` (12) *distinct* OP addresses to have received votes from currently-funded voters within a computed time window, or it throws an unrecoverable `Error` [2](#0-1) .

### Finding Description
`system_vote_count` messages can be authored by any unprivileged address and are validated with essentially no restriction beyond being a known subject and one-per-unit [1](#0-0) . This is the "proposal" side of the mechanism — there is no threshold requirement analogous to `proposalThreshold()`.

When such a unit stabilizes, `countVotes(conn, mci, 'op_list', ...)` is invoked from `markMcIndexStable()` as part of core, deterministic main-chain stabilization logic executed identically by every full node [3](#0-2) .

Inside `countVotes()`, voter balances are computed only from addresses with non-zero, currently unspent, stable-good base-asset outputs (`voter_balances` temp table) [4](#0-3) . The vote-counting time window (`since_timestamp`) is expanded backward in one-year steps until either enough voted balance share is reached or the window reaches the very first ever vote for the subject [5](#0-4) . The OP candidates are then aggregated with an INNER JOIN (`CROSS JOIN voter_balances USING(address)`) against this balance table, meaning any voter whose current on-chain balance is zero is silently excluded from the count entirely, along with all the OP addresses that voter uniquely supported [6](#0-5) .

If fewer than exactly `COUNT_WITNESSES` (12) distinct OP addresses remain after this join-and-window filtering, the code does not degrade gracefully — it throws:
```
throw Error(`wrong number of voted OPs: ` + ops.length);
``` [7](#0-6) 

This mirrors the reported governance-deadlock bug class exactly: the mechanism to *initiate* the vote count (posting `system_vote_count`) is gated by an essentially trivial, currently-active condition (any address, any time), while the mechanism to *successfully complete* it (quorum of 12 distinct funded OP-address supporters) depends on a different, drifting population — the set of voters who still hold spendable base-asset balance and who collectively still name 12 distinct addresses. As voters spend down their balances, consolidate, or stop actively re-voting, this quorum condition can become unachievable, just as growing/stale `smNFTBalance` made `BlackGovernor`'s 4% quorum unachievable relative to active participation.

### Impact Explanation
`countVotes()` is invoked synchronously within the deterministic, consensus-critical MC-stabilization path (`markMcIndexStable` → `addBalls` → `saveSystemVote`/vote-count dispatch) that every full node executes identically for the same MCI [8](#0-7) . The thrown `Error` is not caught anywhere in this call chain (no `try/catch` wraps the `await countVotes(...)` call or its internals), so it becomes a crash / uncaught exception at exactly the same point in exactly the same MCI on every full node in the network simultaneously — since the underlying state (balances, votes, timestamps) is identical DAG-derived data. This is a "network unable to confirm new units" scenario: MC stabilization for that MCI (and beyond) cannot complete, halting confirmation of the entire DAG, not merely a single node's local desync.

### Likelihood Explanation
Reaching this condition does not require any privileged role — it only requires:
1. An unprivileged unit poster submitting a `system_vote_count` unit for `op_list` (freely allowed post-`v4UpgradeMci`) [1](#0-0) , and
2. The current pool of funded voters, combined over the expanding time window, collectively naming fewer than 12 distinct OP addresses — plausible whenever voter participation is thin, concentrated, or preloaded/genesis voters have since spent down their balances, since the balance join silently drops such voters and their unique OP nominations [4](#0-3) .

Because the trigger side has essentially no gating and the quorum side depends on an evolving, spendable-balance-based population disjoint from "who is allowed to trigger the count," this is a realistic Medium/High-likelihood condition as the network matures and voter balances shift, exactly as flagged for the smNFT-balance quorum drift in the original report.

### Recommendation
- Do not `throw` an unrecoverable `Error` when fewer than `COUNT_WITNESSES` distinct OP addresses are found; instead handle the shortfall deterministically and non-fatally (e.g., retain the previous `op_list`, or define an explicit, agreed-upon fallback ordering) so stabilization can proceed identically on all nodes without crashing.
- Align the "who can trigger a vote count" gating with "who is counted for quorum": e.g., require a minimum aggregate/participating balance or minimum distinct-candidate count before permitting a `system_vote_count` unit to be posted/validated, mirroring the recommendation to align `BlackGovernor`'s quorum base with its proposal threshold.
- Consider a dual/fallback condition (e.g., "use previous stable `op_list` if fewer than `COUNT_WITNESSES` distinct funded candidates are found") rather than an unconditional invariant violation.
- Add explicit monitoring/alerting for the shrinking distinct-OP-candidate count and the size of the `since_timestamp` expansion, so degrading participation is visible before it becomes a hard failure.

### Proof of Concept
1. Let genesis preload the mandatory 12-address `op_list` votes from a small fixed set of addresses, as done in `initSystemVarVotes` [9](#0-8) .
2. Have those preloaded voter addresses spend down their entire base-asset balance over time (an entirely legitimate, unprivileged action) so they no longer appear in `voter_balances` during a later `countVotes()` run [10](#0-9) .
3. Ensure no other sufficiently-broad wave of `system_vote` op_list votes has since spread support across 12 distinct addresses among currently-funded voters within the expanding `since_timestamp` window [5](#0-4) .
4. Any unprivileged address posts a `system_vote_count` unit with payload `"op_list"` [1](#0-0) .
5. When this unit stabilizes, `countVotes()` runs, the `op_rows` query returns fewer than 12 groups, and the deterministic `throw Error("wrong number of voted OPs: " + ops.length)` fires identically on every full node processing that MCI, halting further main-chain stabilization [2](#0-1) .

### Citations

**File:** validation.js (L1913-1923)
```javascript
		case "system_vote_count":
			if (objValidationState.last_ball_mci < constants.v4UpgradeMci && !constants.bDevnet)
				return callback("cannot count votes for system params yet");
			if (objValidationState.bAA)
				return callback("AA cannot trigger system vote count");
			if (objValidationState.bHasSystemVoteCount)
				return callback("can be only one system vote count");
			objValidationState.bHasSystemVoteCount = true;
			if (!["op_list", "threshold_size", "base_tps_fee", "tps_interval", "tps_fee_multiplier"].includes(payload))
				return callback("unknown subject in vote count");
			return callback();
```

**File:** main_chain.js (L1657-1667)
```javascript
					async function() {
						// vote count must be processed last, after all system_votes, and once for the entire mci
						for (let subject of voteCountSubjects)
							await countVotes(conn, mci, subject);
						// next op
						updateRetrievable();
					}
				);
			}
		);
	}
```

**File:** main_chain.js (L1757-1780)
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
	let values = [];
	for (let address in balances)
		values.push(`(${db.escape(address)}, ${balances[address]})`);
```

**File:** main_chain.js (L1801-1805)
```javascript
	await conn.query(`CREATE TEMPORARY TABLE voter_balances (
		address CHAR(32) NOT NULL PRIMARY KEY,
		balance BIGINT NOT NULL
	)`);
	await conn.query(`INSERT INTO voter_balances (address, balance) VALUES ` + values.join(', '));
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

**File:** initial_votes.js (L46-62)
```javascript
	const arrPreloadedVoters = constants.bDevnet
		? [require('./chash.js').getChash160('')]
		: (constants.bTestnet
			? ['EJC4A7WQGHEZEKW6RLO7F26SAR4LAQBU']
			: ['3Y24IXW57546PQAPQ2SXYEPEDNX4KC6Y', 'G4E66WLVL4YMNFLBKWPRCVNBTPB64NOE', 'Q5OGEL2QFKQ4TKQTG4X3SSLU57OBMMBY', 'BQCVIU7Y7LHARKJVZKWL7SL3PEH7UHVM', 'U67XFUQN46UW3G6IEJ2ACOBYWHMI4DH2']
		);
	for (let address of arrPreloadedVoters) {
		await conn.query(
			`INSERT OR IGNORE INTO system_votes (unit, address, subject, value, timestamp) VALUES
			('', '${address}', 'op_list', '${strOPs}', ${timestamp}),
			('', '${address}', 'threshold_size', ${threshold_size}, ${timestamp}),
			('', '${address}', 'base_tps_fee', ${base_tps_fee}, ${timestamp}),
			('', '${address}', 'tps_interval', ${tps_interval}, ${timestamp}),
			('', '${address}', 'tps_fee_multiplier', ${tps_fee_multiplier}, ${timestamp})
		`);
		const values = arrOPs.map(op => `('', '${address}', '${op}', ${timestamp})`);
		await conn.query(`INSERT OR IGNORE INTO op_votes (unit, address, op_address, timestamp) VALUES ` + values.join(', '));
```
