### Title
Median system-vote counting (`countVotes`) throws an uncaught error when voters' balances vanish, bricking system-parameter updates and MC stabilization - (File: `main_chain.js`)

### Summary
`countVotes()` in `main_chain.js` is the ocore analog of `FeeSplitter.addFees()`: both compute a ratio/aggregate ("median share of votes" vs "total supply") derived from *current* on-chain balances of a set of participants, and both `throw`/revert when that aggregate unexpectedly becomes empty/zero because the underlying balances were spent away. In `FeeSplitter` this bricks selling; in ocore it bricks a required, protocol-level, per-stable-MCI system-parameter recount.

### Finding Description
`countVotes(conn, mci, subject, ...)` [1](#0-0)  is invoked during main-chain stabilization to recompute network-wide system parameters (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) from balance-weighted votes stored via `system_vote`/numerical-vote messages that any unprivileged unit poster can attach to a unit (see `system_vote` handling referenced across `writer.js`, `validation.js`, `composer.js`).

The function first collects every address that has *ever* cast a vote for `subject`: [2](#0-1) 

It then computes each voter's **current** unspent base-asset balance and populates a temporary `voter_balances` table — addresses with zero current balance are simply absent from this table because the balance query only returns addresses with unspent stable-good outputs: [3](#0-2) 

For the numeric-vote subjects (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`), the code computes a weighted median by summing `total_balance` across `numerical_votes CROSS JOIN voter_balances`: [4](#0-3) 

Because the join is against `voter_balances` (populated only from *currently non-zero* balances), any voter who has since spent all of their bytes disappears entirely from the join. If **all** voters for a given subject have spent their base-asset balance down to zero by the time of stabilization — a perfectly legal, unprivileged action (a normal payment) — `rows` becomes empty, `total_voted_balance` is `0`, the `for` loop never assigns `value`, and the function throws:
```
throw Error(`no median value for ` + subject);
```
This is the exact same bug class as `FeeSplitter.addFees()` reverting when `totalSupply()` returns `0` because `curvesTokenSupply - curvesTokenBalance` collapses to zero after all remaining tokens are withdrawn to ERC20 — in both cases a legitimate, attacker-controllable state transition (spending/withdrawing) makes the denominator/aggregate collapse to zero, and the code has no fallback path, only an unconditional revert/throw.

### Impact Explanation
`countVotes` runs as part of the deterministic main-chain-stabilization pipeline that every full node must execute identically. An uncaught `throw Error(...)` inside this async function is not defensively handled at the call sites shown, so it propagates as an unhandled exception/rejected promise during MC-index stabilization. This can:
- Halt/crash the node's stabilization processing (denial of service — "network unable to confirm new units" for that node), and
- If only some nodes hit the zero-balance state at the exact stabilization boundary (e.g., due to differing view of "current" balances relative to timing of a spend just before the trigger), it risks nodes disagreeing on whether stabilization at that MCI succeeds, which is a node-disagreement-on-validity/stability class issue.

Either way, since `op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` are consensus-critical system variables written into `system_vars` and consumed by TPS-fee/witness-list logic elsewhere, an unrecoverable exception here can freeze protocol parameter updates network-wide until the code is patched — the most severe of the FeeSplitter-analog outcomes (worse than "selling bricked for one user," this is a chain-wide liveness/consensus hazard).

### Likelihood Explanation
Reachability requires only that:
1. Some addresses cast `system_vote`/numerical votes for a subject (unprivileged, anyone can do this), and
2. All of those voting addresses subsequently spend their base-asset outputs to zero before the relevant MC-index stabilizes and `countVotes` runs for that subject.

An attacker (or even organic activity) can trivially arrange this by voting with a single, small, disposable address and then immediately spending it dry — no privileged role, hub cooperation, or timing race with other nodes is needed. The `while(true)` window-expansion loop even actively searches all the way back to `activation_timestamp` before giving up, so the throw is reliably triggered once the condition holds, not merely a rare corner case.

### Recommendation
Mirror the report's suggested fix pattern: detect the degenerate "no weighted votes remain" state explicitly and fail safe rather than throw an unhandled error that halts consensus processing. Concretely, in `main_chain.js`:
- If `rows.length === 0` (or `total_voted_balance === 0`) for the numeric-subject branch, skip updating `system_vars` for that stabilization pass (analogous to the existing `if (values.length === 0) return console.log(...)` early exit for the "no voters at all" case) instead of throwing, or retain the previously stored value for `subject` until a future recount produces a valid quorum.
- Wrap/guard `countVotes` call sites so that even if it does throw, the stabilization pipeline does not crash the whole node process, and instead surfaces the failure as a well-defined error/retry rather than an unhandled promise rejection.

### Proof of Concept
1. Address A (any unprivileged address) posts a unit containing a `system_vote` message with a numerical vote for `subject = 'base_tps_fee'`.
2. Address A subsequently spends all of its base-asset balance to zero (a normal payment to another address), before the MC index containing the aggregation window stabilizes.
3. No other address has voted for `base_tps_fee` within the window that still has a nonzero currently-tracked balance.
4. On stabilization, `countVotes(conn, mci, 'base_tps_fee', ...)` computes `rows = []` from the `numerical_votes CROSS JOIN voter_balances` query (line 1882-1889) because Address A is absent from `voter_balances` (its balance is 0), giving `total_voted_balance = 0` and no loop iterations to set `value`.
5. `value === undefined` at line 1900, and the function throws `Error("no median value for base_tps_fee")`, which is uncaught by any caller, disrupting main-chain-index stabilization for that node. [4](#0-3)

### Citations

**File:** main_chain.js (L1737-1737)
```javascript
async function countVotes(conn, mci, subject, is_emergency = 0, emergency_count_command_timestamp = 0) {
```

**File:** main_chain.js (L1741-1742)
```javascript
	const address_rows = await conn.query("SELECT DISTINCT address FROM system_votes WHERE subject=?", [subject]);
	let addresses = address_rows.map(r => r.address);
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
