### Title
System-vote OP-list tally can `throw Error` and halt MC stabilization on every full node when fewer than `COUNT_WITNESSES` distinct addresses receive votes - (File: main_chain.js)

### Summary
`countVotes()` in `main_chain.js` tallies `system_vote` messages (a native, unprivileged, single-unit message type any address can post) weighted by each voter's stable balance, and uses the result to update consensus-critical system variables such as `op_list` (the order-provider/witness list). For the `op_list` subject, it selects the top `constants.COUNT_WITNESSES` `op_address` values by summed voted balance and then hard-`throw`s if the count of returned rows is not exactly `COUNT_WITNESSES`.

### Finding Description
Any address can post a `system_vote` unit voting for a set of OP addresses; this only requires posting a normal unit, i.e., it is reachable by an unprivileged unit poster. `countVotes()` aggregates these votes into `op_votes`/`voter_balances` and runs: [1](#0-0) 
which selects `SUM(balance)` grouped by `op_address`, orders by `total_balance DESC, op_address`, and `LIMIT`s to `COUNT_WITNESSES`. If, at the point `countVotes` runs for a given MCI, fewer than `COUNT_WITNESSES` distinct `op_address` values exist among the votes that satisfy the `since_timestamp` window (e.g. because the "vote timeframe" that is dynamically shrunk/expanded based on total voted share, `SYSTEM_VOTE_MIN_SHARE`, still leaves too few distinct voted OP candidates, or because most votes are dust-balance votes that get diluted/expired out of the window while only a handful of addresses remain with in-window votes), the query returns fewer than `COUNT_WITNESSES` rows and the code unconditionally throws: [2](#0-1) 

This mirrors the `VoterV3.poke()` bug class in the external report: a `require`/`throw` on a computed value that can legitimately go to an unexpected boundary (zero pool weight there; fewer-than-expected distinct winners here) turns a routine, externally-triggerable aggregation step into an unconditional revert instead of gracefully handling the edge case (e.g., falling back to the previous OP list or continuing with the smaller set), exactly as the report recommends replacing `require` with an `if`/`continue`.

`countVotes()` is invoked as part of stabilizing a main-chain unit (it is exported from `main_chain.js` and called from the stabilization pipeline that runs identically on every full node), so any `throw` here is not a local wallet error — it aborts the write/stabilization transaction on every node that processes that MCI, and because the vote/timestamp state that produced the failing count is itself derived from the DAG (agreed-upon `system_votes` table content and `since_timestamp` window), all honest full nodes hit the same throw deterministically.

### Impact Explanation
An unconditional `throw Error` inside the MC-stabilization vote-counting logic that executes identically on every node is a "network unable to confirm new units" condition once triggered: MCI stabilization for that index cannot complete, and normal witness/order-provider list updates would be blocked. This satisfies the accepted-impact bar ("a network unable to confirm new units") from the validation criteria, distinguishing it from a merely cosmetic or single-node bug.

### Likelihood Explanation
Reaching the vulnerable branch requires the `system_votes` history for `op_list` to contain fewer than `COUNT_WITNESSES` distinct `op_address` candidates within the dynamically-computed `since_timestamp` window at the moment `countVotes` executes. This is plausible in low-participation periods, right after a chain/testnet's OP-vote activation MCI, or if an attacker/actor structures many low-balance votes for a fragmented set of addresses so that the window-expansion loop (`SYSTEM_VOTE_MIN_SHARE` check) still ends up admitting a set of candidates whose count is under `COUNT_WITNESSES` after grouping. I could not fully verify from the available code slices whether earlier validation (in `validation.js`, which also references `COUNT_WITNESSES`/`op_votes`) enforces a minimum number of distinct OP addresses per vote or a floor guaranteeing at least `COUNT_WITNESSES` candidates always exist in the table before `countVotes` runs; this bounds my confidence and would need to be confirmed by tracing the full `system_vote` validation path and the `SYSTEM_VOTE_MIN_SHARE`/expansion-loop guarantees, which the index did not fully expose to me. Given this uncertainty, I flag this as a probable but not fully proven analog.

### Recommendation
Replace the hard `throw Error("wrong number of voted OPs: ...")` with resilient handling: if fewer than `COUNT_WITNESSES` distinct OP candidates are found, fall back to retaining the previous `op_list` value (skip the update for this MCI) rather than aborting stabilization, analogous to the report's recommendation of turning the reverting `require` into a non-reverting `if (...) continue;`.

### Proof of Concept
Not independently reproducible from static analysis alone — verifying triggerability requires tracing (1) the full `system_vote`/`op_list` message validation rules in `validation.js` to confirm whether they permit a state where fewer than `COUNT_WITNESSES` distinct addresses have qualifying in-window votes, and (2) the `since_timestamp` expansion loop's guarantees. This would need to be exercised in a running/test ocore node (e.g., a unit test seeding `system_votes` with a small number of distinct OP addresses across a small total balance share and then calling `countVotes` for `op_list`) to confirm the `throw` fires and halts stabilization, which I was not able to execute in this read-only investigation.

### Citations

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
