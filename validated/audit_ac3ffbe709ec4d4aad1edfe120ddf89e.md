### Title
Uncaught `Error` thrown in `countVotes()` when fewer than `COUNT_WITNESSES` distinct addresses win the `op_list` vote — halts main-chain stabilization (File: `main_chain.js`)

### Summary
`countVotes()` selects the new operator (witness) list by tallying `system_vote` messages weighted by voter balance, taking the top `constants.COUNT_WITNESSES` (12) `op_address` values ordered by `SUM(balance) DESC`, exactly like `CultureIndex.getTopVotedPiece()` selects the highest-weight candidate from a heap. If the number of distinct addresses that actually received votes is less than 12, the function unconditionally throws, which propagates out of `markMcIndexStable()` / `advanceMcStability()` and aborts main-chain stabilization for the whole node.

### Finding Description
`countVotes()` queries the top-voted `op_address` values: [1](#0-0) 

```
const op_rows = await conn.query(`SELECT op_address, SUM(balance) AS total_balance
    FROM ${votes_table}
    CROSS JOIN voter_balances USING(address)
    WHERE timestamp>=?
    GROUP BY op_address
    ORDER BY total_balance DESC, op_address
    LIMIT ?`,
    [since_timestamp, constants.COUNT_WITNESSES]
);
...
let ops = op_rows.map(r => r.op_address);
if (ops.length !== constants.COUNT_WITNESSES)
    throw Error(`wrong number of voted OPs: ` + ops.length);
```

This mirrors the root cause of the reported `CultureIndex` bug: a "top‑N by weight" selection is trusted to always satisfy a hard downstream invariant (`quorumVotes` in the original bug, exactly `COUNT_WITNESSES` distinct winners here), but nothing guarantees that invariant holds. If turnout is low, or votes are concentrated on fewer than 12 distinct `op_address` values (which can happen naturally, exactly as the original report notes for the quorum case, or can be engineered by a holder splitting/concentrating votes), `ops.length` can be `< 12` (or in edge cases with ties at the `LIMIT` boundary, ambiguous), and the function throws.

`countVotes()` is invoked from the stability-advance code path, `advanceMcStability` → `updateStableMcFlag` → `markMcIndexStable`, once for every relevant `mci` as soon as an mci becomes stable and a vote-count subject is due: [2](#0-1) 

This code is not wrapped to recover gracefully; an uncaught `Error` here interrupts the write/stabilization flow of the node processing the unit that made the corresponding `mci` stable.

### Impact Explanation
Because vote counting happens deterministically from data already committed to stable, "good" units, every full node evaluating the same `mci` will independently hit the identical code path and throw the identical error. This is not a localized wallet crash — it is a deterministic protocol-logic bug that fires on all nodes simultaneously once the vote tally under-produces winners, halting main-chain stabilization and therefore the node's ability to confirm/finalize further units, matching the "network unable to confirm new units" impact class. Unlike the `CultureIndex` case (where only the auctioning of one bogus piece is stuck while other pieces can theoretically still exist unprocessed behind it), here the entire consensus advancement pipeline for the node depends on this call completing without throwing, so the blast radius is broader.

### Likelihood Explanation
The precondition (fewer than `COUNT_WITNESSES` distinct `op_address` winners within the sliding vote-timeframe window) can occur naturally under low voter turnout or concentrated voting, exactly as the original report emphasizes for the quorum-starved top piece ("this scenario can happen naturally, without anyone being malicious"). It can also be induced by any unprivileged holder who casts `system_vote` messages concentrating stake-weighted votes on fewer than 12 addresses (or by simply not voting at all beyond a handful of addresses), similarly to how the `ERC20TokenEmitter.buyToken` PoC inflated a single fake candidate's weight to disrupt the `dropTopVotedPiece` selection/threshold interaction. I was not able to fully verify from the indexed code whether there exist additional guards elsewhere (e.g., a minimum voter/candidate floor before `countVotes` is invoked) that would reduce likelihood — a background agent with full repo access should check `validation.js`'s `system_vote` handling and `writer.js`'s `system_vote` persistence path for any such safeguard before finalizing severity.

### Recommendation
- Do not `throw` when `ops.length !== constants.COUNT_WITNESSES`; instead fall back to the previous stable `op_list` (skip updating it for this vote-count cycle) and log/flag the anomaly, analogous to keeping the previous top-voted-but-unqualified item out of the critical path in the `CultureIndex` fix suggestion.
- Add an explicit minimum-candidate check before running the vote tally, and define deterministic tie-breaking/backfill behavior when fewer than `COUNT_WITNESSES` addresses cross the participation threshold, so the network can continue confirming units instead of halting.

### Proof of Concept
A concrete PoC would require constructing a sequence of stable, good units posting `system_vote` messages for the `op_list` subject from a set of addresses whose balances vote for fewer than 12 distinct `op_address` values (e.g., all voters vote for the same 5 addresses) within the sliding vote timeframe, then stabilizing the `mci` that triggers `countVotes(conn, mci, 'op_list')`. This is structurally the same setup as the original PoC — accumulate balance-weighted voting power and drive the "top-N selection" mechanism into a state where the downstream hard-coded invariant (`ops.length === COUNT_WITNESSES`) cannot be satisfied — I did not execute this against a running node/test harness since that requires runtime/database access beyond the indexed source I could inspect.

### Citations

**File:** main_chain.js (L1657-1663)
```javascript
					async function() {
						// vote count must be processed last, after all system_votes, and once for the entire mci
						for (let subject of voteCountSubjects)
							await countVotes(conn, mci, subject);
						// next op
						updateRetrievable();
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
