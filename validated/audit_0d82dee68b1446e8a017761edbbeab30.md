### Title
Malformed `op_list` vote count permanently halts main-chain stabilization - (File: `main_chain.js`)

### Summary
Any unprivileged unit poster can post a `system_vote` (`op_list`) and a `system_vote_count` message, both of which are validated but not deeply enough to guarantee that vote tallying will succeed. When the tally for `op_list` is finally computed at stabilization time in `countVotes()`, the code assumes exactly `constants.COUNT_WITNESSES` (12) distinct `op_address` rows will be returned. If that assumption fails, the node `throw`s an `Error`, which is unrecoverable and deterministic across all full nodes, permanently blocking that MCI from stabilizing — the direct analog of the LimboDAO "stuck proposal" bug: a single mandatory, unskippable state-transition step becomes unexecutable and blocks all further progress.

### Finding Description
`countVotes()` is invoked from `markMcIndexStable()` → `addBalls()` once per `system_vote_count` subject collected while stabilizing an MCI: [1](#0-0) 

For the `op_list` subject it selects the top `COUNT_WITNESSES` (12) `op_address` values ordered by summed voter balance, then hard-asserts the result set is exactly 12 rows, `throw`-ing otherwise: [2](#0-1) 

This is reachable by an ordinary user because:
- `system_vote` (`op_list`) messages only require the address list to be valid, sorted, and unique — anyone can post an `op_list` vote for as few as `COUNT_WITNESSES` distinct OP candidates that they choose: [3](#0-2) 
- `system_vote_count` messages are validated only for having a recognized subject and being singular per unit — again postable by any address, not privileged and not restricted to AAs (in fact explicitly disallowed for AAs, meaning any regular wallet/unit poster can trigger the count): [4](#0-3) 

Because `countVotes()` restricts to `LIMIT COUNT_WITNESSES` op-addresses ordered by `total_balance DESC, op_address` from whichever `op_address` values happen to exist in `op_votes`/`system_votes` within the computed `since_timestamp` window, an attacker can engineer a scenario where the distinct number of voted-for OP addresses within the active voting window is less than 12 (e.g., if OP-list voting activity is thin, or if all voters coordinate votes for fewer than 12 distinct candidates, or a vote-count command is triggered right after votes for only a handful of distinct OPs exist). The `GROUP BY op_address` then yields fewer than 12 rows, `ops.length !== constants.COUNT_WITNESSES` is true, and the node throws unconditionally — this is deterministic code executed identically by every full node validating/stabilizing this MCI, since `markMcIndexStable` is a core consensus routine invoked from `advanceMcStability`/`updateMainChain`, which every full node must run to progress: [5](#0-4) [6](#0-5) 

Once this uncaught exception fires inside the transaction wrapping `markMcIndexStable`, the affected MCI can never be marked stable by any node that reaches this code path (the throw is unconditional given the same DB state, so retries reproduce the same crash). Because MC stability is the gating mechanism for confirming further units (subsequent units cannot stabilize until earlier MCIs stabilize), and because `handleAATriggers`, `updateTpsFees`, and further unit confirmation all live downstream of this same synchronous stabilization chain, the entire network becomes unable to confirm new units past this point — analogous to LimboDAO's single "current proposal" slot becoming permanently unexecutable and blocking all future proposals.

### Impact Explanation
This crashes the deterministic consensus code path (`markMcIndexStable` → `addBalls` → `countVotes`) that every full node executes identically when advancing MC stability. Because the crash is data-driven and reproducible from the same persisted votes, it is not a transient/process-level fault: every node that attempts to stabilize the affected MCI will hit the same `throw Error("wrong number of voted OPs: " + ops.length)`. This satisfies the "network unable to confirm new units" acceptance criterion: no further MCI can stabilize, no further AA triggers fire, and TPS-fee accounting halts, effectively freezing the ledger's forward progress network-wide until node operators can manually intervene (patch/redeploy or corrective DB surgery), which is outside protocol-level recovery.

### Likelihood Explanation
Reaching this requires only unprivileged, already-validated message types (`system_vote` with subject `op_list`, and `system_vote_count` with payload `op_list`), both explicitly permitted for ordinary unit authors and explicitly forbidden only for AAs. The condition that triggers the crash — fewer than 12 distinct OP addresses having received votes within the sliding vote-timeframe window at the moment counting occurs — is plausible in practice especially: (a) early after the vote feature activates when voting participation for a full slate of distinct OPs is sparse, (b) if voters concentrate stake behind fewer than 12 unique addresses, or (c) via deliberate manipulation by an attacker who posts `op_list` votes for fewer than 12 distinct OPs from addresses holding sufficient stake to satisfy the `SYSTEM_VOTE_MIN_SHARE` threshold, then posts a `system_vote_count`. This does not require compromising witnesses or the network — a single well-funded (or many small) attacker(s) issuing standard unit types can attempt it.

### Recommendation
Do not let vote counting throw an unrecoverable, unconditional `Error` on data conditions influenced by unprivileged senders. Options:
- If fewer than `COUNT_WITNESSES` distinct OPs are available in the sliding window, expand the window (similar to the existing balance-share expansion loop) before falling back to a defined, safe behavior (e.g., keep the previous stable OP list) rather than throwing.
- Treat "insufficient candidate diversity" as a recoverable case: skip updating `op_list` for this vote-count trigger (log/no-op) instead of crashing consensus-critical code, and/or reject/ignore `system_vote_count` messages until there is a validation-time guarantee that at least `COUNT_WITNESSES` distinct OP addresses have active votes.
- Add validation-time checks (in `validateInlinePayload` for `system_vote_count`) that verify, at the time the message is included, that the vote-count would be well-defined, rejecting the message otherwise, so malformed sequences never make it into a stable unit in the first place.

### Proof of Concept
1. Wait for `constants.v4UpgradeMci` (system voting active). 
2. From a small set of addresses controlling collectively at least `SYSTEM_VOTE_MIN_SHARE * TOTAL_WHITEBYTES` of stable balance, each post a `system_vote` message with `subject: "op_list"` and identical/overlapping `value` arrays that name fewer than 12 distinct OP addresses in total across all voters within the relevant time window (validation only requires the array itself to have exactly `COUNT_WITNESSES` sorted-unique addresses per message — cross-message distinctness of the union of voted candidates is not enforced) — see [3](#0-2) .
3. Post a `system_vote_count` message with payload `"op_list"` from any regular (non-AA) address — see [4](#0-3) .
4. Once this unit's MCI becomes eligible for stabilization, `markMcIndexStable` collects the `system_vote_count` subject and calls `countVotes(conn, mci, "op_list")` — see [1](#0-0) .
5. Inside `countVotes`, the `op_rows` query groups by `op_address` over the active window; if the distinct count of candidate OP addresses actually receiving votes is less than 12, `ops.length !== constants.COUNT_WITNESSES` and the process throws — see [2](#0-1) .
6. Every full node executing this same deterministic logic on the same persisted vote data crashes/aborts at the same point, and the affected MCI (and everything after it) can never stabilize, halting unit confirmation network-wide.

### Citations

**File:** main_chain.js (L470-475)
```javascript
// tries to advance the stability point by 1 mci
function advanceMcStability(conn, batch, last_added_unit, onDone) {
	if (!onDone)
		return new Promise(resolve => advanceMcStability(conn, batch, last_added_unit, (arrStabilizedMcis, bStabilizedAATriggers) => resolve({ arrStabilizedMcis, bStabilizedAATriggers })));
	let bStabilizedAATriggers = false;
	let arrStabilizedMcis = [];
```

**File:** main_chain.js (L1288-1291)
```javascript
function markMcIndexStable(conn, batch, mci, onDone){
	if (!onDone)
		return new Promise(resolve => markMcIndexStable(conn, batch, mci, resolve));
	profiler.start();
```

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

**File:** validation.js (L1861-1873)
```javascript
				case "op_list":
					const arrOPs = payload.value;
					if (!isArrayOfLength(arrOPs, constants.COUNT_WITNESSES))
						return callback("OP list must be an array of " + constants.COUNT_WITNESSES);
					if (!arrOPs.every(isValidAddress))
						return callback("all OPs must be valid addresses");
					let prev_op = arrOPs[0];
					for (let i = 1; i < arrOPs.length; i++){
						const op = arrOPs[i];
						if (op <= prev_op)
							return callback("OP list must be sorted and unique");
						prev_op = op;
					}
```

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
