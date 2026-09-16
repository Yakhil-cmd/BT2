### Title
System-parameter vote weight is read live at count time instead of being snapshotted to the vote's cast time, letting a self-triggered `system_vote_count` be timed against a temporarily inflated balance - ([File: main_chain.js])

### Summary
`countVotes()` in `main_chain.js` tallies `system_vote` messages (subject `op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) by re-reading each voter's **current** confirmed balance at the moment the tally runs, not the balance the voter held when the vote was cast. The tally itself is triggered by an ordinary, unprivileged `system_vote_count` message that any unit author can post at any time of their choosing. This lets an attacker cast a `system_vote`, wait until (or arrange for) their address to briefly hold a large balance, and then fire the `system_vote_count` trigger at that exact moment to have their vote counted with inflated weight, before moving the funds elsewhere. This is the same root-cause pattern as the referenced report: the "voting power" used to decide an outcome is evaluated at a different, attacker-influenced point in time than when the vote was actually cast.

### Finding Description
Any address can post a `system_vote` message (validated in `validation.js`) recording its preference for a subject with a timestamp: [1](#0-0) 

Counting is not automatic per-MCI; it is explicitly requested by a `system_vote_count` message, which any non-AA author may include in a unit, naming one of the five subjects: [2](#0-1) 

When that unit stabilizes, the subject is queued and `countVotes()` is invoked once for the MCI: [3](#0-2) [4](#0-3) 

Inside `countVotes()`, the weight assigned to every voter (including votes cast long ago) is the address's balance **as of the moment the tally executes** — a live query, not a snapshot tied to when the vote message was created: [5](#0-4) 

The subsequent median/top-N computation (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`, `op_list`) uses exactly this live balance as the weighting denominator/numerator: [6](#0-5) [7](#0-6) 

Because (a) the vote's expressed choice can be posted at time T1 while (b) its counted weight is whatever balance the address holds at time T2 (the moment someone — potentially the same attacker — posts the `system_vote_count` trigger), an attacker fully controls T2. This is structurally identical to the Party `totalVotingPower` bug: the value used to decide the outcome is not pinned to the same reference time as the individual votes it aggregates, so it can be pumped or deflated independently of genuine, sustained stake.

### Impact Explanation
The subjects controlled by this vote are core consensus parameters consumed everywhere:
- `op_list` becomes the witness/OP set used for DAG stability (`storage.getOpList`, used in `validateWitnesses`), directly affecting whether/when units become stable.
- `threshold_size` drives `getOversizeFee`, and `base_tps_fee`/`tps_interval`/`tps_fee_multiplier` drive TPS-fee requirements that determine whether a unit is valid/affordable: [8](#0-7) 

A wealthy but not necessarily long-term-committed actor can time a large, transient balance (e.g., a large incoming payment they control) together with a self-posted `system_vote_count` trigger to swing these parameters — e.g., pushing `base_tps_fee`/`tps_fee_multiplier` to values that make honest fee payment difficult (network unable to confirm new units for ordinary users), or swaying the elected OP set — without needing to keep the capital committed once the count has run. This qualifies as a network-level parameter-manipulation/DoS risk (Medium/High), reachable entirely by unprivileged unit posters through the standard `system_vote` / `system_vote_count` message types.

### Likelihood Explanation
Both `system_vote` and `system_vote_count` are ordinary application messages available to any address (not AA, not privileged), require no special role, and the trigger has no cooldown, minimum vote age, or "only one count per time window" guard beyond "one system_vote_count per unit" (`bHasSystemVoteCount`) and per-MCI-processed-once semantics; anyone can repeatedly post new triggering units. Executing the attack only requires timing a balance change with a self-authored trigger unit, which is straightforward for a well-resourced actor and does not require compromising any node or peer.

### Recommendation
Decouple "when a vote is weighed" from "when the tally is triggered": weight each `system_vote` by the balance the address held at (or shortly before) the vote's own recorded timestamp/MCI rather than by the balance read live when `countVotes()` executes, e.g. by snapshotting balances into `system_votes`/`numerical_votes`/`op_votes` at insertion time (`saveSystemVote`) instead of recomputing them from current UTXOs inside `countVotes`. Alternatively, require the counted balance snapshot to be tied to a fixed, non-attacker-chosen reference point (such as the MCI a fixed period before the trigger unit, rather than "now"), so that transient balance inflation immediately before a self-posted `system_vote_count` cannot skew the aggregated result.

### Proof of Concept
1. Attacker address `A` posts a `system_vote` message voting `base_tps_fee = X` (or any subject/value) while holding only a small balance; this is stored with a timestamp in `system_votes`/`numerical_votes` (`saveSystemVote`, `main_chain.js:1619-1651`).
2. Attacker waits until `A` momentarily receives a very large payment (self-funded, e.g., moved from another wallet the attacker controls), so `A`'s current on-chain balance is large.
3. While the balance is inflated, attacker posts a `system_vote_count` message for the same subject (`validation.js:1913-1923`), which becomes queued in `voteCountSubjects` on stabilization (`main_chain.js:1575-1578`) and triggers `countVotes()` for that MCI (`main_chain.js:1657-1663`).
4. `countVotes()` reads `A`'s balance live (`main_chain.js:1753-1780`) at this exact moment and applies it to the vote value `A` cast back in step 1, giving that historical vote outsized weight in the median/top-N calculation (`main_chain.js:1878-1902` / `1850-1865`).
5. Attacker immediately moves the funds out of `A` after the count completes; the resulting `system_vars` value (e.g. `base_tps_fee`) persists network-wide even though `A` no longer holds the balance that justified its weight.

### Citations

**File:** validation.js (L1844-1859)
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
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["subject", "value"]))
				return callback("unknown fields in " + objMessage.app);
			if (typeof payload.subject !== "string")
				return callback("subject must be string");
			if (!payload.value)
				return callback("no value in " + objMessage.app);
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

**File:** main_chain.js (L1575-1578)
```javascript
											case 'system_vote_count': // will be processed later, when we finish this mci
												if (!voteCountSubjects.includes(payload))
													voteCountSubjects.push(payload);
												break;
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

**File:** main_chain.js (L1753-1780)
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
	let values = [];
	for (let address in balances)
		values.push(`(${db.escape(address)}, ${balances[address]})`);
```

**File:** main_chain.js (L1850-1865)
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

**File:** storage.js (L1147-1166)
```javascript
function getOversizeFee(objUnitOrSize, mci, bAA) {
	let size;
	if (typeof objUnitOrSize === "number")
		size = objUnitOrSize; // must be already without temp data fee
	else if (typeof objUnitOrSize === "object") {
		if (!objUnitOrSize.headers_commission || !objUnitOrSize.payload_commission)
			throw Error("no headers or payload commission in unit");
		// AA-generated units pay the oversize fee based on the unit size excluding its payment messages to avoid swelling the fee while spending dust outputs
		const payload_commission = (bAA && mci >= constants.pemCurvesFixMci)
			? objectLength.getTotalPayloadSize({ ...objUnitOrSize, messages: objUnitOrSize.messages.filter(message => message.app !== 'payment') })
			: objUnitOrSize.payload_commission;
		size = objUnitOrSize.headers_commission + payload_commission - objectLength.getPaidTempDataFee(objUnitOrSize);
	}
	else
		throw Error("unrecognized 1st arg in getOversizeFee");
	const threshold_size = getSystemVar('threshold_size', mci);
	if (size <= threshold_size)
		return 0;
	return Math.ceil(size * (exp(size / threshold_size - 1) - 1));
}
```
