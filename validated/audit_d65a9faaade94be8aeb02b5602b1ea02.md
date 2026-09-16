### Title
Emergency op_list (witness list) change is triggered purely by elapsed timestamp, allowing an attacker to force a governance state change with unmatured/attacker-controlled votes - ([File: main_chain.js])

### Summary
`applyEmergencyOpListChange()` in `main_chain.js` performs a critical governance state transition (replacing the network's order-provider/witness list, `op_list`) based solely on how much wall-clock time has elapsed since the last stable unit, exactly the anti-pattern described in the source report: a state-machine transition gated only by a timestamp check, with no verification of *why* the network is "stuck" or whether the emergency conditions are genuine.

### Finding Description
Any ordinary address (not an AA) can post a `system_vote_count` message with `subject: 'op_list'`; validation only checks that it's a single such message per unit and that the subject is one of the known ones, with no privilege restriction. [1](#0-0) 

When such a unit is saved, `writer.js` unconditionally calls `main_chain.applyEmergencyOpListChange(conn, objUnit.timestamp, cb)` for any `good`-sequence unit carrying this message. [2](#0-1) 

`applyEmergencyOpListChange` itself only checks one condition — that the poster's declared `timestamp` is at least `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days) after the last *stable* unit's timestamp — before invoking `countVotes(..., is_emergency=1, ...)`: [3](#0-2) 

Unlike the normal (non-emergency) vote count, the emergency path in `countVotes`/`getUnstableVotes` additionally folds in **unstable** (not-yet-finalized) votes as long as they are merely older than `EMERGENCY_COUNT_MIN_VOTE_AGE` (1 hour), bypassing the stability/finality requirement that protects the normal vote-count logic: [4](#0-3) [5](#0-4) 

This mirrors the report's flaw exactly: the transition from "normal" to "emergency" governance mode is decided purely by elapsed time since the last stable unit, without any check on *why* stability stalled (e.g., deliberate flooding/branching by the very actor who wants to trigger the emergency path, or a temporarily quiet but otherwise healthy network), and without excluding votes that are freshly crafted by the same attacker for the purpose of exploiting the lowered bar (1-hour maturity instead of full stability).

### Impact Explanation
The `op_list` determines the set of order providers (witnesses) that the entire main-chain stability algorithm relies on (`findMinMcWitnessedLevel`, `readWitnesses`, etc. in `main_chain.js`). Forcing an unwarranted or attacker-influenced emergency change to this list is a fundamental governance/consensus-safety compromise: nodes could end up disagreeing about which units are stable, the resulting order-provider set could be controlled or biased by an attacker who orchestrated the "stuck" condition and supplied same-timestamp-satisfying young votes, and because `MAX_WITNESS_LIST_MUTATIONS = 1`, an incorrect or manipulated set can also break normal unit composition/parent selection for a period, freezing normal operation for legitimate users. This satisfies the "node disagreement on validity or stability" / "network unable to confirm new units" impact bar.

### Likelihood Explanation
Reachability is high: the only requirement to invoke the check is posting a single ordinary unit with a `system_vote_count`/`op_list` message once the 3-day stall condition holds, which is fully permissionless per the validation rules shown above. The harder part for an attacker is causing or waiting for a genuine 3-day stability stall, but the code does nothing to verify that the stall is not attacker-induced or that included "unstable" votes are not attacker-supplied and merely artificially aged past the 1-hour bar. Given the multi-day window requirement this is not trivially exploitable at will, but the design flaw (timestamp-only gating with no cross-check of consensus health or vote provenance) is exactly analogous to the reported class of bug.

### Recommendation
Do not gate the emergency `op_list` change purely on elapsed timestamp. Add checks that verify the network is genuinely stalled (e.g., cross-validate against multiple independent free/best-parent branches, require confirmation from a diverse/majority set of currently-active order providers, or require some minimum spread of unrelated authors) before allowing the reduced vote-maturity path. Consider also excluding votes whose age was only "aged" via crafted timestamps close to the `EMERGENCY_COUNT_MIN_VOTE_AGE` threshold, and require that emergency-eligible votes come from historically established stake/voters rather than very recent unstable messages.

### Proof of Concept
1. Wait for (or engineer, e.g., via selectively not relaying/witnessing certain branches) a period where no unit becomes stable for `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days) — `main_chain.js:1938-1939`.
2. Have several controlled addresses each post a `system_vote` (`subject: 'op_list'`) unit more than `EMERGENCY_COUNT_MIN_VOTE_AGE` (1 hour) before the triggering unit — these units need not be stable, only "good" sequence — `main_chain.js:1915-1933`.
3. Post a single unprivileged unit containing `system_vote_count` for `op_list` with a timestamp satisfying the 3-day gate — `validation.js:1913-1923`, `writer.js:639-645`.
4. `applyEmergencyOpListChange` fires and `countVotes` is invoked with `is_emergency=1`, folding the attacker's unstable votes into the tally and replacing `op_list` (`main_chain.js:1826-1876`) — solely because the timestamp condition was met, without any check on why the network stalled or on the legitimacy/independence of the voting addresses.

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

**File:** writer.js (L639-645)
```javascript
							if (objValidationState.bHasSystemVoteCount && objValidationState.sequence === 'good') {
								const m = objUnit.messages.find(m => m.app === 'system_vote_count');
								if (!m)
									throw Error(`system_vote_count message not found`);
								if (m.payload === 'op_list')
									arrOps.push(cb => main_chain.applyEmergencyOpListChange(conn, objUnit.timestamp, cb));
							}
```

**File:** main_chain.js (L1826-1849)
```javascript
			const votes_table = is_emergency ? 'op_votes_tmp' : 'op_votes';
			if (is_emergency) { // add unstable votes for OPs
				await conn.query(`CREATE TEMPORARY TABLE ${votes_table} AS SELECT address, op_address, timestamp FROM op_votes`);
				// the order of iteration is undefined, so we'll first collect the messages and then sort them. The order matters only when the same address sends multiple unstable votes
				let votes = unstable_votes || getUnstableVotes(emergency_count_command_timestamp);
				console.log('unsorted unstable votes', votes);
				votes.sort((v1, v2) => {
					const dt = v1.timestamp - v2.timestamp;
					if (dt !== 0)
						return dt;
					return v1.level - v2.level;
				});
				console.log('sorted unstable votes', votes);
				for (let { timestamp, author_addresses, arrOPs } of votes) {
					// apply each vote separately as a new unstable vote from the same user would override the previous one
					await conn.query(`DELETE FROM ${votes_table} WHERE address IN (?)`, [author_addresses]);
					let values = [];
					for (let address of author_addresses)
						for (let op_address of arrOPs)
							values.push(`(${db.escape(address)}, ${db.escape(op_address)}, ${timestamp})`);
					console.log('unstable votes', values);
					await conn.query(`INSERT INTO ${votes_table} (address, op_address, timestamp) VALUES ` + values.join(', '));
				}
			}
```

**File:** main_chain.js (L1915-1933)
```javascript
function getUnstableVotes(emergency_count_command_timestamp) {
	let votes = [];
	for (let unit in storage.assocUnstableMessages) {
		for (let m of storage.assocUnstableMessages[unit]) {
			if (m.app === 'system_vote' && m.payload.subject === 'op_list') {
				const { timestamp, author_addresses, sequence, level } = storage.assocUnstableUnits[unit];
				if (sequence !== 'good')
					continue;
				if (emergency_count_command_timestamp - timestamp < constants.EMERGENCY_COUNT_MIN_VOTE_AGE) {
					console.log('unstable vote from', author_addresses, 'is too young');
					continue;
				}
				const arrOPs = m.payload.value;
				votes.push({ timestamp, level, author_addresses, arrOPs });
			}
		}
	}
	return votes;
}
```

**File:** main_chain.js (L1936-1946)
```javascript
async function applyEmergencyOpListChange(conn, emergency_count_command_timestamp, cb) {
	// last stable unit
	const [{ timestamp, main_chain_index }] = await conn.query("SELECT timestamp, main_chain_index FROM units WHERE is_stable=1 AND is_on_main_chain=1 ORDER BY main_chain_index DESC LIMIT 1");
	if (emergency_count_command_timestamp < timestamp + constants.EMERGENCY_OP_LIST_CHANGE_TIMEOUT) {
		console.log(`too early to apply emergency OP list change yet`);
		return cb();
	}
	console.log(`applying emergency vote count after being stuck at mci ${main_chain_index}`);
	await countVotes(conn, main_chain_index - 1, 'op_list', 1, emergency_count_command_timestamp);
	cb();
}
```
