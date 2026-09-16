### Title
Emergency OP-list vote count accepts unconfirmed (unstable) votes and applies the change synchronously, before consensus — ([File: main_chain.js])

### Summary
The Beanstalk incident succeeded because the protocol allowed a proposal to be voted on and executed in the same transaction, with no time interval and no requirement that the vote outcome be confirmed/final before being acted upon. `ocore`'s "emergency OP list change" governance path (`system_vote` / `system_vote_count` messages, any unprivileged unit author) has an analogous root cause: it counts and applies a witness/Order-Provider (OP) list change using **unstable, unconfirmed** `system_vote` messages, and applies the result synchronously while writing the very unit that requested the count — before that unit, or the votes it relies on, have reached DAG stability/finality.

### Finding Description
Any address can cast a `system_vote` for the `op_list` subject [1](#0-0) , and any address can post a `system_vote_count` message to request tallying [2](#0-1) . Both checks only require the message to come from a non-AA, single-author unit — no operator/OP privilege is needed.

Normally, `system_vote_count` messages are only processed after the *stabilization* of the MCI that carries them: `voteCountSubjects` is deferred and `countVotes()` is invoked from `markMcIndexStable` once that MCI is finalized [3](#0-2) , i.e. after real confirmation.

However, for `op_list` there is a separate, **emergency** fast path that bypasses this. As soon as a unit containing an `op_list` `system_vote_count` is written (`sequence === 'good'`), `writer.js` immediately calls `main_chain.applyEmergencyOpListChange` — synchronously, in the same write, *before* `updateMainChain` even runs for this unit: [4](#0-3) 

`applyEmergencyOpListChange` only checks that the last **stable** unit's timestamp is older than `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days) — it does not wait for the triggering unit or the votes to become stable: [5](#0-4) 

It then calls `countVotes(..., is_emergency=1, ...)`, which pulls in `getUnstableVotes()` — votes taken directly from `storage.assocUnstableMessages`, i.e. from units that are **not yet stable**, filtered only by `sequence === 'good'` and an age of at least `EMERGENCY_COUNT_MIN_VOTE_AGE` = 1 hour (`constants.js:19`): [6](#0-5) 

These unconfirmed votes are merged with historical stable votes and immediately determine the new OP list: [7](#0-6) 

The result is applied at once: `storage.systemVars.op_list` is mutated and `storage.resetWitnessCache()` is called, changing the effective witness/OP list used for best-parent selection and stability determination network-wide, all before the triggering unit (or the underlying votes) have been confirmed as permanently valid: [8](#0-7) 

Just like Beanstalk's flaw ("no time interval between the voting and execution of the proposal"), this path lets a governance-critical, network-wide parameter (the OP list, which anchors main-chain stability and node agreement on validity) be flipped on the basis of votes and a triggering unit that have not passed the DAG's normal confirmation/stability process — units that are still subject to potential re-sequencing or reversal to `final-bad`.

### Impact Explanation
Changing the OP list changes which addresses are trusted witnesses for best-parent selection and MC stability across the whole network (`storage.resetWitnessCache()`), a systemic, hard-to-reverse effect. If the effective change is driven by votes/units that are not yet final, different nodes can end up disagreeing about whether those specific votes/units are actually valid (`sequence` can still resolve to `final-bad` later), producing exactly the kind of "node disagreement on validity or stability" / inability to reach consensus on new units that the rules call out as concrete impact. Because the change is applied immediately and irreversibly rewrites live consensus state, an attacker who can get enough temporarily-good (not-yet-final) votes counted can force in a hostile or dysfunctional OP set, stalling or forking main-chain progress for the network.

### Likelihood Explanation
Exploitation requires (a) the main chain to already be stuck for `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days) relative to the last stable unit, and (b) an attacker/colluding minority controlling `system_vote` messages that are ≥1 hour old and merely `sequence='good'` (not stable) at count time. The precondition (a) is an operational trigger, not a privilege boundary, and is reachable purely from unit-posting behavior (e.g., deliberately not cooperating on best-parent/witness selection to stall stabilization) combined with (b), both of which are reachable by an ordinary unprivileged unit poster as required by scope. Likelihood is assessed as Medium: the 3-day stall precondition limits how often the emergency path fires, but once triggered, there is no requirement that the counted votes be final, which is the structural analog to Beanstalk's missing time-lock.

### Recommendation
Require that the emergency-path votes and the `system_vote_count` triggering unit themselves be `is_stable=1` (not merely `sequence='good'`) before they can be counted and applied, or introduce an explicit delay between when an emergency OP-list result is computed and when it takes effect (mirroring the normal, stability-gated `countVotes` path). At minimum, re-validate/re-apply the emergency result once the triggering unit and the votes it used have stabilized, and roll back/re-run the computation if any contributing unit is later resolved to `final-bad`.

### Proof of Concept
1. Attacker (or colluding addresses) each post a `system_vote` message with `subject: "op_list"` pointing to an attacker-controlled slate of OP addresses (validated at `validation.js:1861-1882`). These units are broadcast and become part of `storage.assocUnstableMessages`, but are deliberately not stabilized (e.g., by producing competing units/parents to stall MC progress).
2. Wait until the last *stable* unit is older than `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days) and the votes from step 1 are older than `EMERGENCY_COUNT_MIN_VOTE_AGE` (1 hour) — both are purely timestamp checks (`main_chain.js:1936-1946`, `main_chain.js:1923`).
3. Post a `system_vote_count` message with `payload: "op_list"` from any single-author, non-AA unit (allowed per `validation.js:1913-1923`).
4. On write of this unit, `writer.js:639-644` synchronously invokes `applyEmergencyOpListChange`, which calls `countVotes(..., is_emergency=1, ...)`. `getUnstableVotes()` (`main_chain.js:1915-1933`) pulls in the attacker's still-unstable votes from step 1 and tallies them together with `voter_balances`, producing a new `op_list` that is applied immediately via `storage.systemVars.op_list.unshift(...)` and `storage.resetWitnessCache()` — before the triggering unit or the underlying votes have been confirmed stable.

### Citations

**File:** validation.js (L1844-1873)
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
			switch (payload.subject) {
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

**File:** main_chain.js (L1826-1875)
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

**File:** writer.js (L639-644)
```javascript
							if (objValidationState.bHasSystemVoteCount && objValidationState.sequence === 'good') {
								const m = objUnit.messages.find(m => m.app === 'system_vote_count');
								if (!m)
									throw Error(`system_vote_count message not found`);
								if (m.payload === 'op_list')
									arrOps.push(cb => main_chain.applyEmergencyOpListChange(conn, objUnit.timestamp, cb));
```
