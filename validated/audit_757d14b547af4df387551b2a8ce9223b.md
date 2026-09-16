Based on my research, the external report's "lack of emergency administration" bug class maps to a concrete, reachable analog in `ocore`: the network's own emergency-governance mechanism for changing the witness list (`op_list`) is itself unsound because it derives a consensus-critical value from non-deterministic, node-local state.

### Title
Emergency `op_list` vote-count derives consensus-critical witness list from non-deterministic, node-local unstable state - (File: main_chain.js)

### Summary
`ocore` already implements an "out-of-band" emergency mechanism resembling what the audit recommended: if the DAG stalls, any unit carrying a `system_vote_count` message for `op_list` triggers `applyEmergencyOpListChange`, which recomputes the witness list using not-yet-stable ("unstable") `system_vote` messages weighted by balance [1](#0-0) . This recomputation is applied immediately at write time, before the triggering unit or any of the votes it counts are confirmed stable [2](#0-1) , and the input set it operates on (`storage.assocUnstableMessages`) is purely local, in-memory state that is not guaranteed to be identical across nodes at the same DAG position.

### Finding Description
`countVotes(conn, mci, subject, is_emergency, emergency_count_command_timestamp)` normally counts only stable `system_votes` rows. When `is_emergency` is set for `op_list`, it additionally folds in unstable votes obtained from `getUnstableVotes`, which walks the process-local `storage.assocUnstableMessages` map and returns any `system_vote` messages on units that are currently marked `sequence === 'good'` in this node's local view [3](#0-2) . These are then merged into a temporary `op_votes_tmp` table and used to pick the new `COUNT_WITNESSES`-sized witness set by summed balance [4](#0-3) .

This emergency path is triggered directly from `writer.js` as soon as a `system_vote_count` message for `op_list` is saved with a *provisional* `sequence === 'good'`, i.e., before the containing unit is stable and before its sequence classification is final [2](#0-1) . `applyEmergencyOpListChange` only gates on a timeout since the last stable unit, not on any global agreement about which votes exist [1](#0-0) .

Because `storage.assocUnstableMessages` reflects whatever unstable units a given node happens to have received and not yet garbage-collected at the moment it processes the triggering unit, two honest nodes that receive units in a different order, or that are at slightly different sync positions, can legitimately compute different sets of "unstable votes," and therefore different weighted-balance results, for the exact same emergency-count trigger unit. The result is written unconditionally with `REPLACE INTO system_vars` [5](#0-4) , `storage.systemVars.op_list` is mutated node-locally, and `network.js`'s `onSystemVarUpdated` immediately swaps live witnesses based on this value [6](#0-5) .

### Impact Explanation
The witness/order-provider (`op_list`) set is foundational to `ocore` consensus: it determines `witnessed_level`, best-parent selection, and ultimately which units are `sequence='good'` and stabilize. If nodes disagree on the emergency-derived `op_list` because they disagreed on which unstable votes to count, they will subsequently disagree on stability and validity of later units built on that state — a direct consensus split ("node disagreement on validity or stability"), which can halt or fork network confirmation and be leveraged for double-spend/censorship scenarios once nodes settle on incompatible views of who the legitimate witnesses are.

### Likelihood Explanation
The precondition (network being "stuck," i.e., the emergency path's very design goal) is exactly the scenario the mechanism exists to handle, and the emergency path is reachable by any node that can get a unit with a `system_vote_count`/`op_list` message accepted (validation only requires a valid, previously-seen subject and one-per-unit constraint) [7](#0-6) . An attacker (or even honest but differently-synced nodes) triggering the emergency recount while unstable `system_vote` propagation is incomplete or reordered across the network is a realistic condition, especially since it is explicitly designed to activate during periods of degraded network health — the very time when peer-to-peer state divergence is most likely.

### Recommendation
Do not base a consensus-critical parameter change on process-local unstable/unconfirmed message state. Either (a) restrict emergency vote counting to votes/units that are already deterministically ordered and agreed upon (e.g., require the votes themselves to be stable, accepting a slower but consistent emergency response), or (b) make the set of "unstable votes" used in the emergency computation part of the triggering unit's own payload (so all nodes evaluating the same unit use the identical vote set), and add explicit validation of that payload during unit validation so divergent computations are impossible by construction.

### Proof of Concept
1. Network main chain stalls past `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` from the last stable unit.
2. Two well-connected but not identically-synced nodes A and B each have received a different subset/order of pending `system_vote` (`op_list`) units in `storage.assocUnstableMessages` (normal p2p propagation timing differences, no malicious action required).
3. A unit carrying `system_vote_count` for `op_list` propagates and is written by both A and B with `sequence='good'`, triggering `writer.js` → `main_chain.applyEmergencyOpListChange` → `countVotes(..., is_emergency=1, ...)` on each node independently [2](#0-1) [1](#0-0) .
4. Because `getUnstableVotes` reads each node's own `storage.assocUnstableMessages` [3](#0-2) , A and B compute different balance-weighted `op_rows` and therefore different final `ops` witness lists at line `main_chain.js:1860` [8](#0-7) .
5. Each node commits its own result via `REPLACE INTO system_vars` and immediately swaps live witnesses through `onSystemVarUpdated` [6](#0-5) , leaving A and B with permanently divergent witness lists and therefore divergent views of unit validity/stability going forward.

### Citations

**File:** main_chain.js (L1826-1863)
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
```

**File:** main_chain.js (L1908-1913)
```javascript
	console.log(`new`, subject, value);
	// a repeated emergency vote on the same mci would overwrite the previous one
	await conn.query(`${is_emergency || mci === 0 ? 'REPLACE' : 'INSERT'} INTO system_vars (subject, value, vote_count_mci, is_emergency) VALUES (?, ?, ?, ?)`, [subject, value, mci === 0 ? -1 : mci, is_emergency]);
	await conn.query(conn.dropTemporaryTable('voter_balances'));
	eventBus.emit('system_vars_updated', subject, value);
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

**File:** network.js (L2157-2182)
```javascript
function onSystemVarUpdated(subject, value) {
	console.log('onSystemVarUpdated', subject, value);
	sendUpdatedSysVarsToAllLight();
	// update my witnesses with the new OP list unless catching up
	if (subject === 'op_list' && !bCatchingUp) {
		const arrOPs = JSON.parse(value);
		myWitnesses.readMyWitnesses(arrWitnesses => {
			if (arrWitnesses.length === 0)
				return console.log('no witnesses yet');
			const diff1 = _.difference(arrWitnesses, arrOPs);
			if (diff1.length === 0)
				return console.log("witnesses didn't change");
			const diff2 = _.difference(arrOPs, arrWitnesses);
			if (diff2.length !== diff1.length)
				throw Error(`different lengths of diffs: ${JSON.stringify(diff1)} vs ${JSON.stringify(diff2)}`);
			for (let i = 0; i < diff1.length; i++) {
				const old_witness = diff1[i];
				const new_witness = diff2[i];
				console.log(`replacing witness ${old_witness} with ${new_witness}`);
				myWitnesses.replaceWitness(old_witness, new_witness, err => {
					if (err)
						throw Error(`failed to replace witness ${old_witness} with ${new_witness}: ${err}`);
				});
			}
		}, 'ignore');
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
