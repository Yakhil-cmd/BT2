### Title
Emergency OP-list vote count relies on non-deterministic in-memory unstable state, risking node disagreement on the validator (OP) list - ([File: main_chain.js])

### Summary
`ocore`'s Order Provider (OP) list is the direct analog of Celer's SGN validator set: it is chosen by stake-weighted votes cast with the `system_vote` app and tallied by `countVotes()` [1](#0-0) . Under normal conditions, votes are only counted once a main-chain index is *stable*, guaranteeing all nodes count the exact same set of votes. However, an "emergency" path exists that counts **unstable** votes when the network appears stuck, and this path is reachable by any unprivileged address able to post a `system_vote_count` unit.

### Finding Description
`applyEmergencyOpListChange()` is invoked whenever a `system_vote_count` message for `op_list` is included in a "good"-sequence unit, with no privilege check beyond ordinary unit/message validation [2](#0-1) [3](#0-2) . Once the last stable unit is older than `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days) [4](#0-3) , it calls `countVotes(conn, main_chain_index - 1, 'op_list', 1, emergency_count_command_timestamp)` [5](#0-4) .

Inside `countVotes`, when `is_emergency` is set, the function pulls **unstable** votes directly from the in-memory maps `storage.assocUnstableMessages` / `storage.assocUnstableUnits` via `getUnstableVotes()` [6](#0-5) , rather than from any DAG-stability-derived, deterministic source. These maps are purely local runtime state that depends on which units a given node has received and how it has currently classified their `sequence` ('good' vs not) *at the moment the emergency trigger fires* — a classification that is explicitly subject to change before the unit is stable (that is the definition of "unstable"). The only filter applied is a vote-age check (`EMERGENCY_COUNT_MIN_VOTE_AGE` = 1 hour) and a deterministic sort by `(timestamp, level)`, but the underlying candidate set of unstable votes itself is not guaranteed to be identical across nodes, because:
- Different nodes may have received a different subset of not-yet-stable units at the time the trigger unit is processed.
- A vote-carrying unit's `sequence` can still flip from `'good'` to `'final-bad'` afterward on some nodes before it stabilizes, while other nodes may finalize it as `'good'` first if their local processing/timing differs slightly.

The resulting OP list is written into `system_vars` via `INSERT`/`REPLACE` and immediately becomes part of consensus-critical state (`storage.systemVars.op_list`) used by `checkWitnessedLevelDidNotRetreat` / OP-based validation for all subsequent units [7](#0-6) . If two nodes derive different `arrOPs` (or even the same OPs sorted differently before the `ops.sort()` normalization) from the emergency path due to divergent unstable-vote snapshots, they will disagree on the current validator/OP set and thus on the validity of subsequent units authored under that OP set.

The comment history in the same function ("this is a bug, should count only unique witnesses" for a related old algorithm, and the previously-encountered "13 OPs" consensus bug fixed on testnet in `initial_votes.js`) confirms that OP-list tallying in this codebase has a track record of producing inconsistent results across nodes [8](#0-7) .

### Impact Explanation
If nodes disagree on the resulting OP (validator) list after an emergency recount, they will subsequently disagree on which units satisfy the witnessed-level/majority-of-OPs stability rule, since `storage.getOpList()` (fed by `system_vars`) directly gates unit validity via `checkWitnessedLevelDidNotRetreat` [7](#0-6) . This is a "node disagreement on validity or stability" outcome and could stall the network's ability to reach stability/confirm new units network-wide, matching the accepted impact classes.

### Likelihood Explanation
The emergency path only activates after 3 days without stabilization, i.e., in an already-degraded network condition, which lowers overall likelihood, but exploitation does not require any special privilege — any address can post ordinary `system_vote` and `system_vote_count` units, and the divergence stems purely from node-local runtime state (unstable in-memory maps) rather than an attacker directly forging signatures, similar in spirit to how Celer's bug allowed state changes from votes that had not gone through the normal validated consensus path.

### Recommendation
Base the emergency vote tally exclusively on deterministic, DAG-derivable state (e.g., only consider unstable units whose parent-chain/witness inclusion can be independently and identically recomputed by every node from the shared DAG, not from node-local `assocUnstableUnits`/`assocUnstableMessages` snapshots), or require that the units contributing votes have reached a bounded, unambiguous point in the DAG (e.g., a specific level-based cutoff that is provably identical on all fully-synced nodes) before being eligible for emergency counting.

### Proof of Concept
Not directly demonstrable without a live multi-node testnet exhibiting a >3‑day stall; the concern is structural (reliance on `storage.assocUnstableUnits`/`assocUnstableMessages`, local mutable state that is not guaranteed identical across nodes at the moment `applyEmergencyOpListChange` fires) rather than a single deterministic input trigger.

**Caveat / uncertainty**: I could not fully verify within the available index whether some other invariant (e.g., a required MC-witnessing depth before a unit is added to `assocUnstableMessages`, or a subsequent re-validation step) forces all nodes to converge on the same unstable-vote snapshot despite the sequence field being mutable pre-stability. This would need to be confirmed by tracing `sequence` transition points and `assocUnstableUnits` population/removal across `writer.js` and `joint_storage.js` in a full Devin session before treating this as a confirmed exploit rather than a design-risk finding.

### Citations

**File:** main_chain.js (L1737-1743)
```javascript
async function countVotes(conn, mci, subject, is_emergency = 0, emergency_count_command_timestamp = 0) {
	console.log('countVotes', mci, subject, is_emergency, emergency_count_command_timestamp);
	if (is_emergency && subject !== "op_list")
		throw Error("emergency vote count supported for op_list only, got " + subject);
	const address_rows = await conn.query("SELECT DISTINCT address FROM system_votes WHERE subject=?", [subject]);
	let addresses = address_rows.map(r => r.address);
	const unstable_votes = (is_emergency && mci >= constants.pemCurvesFixMci) ? getUnstableVotes(emergency_count_command_timestamp) : null;
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

**File:** validation.js (L925-926)
```javascript
	if (objValidationState.last_ball_mci >= constants.v4UpgradeMci)
		return checkWitnessedLevelDidNotRetreat(storage.getOpList(objValidationState.last_ball_mci));
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

**File:** constants.js (L18-19)
```javascript
exports.EMERGENCY_OP_LIST_CHANGE_TIMEOUT = 3 * 24 * 3600;
exports.EMERGENCY_COUNT_MIN_VOTE_AGE = 3600;
```

**File:** initial_votes.js (L9-28)
```javascript
		if (constants.bTestnet) { // fix a previous bug
			const vote_rows = await conn.query("SELECT op_address, unit FROM op_votes WHERE address='EJC4A7WQGHEZEKW6RLO7F26SAR4LAQBU'");
			if (vote_rows.length === 13) {
				const vote_row = vote_rows.find(row => row.op_address === '2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX');
				if (!vote_row)
					throw Error("13 OPs but 2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX is not among them");
				if (vote_row.unit)
					throw Error("13th OP has unit " + vote_row.unit);
				console.log("deleting the 13th vote");
				await conn.query("DELETE FROM op_votes WHERE address='EJC4A7WQGHEZEKW6RLO7F26SAR4LAQBU' AND op_address='2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX'");
			}
			// change the OP list on those nodes that were not affected by the bug (the minority)
			const [op_list_row] = await conn.query("SELECT value, vote_count_mci FROM system_vars WHERE subject='op_list' ORDER BY vote_count_mci DESC LIMIT 1");
			if (!op_list_row)
				throw Error("no last op list");
			const { value, vote_count_mci } = op_list_row;
			if (vote_count_mci === 3547796 && value === '["2GPBEZTAXKWEXMWCTGZALIZDNWS5B3V7","4H2AMKF6YO2IWJ5MYWJS3N7Y2YU2T4Z5","DFVODTYGTS3ILVOQ5MFKJIERH6LGKELP","ERMF7V2RLCPABMX5AMNGUQBAH4CD5TK4","F4KHJUCLJKY4JV7M5F754LAJX4EB7M4N","IOF6PTBDTLSTBS5NWHUSD7I2NHK3BQ2T","O4K4QILG6VPGTYLRAI2RGYRFJZ7N2Q2O","OPNUXBRSSQQGHKQNEPD2GLWQYEUY5XLD","PA4QK46276MJJD5DBOLIBMYKNNXMUVDP","RJDYXC4YQ4AZKFYTJVCR5GQJF5J6KPRI","WELOXP3EOA75JWNO6S5ZJHOO3EYFKPIR","WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"]') {
				console.log("changing the OP list to the buggy one");
				await conn.query(`UPDATE system_vars SET value='["2FF7PSL7FYXVU5UIQHCVDTTPUOOG75GX","2GPBEZTAXKWEXMWCTGZALIZDNWS5B3V7","4H2AMKF6YO2IWJ5MYWJS3N7Y2YU2T4Z5","DFVODTYGTS3ILVOQ5MFKJIERH6LGKELP","ERMF7V2RLCPABMX5AMNGUQBAH4CD5TK4","F4KHJUCLJKY4JV7M5F754LAJX4EB7M4N","IOF6PTBDTLSTBS5NWHUSD7I2NHK3BQ2T","O4K4QILG6VPGTYLRAI2RGYRFJZ7N2Q2O","OPNUXBRSSQQGHKQNEPD2GLWQYEUY5XLD","PA4QK46276MJJD5DBOLIBMYKNNXMUVDP","RJDYXC4YQ4AZKFYTJVCR5GQJF5J6KPRI","WMFLGI2GLAB2MDF2KQAH37VNRRMK7A5N"]' WHERE subject='op_list' AND vote_count_mci=3547796`);
			}
```
