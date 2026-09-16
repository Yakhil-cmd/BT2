### Title
Emergency OP-list vote count can be forced by any unit poster to finalize a system-parameter change based on unconfirmed votes - (File: main_chain.js)

### Summary
`main_chain.js`'s `applyEmergencyOpListChange()` / `countVotes(..., is_emergency=1, ...)` mirror the `LightClient.force()` pattern from the report: after a timeout with no progress, "the best/available update" is applied even though it was not backed by the normal confirmation/majority process. Here the "best update" is an OP (order-provider/witness) list computed from votes that include *unstable, unconfirmed* `system_vote` messages rather than only stable, fully-confirmed votes. Crucially, the trigger for this forced counting is not privileged: any unit poster can include a `system_vote_count` message with payload `'op_list'` in an ordinary unit, and `writer.js` unconditionally calls `applyEmergencyOpListChange` for every such unit once it is written with `sequence==='good'`. [1](#0-0) [2](#0-1) 

### Finding Description
`applyEmergencyOpListChange(conn, emergency_count_command_timestamp, cb)` only checks that the last stable MC unit's timestamp is older than `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days) before invoking `countVotes(conn, main_chain_index - 1, 'op_list', 1, emergency_count_command_timestamp)` with `is_emergency=1`: [2](#0-1) 

Inside `countVotes`, when `is_emergency` is true, the function pulls in *unstable* votes directly from `storage.assocUnstableMessages` via `getUnstableVotes()`, gated only by a minimum age of `EMERGENCY_COUNT_MIN_VOTE_AGE` (1 hour) and `sequence==='good'` — not by main-chain stability/confirmation: [3](#0-2) [4](#0-3) 

These unconfirmed votes are merged into a temporary `op_votes_tmp` table and the top `COUNT_WITNESSES` (12) OP addresses by voted balance are selected as the new OP list, which is then written to `system_vars` with `is_emergency=1`, immediately taking effect ("applies since the next mci"): [5](#0-4) [6](#0-5) 

The trigger for this whole flow is reachable by an ordinary unit poster: any unit containing a `system_vote_count` message causes `writer.js` to schedule `main_chain.applyEmergencyOpListChange(conn, objUnit.timestamp, cb)` as part of committing that single unit, with the poster fully controlling the `emergency_count_command_timestamp` parameter (`objUnit.timestamp`): [1](#0-0) 

Unlike the normal (non-emergency) `op_list` counting path used at every ordinary MC stabilization — which only counts fully stable `system_vote` messages recorded in `op_votes` after they've become part of the confirmed DAG — the emergency path bypasses this confirmation requirement entirely and only requires that unstable voting units be at least 1 hour old and locally marked `sequence==='good'` (a status that can change before finalization, and that the poster/collaborators fully control by simply structuring their own units).

The situation is directly analogous to the reported `LightClient.force()` bug: normal operation requires a full/stable finality process (there, 2/3 signatures; here, MC stabilization + stable, confirmed votes), but a "stuck" condition (here, 3 days without MC-stability progress) allows any user to short-circuit that process and finalize a set of privileged parties (the 12 OP addresses that replace the witness/order-provider committee) based on votes that were never confirmed as part of the stable DAG.

### Impact Explanation
The OP list plays the analogous role of the sync committee in the original report: the addresses in `storage.systemVars.op_list` control which units are counted as OPs for main-chain determination, witnessing, and everything downstream of it (stability determination, majority-of-witnesses checks in `validation.js`/`main_chain.js`, `MAJORITY_OF_WITNESSES` calculations, etc.), as seen throughout `main_chain.js`/`validation.js` (`arrWitnesses`, `MAJORITY_OF_WITNESSES`, `determineIfHasWitnessListMutationsAlongMc`, etc.) [7](#0-6) 
If a set of colluding addresses (with sufficient combined balance) can force the emergency vote-count to install themselves (or addresses they control) as OPs using only unconfirmed votes gathered by them, they gain effective control over main-chain stabilization going forward, which can be leveraged to manipulate which units/branches are ultimately deemed stable — enabling double-spend-style disagreement on stability/validity across nodes, or freezing legitimate progress of the DAG. This is a Medium/High severity data-validation/finalization issue matching the report's class (forced finalization allowing bad/insufficiently-confirmed updates).

### Likelihood Explanation
Reaching the vulnerable code path requires only:
1. Posting an ordinary unit carrying a `system_vote_count` message with payload `'op_list'` — no special privilege needed, and
2. The network having been "stuck" (no MC stability progress) for `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days).

Condition (2) is the harder part to trigger without the network already being unhealthy, but unlike the sync-committee case that explicitly requires a DoS against provers, a MC-stabilization stall can arise from ordinary causes (insufficient witnessing activity, a contested/branching DAG, bugs, or a minority of malicious/uncooperative OPs withholding activity) — none of which require attacking peers/nodes/hubs, matching an in-scope condition. Once stuck, an attacker (or colluding group) simply needs enough voting balance and >1-hour-old "good"-sequence votes to dominate the emergency count, which is a comparatively low bar (analogous to the "10 signers, 5% stake" bar in the original report).

### Recommendation
- Require that votes counted during an emergency op_list change be backed by confirmed/stable data (or, at minimum, require a much stronger, non-attacker-controllable proof of participation/majority) rather than merely `sequence==='good'` and 1-hour-old unstable messages.
- Restrict who/what can invoke `applyEmergencyOpListChange` — e.g., require this action to be limited/rate-limited network-wide rather than triggerable by every unit that happens to carry a `system_vote_count` message, and consider requiring a privileged/quorum-gated call similar to removing `LightClient.force` or adding a mediating role as recommended in the original report.
- Increase `EMERGENCY_COUNT_MIN_VOTE_AGE` and add participation/majority thresholds analogous to `SYSTEM_VOTE_MIN_SHARE` specifically for the emergency path (currently the loop that expands `since_timestamp` for participation share is shared with normal counting but doesn't guard the *unstable* votes injected under emergency mode).
- Explicitly document the liveness/safety tradeoff of the forced/emergency vote-count mechanism.

### Proof of Concept
1. Network experiences (or is engineered into, e.g. via a contested witness/OP set) a stall where the last stable MC unit's timestamp is more than `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days) in the past. [8](#0-7) 
2. Attacker(s) with a coalition of addresses controlling sufficient `TOTAL_WHITEBYTES` balance post `system_vote` (`op_list`) units naming attacker-controlled addresses as OPs, letting them sit unconfirmed for just over `EMERGENCY_COUNT_MIN_VOTE_AGE` (1 hour) while keeping `sequence==='good'`. [3](#0-2) 
3. Any unit poster (can be the attacker) posts a unit containing a `system_vote_count` message with payload `'op_list'`. `writer.js` calls `main_chain.applyEmergencyOpListChange(conn, objUnit.timestamp, cb)` while committing that unit. [1](#0-0) 
4. `countVotes` runs with `is_emergency=1`, merges the attacker's unconfirmed votes into `op_votes_tmp`, and selects the top 12 addresses by voted balance — potentially all attacker-controlled — writing them into `system_vars` as the new OP list, effective immediately. [5](#0-4) 
5. The attacker-controlled OP list now governs subsequent main-chain/witness majority determinations for the network.

### Citations

**File:** writer.js (L639-644)
```javascript
							if (objValidationState.bHasSystemVoteCount && objValidationState.sequence === 'good') {
								const m = objUnit.messages.find(m => m.app === 'system_vote_count');
								if (!m)
									throw Error(`system_vote_count message not found`);
								if (m.payload === 'op_list')
									arrOps.push(cb => main_chain.applyEmergencyOpListChange(conn, objUnit.timestamp, cb));
```

**File:** main_chain.js (L1823-1849)
```javascript
	let value;
	switch (subject) {
		case 'op_list':
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

**File:** main_chain.js (L1850-1876)
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
			break;
```

**File:** main_chain.js (L1908-1910)
```javascript
	console.log(`new`, subject, value);
	// a repeated emergency vote on the same mci would overwrite the previous one
	await conn.query(`${is_emergency || mci === 0 ? 'REPLACE' : 'INSERT'} INTO system_vars (subject, value, vote_count_mci, is_emergency) VALUES (?, ?, ?, ?)`, [subject, value, mci === 0 ? -1 : mci, is_emergency]);
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

**File:** validation.js (L903-923)
```javascript
	function checkWitnessedLevelDidNotRetreat(arrWitnesses){
		if (!objUnit.parent_units) // genesis
			return callback();
		storage.determineWitnessedLevelAndBestParent(conn, objUnit.parent_units, arrWitnesses, objUnit.version, objValidationState.last_ball_mci >= constants.bestParentPrefersOpUpgradeMci, function(witnessed_level, best_parent_unit){
			if (!best_parent_unit)
				return callback("no best parent");
			objValidationState.witnessed_level = witnessed_level;
			objValidationState.best_parent_unit = best_parent_unit;
			if (objValidationState.last_ball_mci < constants.witnessedLevelMustNotRetreatUpgradeMci) // not enforced
				return callback();
			if (typeof objValidationState.max_parent_wl === 'undefined')
				throw Error('no max_parent_wl');
			if (objValidationState.last_ball_mci >= constants.witnessedLevelMustNotRetreatFromAllParentsUpgradeMci)
				return (witnessed_level >= objValidationState.max_parent_wl) ? callback() : callback("witnessed level retreats from parent's "+objValidationState.max_parent_wl+" to "+witnessed_level);
			storage.readStaticUnitProps(conn, best_parent_unit, function(props){
				(witnessed_level >= props.witnessed_level) 
					? callback() 
					: callback("witnessed level retreats from "+props.witnessed_level+" to "+witnessed_level);
			});
		});
	}
```
