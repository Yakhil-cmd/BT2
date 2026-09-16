## Title
Winning OP list is applied by `countVotes` without re-validating witness eligibility checks enforced only at `system_vote` submission time - ([File: main_chain.js])

### Summary
The Obyte OP (order-provider/witness) list change mechanism follows the same two-phase "propose then execute" pattern flagged in the external report: a `system_vote` message carrying a candidate `op_list` is validated with several eligibility checks at submission time, but the tallying/execution step (`countVotes`, triggered later by a `system_vote_count` message when stability is reached) re-applies none of those checks before writing the new `op_list` into `system_vars` and making it authoritative for future witness/MC-stability logic.

### Finding Description
When a unit posts `{app: 'system_vote', payload: {subject: 'op_list', value: arrOPs}}`, `validateInlinePayload` performs three eligibility checks on the candidate OP addresses before accepting the vote: [1](#0-0) 

- `checkNotAAs` — rejects addresses that are already AAs.
- `checkWitnessesKnownAndGood` — requires the candidate to be a known, "good"-sequence address.
- `checkNoReferencesInWitnessAddressDefinitions` — prevents a witness address definition from referencing other addresses (to keep MC-stability/witnessed-level logic sound).

These checks are cached only at the moment the *vote* unit is validated. The actual state change — selecting the winning `op_list` and writing it to `storage.systemVars`/`system_vars` — happens much later, inside `countVotes`, which is invoked once the corresponding `system_vote_count` message becomes stable: [2](#0-1) [3](#0-2) 

`countVotes` simply aggregates already-stored votes by balance and timestamp and picks the top `COUNT_WITNESSES` addresses — it performs **no** re-check of `checkNotAAs`, `checkWitnessesKnownAndGood`, or `checkNoReferencesInWitnessAddressDefinitions` on the winning set before committing it: [4](#0-3) [5](#0-4) 

The vote-counting window is explicitly designed to look back arbitrarily far (it expands the lookback period year by year until enough voting balance is found, and votes with `system_vote` timestamps are counted regardless of how much later `countVotes` executes): [6](#0-5) 

This is structurally identical to the Tidal `Pool` bug: validation performed at "propose" time (`removeFromCommittee`/`changeCommitteeThreshold` ≈ `system_vote`) is not re-applied at "execute" time (`_executeRemoveFromCommittee`/`_executeChangeCommitteeThreshold` ≈ `countVotes`), even though a long, unbounded time gap (here, up to years, via the expanding lookback window) can elapse between the two phases and invalidate the original guarantees.

Concretely, an address that was a "good", non-AA witness candidate with no address-definition references at the moment its `system_vote` was cast can, before `countVotes` finally executes:
- become an AA address (deployed after the vote), or
- become an address in `temp-bad`/`final-bad` sequence, or
- redefine its address definition to add `seen address`/`seen definition change`/similar references that `checkNoReferencesInWitnessAddressDefinitions` was designed to forbid.

Because none of these are rechecked in `countVotes`, such an address can still be selected into the new `op_list` and written straight into `storage.systemVars.op_list` / the `system_vars` table, which is subsequently used network-wide as the authoritative OP/witness set for `readWitnesses`/`getOpList` and MC-stability determination: [7](#0-6) 

### Impact Explanation
The OP list is the trust anchor for main-chain stability determination post-v4-upgrade (`readWitnesses` returns `getOpList(main_chain_index)` for any unit past `constants.v4UpgradeMci`). Allowing a disqualified address (AA, bad-sequence, or one with forbidden self-referencing definitions) into the active `op_list` undermines the invariants that `checkNoReferencesInWitnessAddressDefinitions` and `checkWitnessesKnownAndGood` exist to protect — witnessed-level computation and MC stability rules assume witnesses are "good", non-AA addresses without such references. A corrupted OP list can differentially affect which units different nodes consider stable, i.e., **node disagreement on validity/stability** of units, which can enable double-spend of outputs that different nodes stabilize differently, or freeze the network's ability to reach consensus on new stable units if the resulting witness set behaves inconsistently across nodes.

### Likelihood Explanation
The look-back window in `countVotes` deliberately expands across multiple years when voting turnout is low, so the time gap between a `system_vote`'s validation and its counting in `countVotes` can be very large — a realistic window for a previously-eligible address to become an AA, get slashed to bad sequence, or change its definition. Any single unprivileged unit poster can cast a `system_vote`, and any party can later trigger the tally via `system_vote_count`; both are ordinary, permissionless message types (per `validation.js` `system_vote`/`system_vote_count` handling), so no privileged actor is required to trigger the scenario — only patience for the natural passage of time between vote and count.

### Recommendation
Re-apply `checkNotAAs`, `checkWitnessesKnownAndGood`, and `checkNoReferencesInWitnessAddressDefinitions` (evaluated as of the `countVotes` execution MCI, not the original vote's `last_ball_mci`) against the winning OP set inside `countVotes` before writing the result to `storage.systemVars`/`system_vars`. Any winning candidate that fails these checks at count time should be excluded and replaced by the next-highest-voted eligible candidate, mirroring the fix pattern applied in the referenced Tidal report (moving/duplicating the validation into the execute path).

### Proof of Concept
1. Address `X` is a normal, "good", non-AA address with a simple definition (no `seen address`/`seen definition change` references). A unit posts `system_vote {subject:'op_list', value: [..., X, ...]}` and passes validation (`checkNotAAs`, `checkWitnessesKnownAndGood`, `checkNoReferencesInWitnessAddressDefinitions` all succeed) — vote recorded in `op_votes`/`system_votes`.
2. Before enough voting balance accumulates to satisfy `SYSTEM_VOTE_MIN_SHARE` within the initial 1-year window, `countVotes` keeps expanding its lookback window (per `main_chain.js:1807-1821`), so tallying is deferred.
3. During this deferred period, address `X` deploys an AA definition at that same address (or has its address definition redefined to include a `seen address` reference, or accumulates enough bad units to be marked non-good sequence).
4. `system_vote_count {payload:'op_list'}` becomes stable and triggers `countVotes(conn, mci, 'op_list')`. The function tallies balances/votes and selects the top `COUNT_WITNESSES` addresses purely by vote weight (`main_chain.js:1850-1863`) — `X` is still selected since no re-validation of AA/sequence/reference status is performed.
5. `X`, now disqualified (AA/bad-sequence/self-referencing definition), is written into `storage.systemVars.op_list` and becomes part of the OP list used by every node for `getOpList`/witnessed-level computation going forward.

### Citations

**File:** validation.js (L1861-1882)
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
					checkNotAAs(conn, arrOPs, objValidationState.last_ball_mci, err => {
						if (err)
							return callback(err);
						checkWitnessesKnownAndGood(conn, objValidationState, arrOPs, err => {
							if (err)
								return callback(err);
							checkNoReferencesInWitnessAddressDefinitions(conn, objValidationState, arrOPs, callback);
						});
					});
```

**File:** main_chain.js (L1657-1660)
```javascript
					async function() {
						// vote count must be processed last, after all system_votes, and once for the entire mci
						for (let subject of voteCountSubjects)
							await countVotes(conn, mci, subject);
```

**File:** main_chain.js (L1737-1751)
```javascript
async function countVotes(conn, mci, subject, is_emergency = 0, emergency_count_command_timestamp = 0) {
	console.log('countVotes', mci, subject, is_emergency, emergency_count_command_timestamp);
	if (is_emergency && subject !== "op_list")
		throw Error("emergency vote count supported for op_list only, got " + subject);
	const address_rows = await conn.query("SELECT DISTINCT address FROM system_votes WHERE subject=?", [subject]);
	let addresses = address_rows.map(r => r.address);
	const unstable_votes = (is_emergency && mci >= constants.pemCurvesFixMci) ? getUnstableVotes(emergency_count_command_timestamp) : null;
	if (unstable_votes) {
		for (let { author_addresses } of unstable_votes) {
			for (let address of author_addresses)
				addresses.push(address);
		}
		addresses = _.uniq(addresses);
	}
	const strAddresses = addresses.map(db.escape).join(', ');
```

**File:** main_chain.js (L1807-1821)
```javascript
	// Vote timeframe. If too small share has voted in the previous year, expand the period to 2 years. If still small, expand to 3 years, and so on.
	let since_timestamp = mc_timestamp;
	while (true) {
		since_timestamp -= 365 * 24 * 3600;
		if (since_timestamp <= activation_timestamp)
			break;
		const [{ total_balance }] = await conn.query(`SELECT SUM(balance) AS total_balance 
			FROM voter_balances
			WHERE address IN (
				SELECT DISTINCT address FROM system_votes WHERE subject=? AND timestamp>=?
			)`,
			[subject, since_timestamp]);
		if (total_balance >= constants.SYSTEM_VOTE_MIN_SHARE * constants.TOTAL_WHITEBYTES)
			break;
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

**File:** main_chain.js (L1908-1913)
```javascript
	console.log(`new`, subject, value);
	// a repeated emergency vote on the same mci would overwrite the previous one
	await conn.query(`${is_emergency || mci === 0 ? 'REPLACE' : 'INSERT'} INTO system_vars (subject, value, vote_count_mci, is_emergency) VALUES (?, ?, ?, ?)`, [subject, value, mci === 0 ? -1 : mci, is_emergency]);
	await conn.query(conn.dropTemporaryTable('voter_balances'));
	eventBus.emit('system_vars_updated', subject, value);
}
```

**File:** storage.js (L655-664)
```javascript
	conn.query("SELECT witness_list_unit, main_chain_index, is_stable FROM units WHERE unit=?", [unit], function(rows){
		if (rows.length === 0)
			throw Error("unit "+unit+" not found");
		const { witness_list_unit, main_chain_index, is_stable } = rows[0];
		if (main_chain_index >= constants.v4UpgradeMci) {
			const op_list = getOpList(main_chain_index);
			if (is_stable)
				assocCachedUnitWitnesses[unit] = op_list;
			return handleWitnessList(op_list);
		}
```
