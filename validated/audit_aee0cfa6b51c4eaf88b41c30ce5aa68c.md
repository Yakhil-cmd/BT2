Confirmed: `validation.js`'s `system_vote` case has no check that the voting author actually holds any GBYTE/base-asset balance — it only validates the payload shape (subject/value), witness eligibility for `op_list`, and numeric ranges for other subjects. [1](#0-0) 

### Title
Zero-balance addresses can spam `system_vote` units, flooding `system_votes`/`op_votes`/`numerical_votes` tables and the `system_var_vote` event stream - (File: validation.js, main_chain.js, writer.js)

### Summary
Any address, including one with zero GBYTE balance, can post a `system_vote` message and have it accepted, persisted, and broadcast, mirroring the `castVote`-without-votes issue in the reported governance contract.

### Finding Description
The `system_vote` validation path only checks payload shape and per-subject formatting constraints (`op_list` sortedness/witness eligibility, numeric ranges for `threshold_size`/`base_tps_fee`/`tps_interval`/`tps_fee_multiplier`); it never checks that `objValidationState.last_ball_mci`'s balance of the author (or any balance at all) is non-zero before accepting the vote. [1](#0-0)  Once accepted, `writer.js` immediately emits the `system_var_vote` event for every `system_vote` message and records it into `storage.assocUnstableMessages`, and upon stabilization `main_chain.js#saveSystemVote` inserts a row per author address into `system_votes` and (depending on subject) `op_votes`/`numerical_votes`, then emits `system_var_vote` again. [2](#0-1) [3](#0-2)  These events are also relayed to any light client that is `bWatchingSystemVars` via `network.js#sendSysVarVoteToAllWatchers`. [4](#0-3)  The actual voting weight is only computed later in `countVotes`, which sums stable-good balances per address, so a zero-balance voter's vote never affects the tallied outcome, but the unit itself, the DB rows, and the events are all created and broadcast regardless of balance. [5](#0-4) 

### Impact Explanation
Because the acceptance/broadcast/storage cost is decoupled from any balance requirement, an attacker can post arbitrarily many `system_vote` units from zero-balance (or minimally funded, since only a small change output is needed to move a unit through the DAG) addresses. This spams the `system_votes`, `op_votes`, and `numerical_votes` tables with permanent log rows (`system_votes` explicitly documents itself as "just a log of all votes, including overridden ones") and floods every full node and every light client watching system vars with `system_var_vote` justsayings, without contributing any real voting weight — directly analogous to the reported `VoteCast` spam issue. This is a data/DB and event-spam issue rather than a fund-loss or consensus-safety issue, since `countVotes` correctly filters by balance when computing final `system_vars`.

### Likelihood Explanation
Trivial to trigger: any address that can get a unit accepted into the DAG (minimal signature validation only, no balance/vote-weight precondition) can send `system_vote` messages after the `v4UpgradeMci` upgrade point, and each address can only vote once per unit (`bHasSystemVote` limits one per unit, but nothing prevents posting the same vote message from many different newly-created addresses).

### Recommendation
Add a balance/eligibility check to `system_vote` validation (or to the acceptance/relay logic in `writer.js`/`network.js`) requiring the author to hold a minimum non-zero base-asset balance at the time of voting (e.g., check via `storage`/`conn.query` on `outputs`, similar to the balance query already used in `countVotes`) before accepting the message or before relaying/logging `system_var_vote` events to watchers, so zero-weight votes cannot be used to flood storage and event traffic.

### Proof of Concept
1. Create a fresh address with zero GBYTE balance (fund only the minimal amount needed for the unit's own commissions).
2. Compose and broadcast a unit with a `system_vote` message (e.g., `{subject: "threshold_size", value: 1000}`), which passes all checks in `validation.js` case `"system_vote"` since none of them check balance. [1](#0-0) 
3. The unit is written; `writer.js` emits `system_var_vote` immediately, and once stable, `main_chain.js#saveSystemVote` inserts a permanent row into `system_votes`/`numerical_votes` and re-emits the event, which is relayed to all `bWatchingSystemVars` light clients. [2](#0-1) [3](#0-2) [4](#0-3) 
4. Repeat with many fresh zero/near-zero-balance addresses to flood the vote tables and event stream, with `countVotes` still excluding these addresses from the actual tally since their balance is 0. [5](#0-4)

### Citations

**File:** validation.js (L1844-1911)
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
					checkNotAAs(conn, arrOPs, objValidationState.last_ball_mci, err => {
						if (err)
							return callback(err);
						checkWitnessesKnownAndGood(conn, objValidationState, arrOPs, err => {
							if (err)
								return callback(err);
							checkNoReferencesInWitnessAddressDefinitions(conn, objValidationState, arrOPs, callback);
						});
					});
					break;
				case "threshold_size":
					if (!isPositiveInteger(payload.value))
						return callback(payload.subject + " must be a positive integer");
					if (!constants.bTestnet || objValidationState.last_ball_mci > 3543000) {
						if (payload.value < 1000)
							return callback(payload.subject + " must be at least 1000");
					}
					callback();
					break;
				case "base_tps_fee":
				case "tps_interval":
				case "tps_fee_multiplier":
					if (!(typeof payload.value === 'number' && isFinite(payload.value) && payload.value > 0))
						return callback(payload.subject + " must be a positive number");
					if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) {
						if (payload.subject === "tps_interval" && payload.value < 0.1)
							return callback(payload.subject + " must be at least 0.1");
						if (payload.subject === "base_tps_fee" && payload.value > 1e8)
							return callback(payload.subject + " must be at most 1e8");
						if (payload.subject === "tps_fee_multiplier" && (payload.value < 1 || payload.value > 1000))
							return callback(payload.subject + " must be between 1 and 1000");
					}
					callback();
					break;
				default:
					return callback("unknown subject: " + payload.subject);
			}
			break;
```

**File:** writer.js (L603-613)
```javascript
			if (objUnit.messages) {
				objUnit.messages.forEach(function(message) {
					if (['data_feed', 'definition', 'system_vote', 'system_vote_count'].includes(message.app)) {
						if (!storage.assocUnstableMessages[objUnit.unit])
							storage.assocUnstableMessages[objUnit.unit] = [];
						storage.assocUnstableMessages[objUnit.unit].push(message);
						if (message.app === 'system_vote' && !objValidationState.bDryRun)
							eventBus.emit('system_var_vote', message.payload.subject, message.payload.value, arrAuthorAddresses, objUnit.unit, 0);
					}
				});
			}
```

**File:** main_chain.js (L1619-1651)
```javascript
								async function saveSystemVote(payload) {
									console.log('saveSystemVote', payload);
									const { subject, value } = payload;
									const objStableUnit = storage.assocStableUnits[unit];
									if (!objStableUnit)
										throw Error("no stable unit " + unit);
									const { author_addresses, timestamp } = objStableUnit;
									const strValue = subject === "op_list" ? JSON.stringify(value) : value;
									for (let address of author_addresses)
										await conn.query("INSERT INTO system_votes (unit, address, subject, value, timestamp) VALUES (?,?,?,?,?)", [unit, address, subject, strValue, timestamp]);
									let sqlValues = [];
									switch (subject) {
										case "op_list":
											const arrOPs = value;
											await conn.query("DELETE FROM op_votes WHERE address IN (?)", [author_addresses]);
											for (let address of author_addresses)
												sqlValues = sqlValues.concat(arrOPs.map(op_address => `(${db.escape(unit)}, ${db.escape(address)}, ${db.escape(op_address)}, ${timestamp})`));
											await conn.query("INSERT INTO op_votes (unit, address, op_address, timestamp) VALUES " + sqlValues.join(', '));
											break;
										case "threshold_size":
										case "base_tps_fee":
										case "tps_interval":
										case "tps_fee_multiplier":
											await conn.query("DELETE FROM numerical_votes WHERE subject=? AND address IN (?)", [subject, author_addresses]);
											for (let address of author_addresses)
												sqlValues.push(`(${db.escape(unit)}, ${db.escape(address)}, ${db.escape(subject)}, ${value}, ${timestamp})`);
											await conn.query("INSERT INTO numerical_votes (unit, address, subject, value, timestamp) VALUES " + sqlValues.join(', '));
											break;
										default:
											throw Error("unknown subject after stability: " + subject);
									}
									eventBus.emit('system_var_vote', subject, value, author_addresses, unit, 1);
								}
```

**File:** main_chain.js (L1741-1781)
```javascript
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
	let balances = {};
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
	if (values.length === 0)
```

**File:** network.js (L189-194)
```javascript
function sendSysVarVoteToAllWatchers(subject, value, author_addresses, unit, is_stable) {
	wss.clients.forEach(function (ws) {
		if (ws.bWatchingSystemVars)
			sendJustsaying(ws, 'system_var_vote', { subject, value, author_addresses, unit, is_stable });
	});
}
```
