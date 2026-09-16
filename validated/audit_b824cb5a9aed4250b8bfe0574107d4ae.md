Confirmed: `system_vote_count` validation only checks that `payload` is one of the five known subjects — no restriction on who can post it or how many times, and once accepted, `applyEmergencyOpListChange` fires immediately after the timeout with no further checks. [1](#0-0) 

### Title
Unrestricted, immediately-effective emergency system-parameter changes via `system_vote_count`/`system_vote` - (File: main_chain.js, validation.js)

### Summary
Any address can post a `system_vote` message to vote on protocol-critical parameters (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) and, after `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days) has elapsed since the last stable unit, any address can post a `system_vote_count` unit that triggers an immediate emergency recount and application of the new `op_list` — with no timelock, no minimum quorum requirement beyond the loosely-defined `SYSTEM_VOTE_MIN_SHARE`, and no protection against last-moment vote injection.

### Finding Description
The `system_vote` message is validated with only basic type/format/bound checks per subject [2](#0-1) , and the companion `system_vote_count` message is validated merely by checking that `payload` is one of the five known subject strings — there is no restriction on which addresses may trigger a count, and no rate limit beyond the natural "one per unit" constraint [1](#0-0) .

The emergency path is `applyEmergencyOpListChange`, invoked from `writer.js` whenever a `system_vote_count` message for `op_list` is included in a good-sequence unit [3](#0-2) . It checks only that the timeout since the last stable unit has passed, then immediately calls `countVotes` with `is_emergency=1` [4](#0-3) .

Inside `countVotes`, when counting is emergency, it collects still-**unstable** (unconfirmed) votes from `storage.assocUnstableMessages` via `getUnstableVotes` and merges them with already-stable votes, weighting by unspent balance [5](#0-4) [6](#0-5) . The only protection against last-second manipulation is `EMERGENCY_COUNT_MIN_VOTE_AGE` (1 hour) requiring a vote be at least 1 hour old relative to the count-trigger timestamp [7](#0-6) , and `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days) of DAG stall before the emergency path activates at all [8](#0-7) . Once the new `op_list` (or numeric parameter) is computed, it is written directly into `storage.systemVars` and the `system_vars` table and takes effect for subsequent MCIs with no further delay, review, or ability for honest participants to react [9](#0-8) .

This mirrors the reported bug class: a state-changing "settings" mechanism (analogous to `file()`) with essentially no economic/temporal guardrails, reachable by any ordinary unit poster (not a privileged admin, but functionally equivalent since a single address or small coordinated set of addresses holding enough weighted balance can force it), and whose effect is immediate and irreversible for the next MCI.

### Impact Explanation
An attacker (or colluding group) who accumulates sufficient stable-good-output balance can use the intentional 3-day DAG stall requirement combined with the emergency vote-count trigger to force through an `op_list` change (replacing order-providers) or manipulate `threshold_size`/`base_tps_fee`/`tps_interval`/`tps_fee_multiplier` medians with limited notice (only the 1-hour minimum vote age as friction). This can lead to network disagreement on validity/stability if the new OP set diverges from what honest nodes expect, or economic manipulation of fee parameters that other AAs and users rely on for correct fee computation (`getOversizeFee` reads `threshold_size` directly from `systemVars`) [10](#0-9) , potentially causing fee miscalculation, transaction rejection, or fund loss for unprepared honest actors.

### Likelihood Explanation
Likelihood is limited by the requirement to actually accumulate `SYSTEM_VOTE_MIN_SHARE * TOTAL_WHITEBYTES` of voting weight and by the 3-day DAG-stall precondition for `op_list`, and by validation bounds already imposed on the numeric subjects (e.g., `threshold_size >= 1000`, `tps_interval >= 0.1`) [11](#0-10) . However, no on-chain governance/timelock exists to let the community react once a valid emergency count is triggered, and the emergency path exists specifically to bypass normal (non-emergency) two-year rolling vote windows, making it the intended "fast path" attackers would target.

### Recommendation
Introduce a mandatory delay (timelock) between when `countVotes` computes a new emergency value and when it becomes effective (i.e., increase the effective `vote_count_mci` offset so the new value only applies several MCIs/days later), publish the impending change so honest OPs/users can react, and/or require a stronger supermajority / longer minimum vote age specifically for the emergency path rather than the standard 1-hour `EMERGENCY_COUNT_MIN_VOTE_AGE`.

### Proof of Concept
1. Accumulate stable-good unspent-output balance across several addresses ≥ `SYSTEM_VOTE_MIN_SHARE * TOTAL_WHITEBYTES`.
2. Post `system_vote` units (`subject: "op_list"`) from those addresses with a malicious 12-address OP set, spaced more than `EMERGENCY_COUNT_MIN_VOTE_AGE` (1 hour) apart from the eventual trigger.
3. Wait for (or otherwise arrange) the DAG to stall for `EMERGENCY_OP_LIST_CHANGE_TIMEOUT` (3 days) with no new stable MCI — this is plausible under network congestion or a coordinated slow-down.
4. Post a `system_vote_count` unit with `payload: "op_list"`; `writer.js` invokes `applyEmergencyOpListChange`, which immediately calls `countVotes(..., is_emergency=1, ...)` [4](#0-3) .
5. `countVotes` tallies the attacker's unstable votes (aged >1 hour) alongside stable ones and can select the attacker's chosen OP list if it commands the largest weighted balance, immediately overwriting `storage.systemVars.op_list` and `system_vars` table [12](#0-11) .

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

**File:** main_chain.js (L1737-1750)
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
```

**File:** main_chain.js (L1839-1912)
```javascript
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
			break;
		
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
			break;
		
		default:
			throw Error("unknown subject in countVotes: " + subject);
	}
	console.log(`new`, subject, value);
	// a repeated emergency vote on the same mci would overwrite the previous one
	await conn.query(`${is_emergency || mci === 0 ? 'REPLACE' : 'INSERT'} INTO system_vars (subject, value, vote_count_mci, is_emergency) VALUES (?, ?, ?, ?)`, [subject, value, mci === 0 ? -1 : mci, is_emergency]);
	await conn.query(conn.dropTemporaryTable('voter_balances'));
	eventBus.emit('system_vars_updated', subject, value);
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

**File:** constants.js (L18-19)
```javascript
exports.EMERGENCY_OP_LIST_CHANGE_TIMEOUT = 3 * 24 * 3600;
exports.EMERGENCY_COUNT_MIN_VOTE_AGE = 3600;
```

**File:** storage.js (L1132-1165)
```javascript
function getSystemVar(subject, mci) {
	for (let { vote_count_mci, value } of systemVars[subject])
		if (mci > vote_count_mci)
			return value;
	throw Error(subject + ` not found for mci ` + mci);
}

function getOpList(mci) {
	return getSystemVar('op_list', mci);
}

function exp(x) {
	return new Decimal(x).exp().toNumber();
}

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
```
