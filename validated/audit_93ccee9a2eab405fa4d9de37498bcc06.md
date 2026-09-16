### Title
Governance vote weight in `countVotes()` is based on transient current balance, allowing flashloan-style manipulation of network parameters and OP list - (File: `main_chain.js`)

### Summary
The on-chain governance mechanism that lets any unit author vote on system parameters (`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) weighs each voter's ballot by the address's *current* unspent byte balance at the moment the vote is tallied, not by a balance that was locked or held for any minimum duration. This is the same bug class as the reported `MinVotingPowerCondition` flashloan issue: "voting power" is derived from a spot balance check rather than a durably committed stake, so an attacker can transiently inflate their balance just long enough to be counted, then move the funds away immediately afterward.

### Finding Description
Anyone can attach a `system_vote` message to a unit to register a vote for a subject/value pair, and anyone can later attach a `system_vote_count` message to trigger tallying for that subject; both are ordinary unit-poster actions, not privileged operations [1](#0-0) .

When a `system_vote_count` message becomes stable, `main_chain.js` calls `countVotes(conn, mci, subject)` for every requested subject exactly once for that MCI [2](#0-1) .

`countVotes()` computes each voting address's weight from a live query of currently-unspent, stable-good `base`-asset outputs: [3](#0-2) 

This balance is *not* the balance the address held when it cast the `system_vote`, nor any amount that is locked/escrowed for the voting period - it is whatever is unspent for that address as of the stabilization point being processed. The vote record itself (`op_votes` / `numerical_votes`) only stores the "latest vote per address" and is included in the tally as long as its timestamp falls within a sliding `since_timestamp` window [4](#0-3) , but the *weight* used for that vote is always the balance queried at tally time: [5](#0-4) [6](#0-5) 

Votes themselves are cheap and persistent: `saveSystemVote()` simply upserts the latest vote per author into `system_votes`/`op_votes`/`numerical_votes` when the casting unit stabilizes [7](#0-6) , with no requirement that the voting balance be locked, escrowed, or held beyond the instant of the tally.

Because ocore units settle asynchronously as part of MC stabilization (rather than atomic single-block transactions), an attacker can still construct a "flashloan-equivalent" sequence entirely within units that stabilize together:
1. Cast (or have already cast) a `system_vote` for a target subject/value from address A.
2. Temporarily fund address A with a large `base` balance (e.g., via a lending/AA construct that requires repayment in a subsequent, already-prepared unit, or via any payment that will be spent again immediately after).
3. Post a `system_vote_count` message for that subject; once this becomes stable, `countVotes()` sums A's currently unspent balance, giving it outsized weight in the tally.
4. Spend/return the borrowed funds in the very next unit, once the tally has already used the inflated balance.

Since the borrowed funds only need to be *unspent as of the specific MCI being stabilized* when `countVotes()` runs - and the spending unit can already be pre-signed and released immediately after - no durable stake is actually required to swing `op_list` (the operator/witness list used for consensus quorum) or the numeric network parameters (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`).

### Impact Explanation
`op_list` directly determines the set of Order Providers (witnesses) used for main-chain stability determination and consensus quorum [8](#0-7) . `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` are read via `storage.getSystemVar()` and directly control unit oversize-fee and TPS-fee calculations network-wide [9](#0-8) . Manipulating any of these via artificially inflated, transient voting weight can:
- Push in a malicious or colluding OP list, causing nodes to disagree on stability/validity or enabling a minority to control main-chain determination.
- Push extreme fee/threshold parameters that either allow cheap spam (network DoS via low fees/thresholds) or make the network unusable/expensive for legitimate users.

This satisfies the "node disagreement on validity or stability" / "network unable to confirm new units" impact bar for a High severity governance-manipulation bug.

### Likelihood Explanation
Exploitation only requires the capability to briefly acquire a large `base`-byte balance (e.g., via a compliant lending counterparty, exchange in/out, or a custom AA lending construct) and to already control an address with a registered `system_vote`. No special network privileges, hub/node/peer role, or protocol upgrade bypass is needed - `system_vote` and `system_vote_count` are both plain, unauthenticated message types available to any unit author [1](#0-0) . The main practical constraint is amassing a large enough transient balance relative to `SYSTEM_VOTE_MIN_SHARE * TOTAL_WHITEBYTES`, which is a capital/logistics problem rather than a protocol barrier.

### Recommendation
- Do not weigh votes by the balance held at tally time. Instead, snapshot/lock the voting balance at the time the `system_vote` is cast (or require the balance to be held continuously between vote-cast time and count time), analogous to requiring "locked" stake instead of a spot balance check.
- Alternatively, require a minimum holding duration (e.g., balance must have been present for N MCIs/timestamp prior to the count) before it can contribute to a tally, similar to the report's suggestion of not allowing the same-block/same-window creation and use of voting power.
- Consider decaying/averaging balance over the `since_timestamp` window rather than taking an instantaneous snapshot, to make short-lived capital injections economically costly.

### Proof of Concept
1. Attacker address A casts `system_vote` for `{subject: "threshold_size", value: <target>}` in a low-balance unit; this stabilizes and is recorded via `saveSystemVote()` into `numerical_votes` [7](#0-6) .
2. Attacker arranges for a large `base` payment to land on address A (e.g., from a lending counterparty or their own liquid reserve) in a unit U1.
3. Attacker posts a `system_vote_count` message for `"threshold_size"` in a unit U2 that depends on/co-stabilizes with U1.
4. Once the MCI containing U1/U2 stabilizes, `main_chain.updateMainChain` invokes `countVotes(conn, mci, "threshold_size")`, which sums A's currently-unspent `base` balance (now inflated by U1) via the query at [10](#0-9) , giving A's vote outsized weight in the median calculation at [11](#0-10) .
5. In the immediately following unit U3, attacker spends/returns the large balance from A, restoring A to its original low balance - the inflated weight has already been baked into `system_vars` for `threshold_size`.

### Citations

**File:** validation.js (L1844-1923)
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

**File:** main_chain.js (L1656-1663)
```javascript
					},
					async function() {
						// vote count must be processed last, after all system_votes, and once for the entire mci
						for (let subject of voteCountSubjects)
							await countVotes(conn, mci, subject);
						// next op
						updateRetrievable();
					}
```

**File:** main_chain.js (L1757-1777)
```javascript
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

**File:** main_chain.js (L1850-1858)
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
```

**File:** main_chain.js (L1860-1870)
```javascript
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
```

**File:** main_chain.js (L1882-1902)
```javascript
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

**File:** storage.js (L1132-1166)
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
}
```
