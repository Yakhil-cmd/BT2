### Title
Low-turnout system_vote counting allows a minority stake to seize control of critical network parameters (op_list, threshold_size, TPS fees) - ([File: main_chain.js])

### Summary
`countVotes()` in `main_chain.js` tallies `system_vote` messages (any address can post one — no privilege required) to set `system_vars` such as `op_list` (the witness/order-provider list), `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier`. The only "quorum" safeguard is that the *voting window* is expanded until the cumulative balance of addresses that voted reaches `SYSTEM_VOTE_MIN_SHARE * TOTAL_WHITEBYTES` (10% of total supply). Once that 10% participation bar is met, the outcome is decided purely by relative weight among the *votes cast*, not by a majority of total supply. [1](#0-0) [2](#0-1) 

This is directly analogous to the `BaseERC20Guild` "low totalLocked" bug class: instead of guild proposal voting power being measured against a shrinkable `totalLocked`, ocore's system-parameter voting power is measured only against the (potentially small) subset of GBYTE balance that has actively voted, not the full token supply. A holder who controls just over half of that minimal 10% share (~5.01% of total coin supply) can dictate `op_list` or fee/threshold parameters, exactly as a guild attacker with disproportionate voting power relative to a low `totalLocked` could seize control.

### Finding Description
`countVotes(conn, mci, subject, ...)` first computes `voter_balances` for addresses that have cast a vote for `subject`, then expands `since_timestamp` backward year by year only until the accumulated voting balance for that subject reaches 10% of `TOTAL_WHITEBYTES`: [1](#0-0) 

For the numeric subjects (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`), the final value is chosen as the median by weighted balance among the votes that satisfied this minimal window, with no absolute minimum on `total_voted_balance` itself: [3](#0-2) 

For `op_list`, the winning set of 12 (`COUNT_WITNESSES`) addresses is simply the top-weighted `op_address` values summed over `voter_balances`, again bounded only by the same 10%-of-supply participation floor, not by a true majority of all coin holders: [4](#0-3) 

Validation of the `system_vote` message itself imposes no lower bound on the voting balance or number of distinct voters — any address holding bytes can submit a vote, and there is no floor check analogous to a `minimumTokensLockedForProposalCreation`/`minimumMembersForProposalCreation` safeguard: [5](#0-4) 

Because `SYSTEM_VOTE_MIN_SHARE` is fixed at `0.1` (10% of total supply) regardless of how concentrated that 10% is among a few addresses, and the vote-counting logic never requires that voted balance represent a supermajority of total supply, a coalition (or single large holder) controlling slightly more than 5% of the entire coin supply — while abstaining voters remain at 0% — can decide the elected `op_list` or manipulate `threshold_size`/`base_tps_fee`/`tps_interval`/`tps_fee_multiplier`. This mirrors the reported bug class: `totalLocked` (here, "total voted balance") is a small, attacker-influenceable denominator rather than the full token supply, letting minority stake dictate system-critical outcomes.

`op_list` in particular controls which addresses are treated as order providers/witnesses for main-chain stability determination (`storage.getOpList`, used throughout `validation.js` and `writer.js` for witnessed-level and stability calculations) [6](#0-5) [7](#0-6) , so control over it is control over the network's finality/validity mechanism — a direct parallel to the guild-takeover's `setConfig` hijack that let the attacker rewrite proposal/lock timing.

### Impact Explanation
Successfully forcing a favorable `op_list` outcome lets an attacker install addresses they control (or collude with) as order providers, undermining main-chain stability/witness-level determination used throughout unit validation and stabilization — this is a node-disagreement-on-validity/stability class impact. Manipulating `threshold_size`, `base_tps_fee`, `tps_interval`, or `tps_fee_multiplier` can distort TPS-fee economics and unit sizing, potentially freezing normal fee-based unit confirmation or making the network unable to process/confirm units under the new parameters, paralleling the "spam further proposals" / "proposal DoS" outcomes in the original report.

### Likelihood Explanation
This requires an attacker to control roughly 5%+ of total coin supply concentrated for voting purposes (or coordinate with other holders), which is a high bar relative to typical smart-contract guild takeovers, but is far below a "51% attack" threshold and does not require any privileged network role — it is reachable by any unprivileged unit poster who can craft `system_vote`/`system_vote_count` messages. The likelihood is elevated in early-network or low-participation periods (mirroring "guilds that have just started" in the original report), since the 10% floor is measured against fixed `TOTAL_WHITEBYTES`, not against currently-circulating/active supply, so if voter turnout is chronically low the same small set of large holders can repeatedly dominate every vote count cycle.

### Recommendation
Introduce an additional, higher supply-based quorum/majority requirement (not just the fixed 10% participation floor) before accepting a `countVotes` outcome for security-critical subjects like `op_list`, and/or require diversity among distinct voting addresses (not just aggregate balance) similar to the `minimumMembersForProposalCreation` mitigation adopted for `BaseERC20Guild`. Consider raising `SYSTEM_VOTE_MIN_SHARE` for `op_list` specifically, or requiring supermajority (e.g., >50% of `TOTAL_WHITEBYTES`) rather than 10%, given the outsized power `op_list` control confers over network stability.

### Proof of Concept
1. An attacker acquires/controls addresses holding slightly over 5% of `TOTAL_WHITEBYTES` (half of the `SYSTEM_VOTE_MIN_SHARE=0.1` floor, assuming all other votes for the `op_list` subject sum to a smaller aggregate — plausible when overall voter turnout is low).
2. Attacker posts `system_vote` messages (subject `op_list`) from these addresses proposing a set of 12 addresses they control, satisfying validation checks in [8](#0-7) .
3. Once stable, `saveSystemVote` records these into `system_votes`/`op_votes` [9](#0-8) .
4. At the next `countVotes` invocation for `op_list`, the `since_timestamp` expansion loop finds the 10%-of-supply threshold satisfied once the attacker's votes (plus any minimal pre-existing votes) are included, and the top-weighted 12 `op_address` entries — the attacker's own addresses — are installed into `storage.systemVars.op_list` [10](#0-9) .
5. From this point, `storage.getOpList()` returns the attacker-controlled witness list used across unit validation and main-chain stability logic [6](#0-5) , giving the attacker practical control over network validity/stability determination with a minority of total supply.

### Citations

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

**File:** main_chain.js (L1878-1903)
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
			break;
```

**File:** constants.js (L73-74)
```javascript
exports.SYSTEM_VOTE_COUNT_FEE = 1e9;
exports.SYSTEM_VOTE_MIN_SHARE = 0.1;
```

**File:** validation.js (L925-926)
```javascript
	if (objValidationState.last_ball_mci >= constants.v4UpgradeMci)
		return checkWitnessedLevelDidNotRetreat(storage.getOpList(objValidationState.last_ball_mci));
```

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

**File:** writer.js (L488-500)
```javascript
		function updateWitnessedLevel(cb){
			if (bGenesis)
				return cb();
			profiler.start();
			if (bCommonOpList)
				updateWitnessedLevelByWitnesslist(storage.getOpList(objValidationState.last_ball_mci), cb);
			else if (objUnit.witnesses)
				updateWitnessedLevelByWitnesslist(objUnit.witnesses, cb);
			else
				storage.readWitnessList(conn, objUnit.witness_list_unit, function(arrWitnesses){
					updateWitnessedLevelByWitnesslist(arrWitnesses, cb);
				});
		}
```
