## Analysis

The Hermez report describes a voting/bidding system where any actor can decide an outcome by acting with a large amount of value at the very last moment, with no cost to voting late and no incentive to commit early. The closest reachable analog in `ocore` is the **on-chain system parameter voting mechanism** (`system_vote` / `system_vote_count`), which lets any address vote to change the order-provider (witness) list or protocol TPS-fee parameters, with the vote weighted by the voter's **current byte balance at the moment counting happens**.

### Root cause

Any ordinary unit author can post a `system_vote` message for subjects `op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier` [1](#0-0) , and any address can post a `system_vote_count` message that schedules tallying for a subject as soon as an MCI stabilizes [2](#0-1) . Only the latest vote per address is kept (`op_votes`/`numerical_votes` are `REPLACE`d) [3](#0-2) .

When `countVotes` runs, it computes each voting address's weight from its **current unspent byte balance** at counting time (not the balance held when the vote was cast, and with no lock-up or bonding), then sums balances per candidate value and picks the winner (majority for `op_list`, median-by-balance for numeric subjects) [4](#0-3) [5](#0-4) .

All votes are public on the DAG as soon as they are broadcast, so any large holder can observe the standing tally, wait until the last possible moment (right before someone posts `system_vote_count`, which anyone is free to do at any time), fund an address with enough bytes, cast/overwrite their `system_vote`, and immediately have that balance counted — because the weight is the balance held now, not a bond that was locked in earlier. There is no decreasing weighting over time and no penalty for voting late, which is exactly the incentive structure described in the Hermez report: last-mover with more capital always wins, and honest early voters gain nothing by revealing their position first.

This mechanism controls the witness/order-provider list (`op_list`) and core protocol fee parameters (`base_tps_fee`, `tps_interval`, `tps_fee_multiplier`, `threshold_size`), i.e., consensus-critical, node-agreement-affecting parameters — not merely a cosmetic poll (`poll`/`vote` messages, by contrast, only support non-binding text polls with no economic effect [6](#0-5) , so those are out of scope here).

There is also a smoothing mechanism (expanding the counting window backward year by year until `SYSTEM_VOTE_MIN_SHARE` of `TOTAL_WHITEBYTES` has voted) [7](#0-6) , but this only affects which historical votes are included, not the fact that the *balance weight* used is the current, unlocked balance read at count time, and it does not prevent a whale from timing a large temporary balance to coincide with the count.

### Assessment against scope rules

While this is a legitimate structural weakness (whale-controlled, last-minute governance capture with public visibility of votes, matching the Hermez bug class precisely), I want to flag the uncertainty: exploiting it requires the attacker to actually hold/borrow a large byte balance and to control or race the timing of a `system_vote_count` post relative to other voters — this is a probabilistic/economic griefing vector rather than a deterministic double-spend, inflation, or fund-loss primitive. It can, however, let a well-funded party unilaterally set the witness list or fee parameters the network runs on, which is a "node disagreement on validity/stability" / network-configuration integrity concern.

### Title
Balance-weighted system parameter voting allows last-moment whale manipulation of witness list and fee parameters - (File: main_chain.js)

### Summary
`system_vote`/`system_vote_count` let any address change `op_list` (order providers/witnesses) or TPS fee parameters, with vote weight equal to the voter's current, unlocked byte balance measured at count time, not a balance committed when the vote was cast.

### Finding Description
`countVotes` reads `SUM(outputs.amount)` for each voting address's currently unspent, stable, good outputs as the vote weight [4](#0-3) , and combines it with the address's most recent `system_vote` row (overwritten on every new vote) [3](#0-2) . Since `system_vote_count` can be posted by anyone at any time once the relevant MCI stabilizes [2](#0-1) , and all pending votes are visible on the public DAG before counting, a well-funded actor can watch the standing tally, move a large sum of bytes into a voting address, cast (or overwrite) a vote, and trigger/wait for the count — all in the same narrow window — to decide the outcome, exactly the "no incentive to vote early / last-mover with capital wins" pattern from the Hermez report.

### Impact Explanation
`op_list` determines the network's order providers (witnesses), and `base_tps_fee`/`tps_interval`/`tps_fee_multiplier`/`threshold_size` determine core throughput/fee economics used by every node to validate units. A manipulated outcome forced by an unincentivized, last-minute high-balance vote can shift consensus-critical configuration, i.e., cause the network to adopt a witness set or fee schedule that most long-term/legitimate stakeholders did not actually support, undermining the intended stake-weighted governance of the protocol.

### Likelihood Explanation
Likelihood is bounded by cost: the attacker needs a temporarily large byte balance at the moment of counting and needs to time the `system_vote_count` trigger (which they can post themselves). Because it is entirely permissionless and requires no special privilege — any ordinary address can post both `system_vote` and `system_vote_count` — a sufficiently funded party can attempt this at will; the vote-count-window backfill (`SYSTEM_VOTE_MIN_SHARE`) somewhat dampens but does not eliminate this, since it only ensures cumulative participation, not resistance to a late, large, decisive vote.

### Recommendation
Short term: weight votes by balance held (or locked/staked) over a preceding window rather than the instantaneous balance at count time, and/or require a minimum bonding period before a vote counts (mirroring the report's "decreasing weight over time" mitigation) so that funding an address immediately before the count carries much less or no weight. Consider requiring `system_vote_count` to be delayed by a fixed minimum interval after the last vote change, so late voters cannot react to and immediately overpower the visible tally.
Long term: research time-decayed or commit-reveal based on-chain voting schemes to reduce the advantage of acting last with capital.

### Proof of Concept
1. Observe current standing tally for a `system_vote` subject (e.g., `op_list`) via `get_system_var_votes` [8](#0-7) .
2. Shortly before the vote window is expected to close (or immediately), transfer a large amount of bytes into address `W`.
3. From `W`, post a `system_vote` unit for the desired subject/value [1](#0-0) .
4. Post a `system_vote_count` unit for that subject [2](#0-1) .
5. Once the MCI stabilizes, `countVotes` sums `W`'s full current balance toward the chosen value/candidate, potentially flipping the outcome without prior stake commitment [5](#0-4) .

### Citations

**File:** validation.js (L1814-1842)
```javascript
		case "vote":
			if (objValidationState.bHasVote && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
				return callback("can be only one vote");
			objValidationState.bHasVote = true;
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (!isStringOfLength(payload.unit, constants.HASH_LENGTH))
				return callback("invalid unit in vote");
			if (typeof payload.choice !== "string")
				return callback("choice must be string");
			if (hasFieldsExcept(payload, ["unit", "choice"]))
				return callback("unknown fields in "+objMessage.app);
			conn.query(
				"SELECT main_chain_index, sequence FROM polls JOIN poll_choices USING(unit) JOIN units USING(unit) WHERE unit=? AND choice=?", 
				[payload.unit, payload.choice],
				function(poll_unit_rows){
					if (poll_unit_rows.length > 1)
						throw Error("more than one poll?");
					if (poll_unit_rows.length === 0)
						return callback("invalid choice "+payload.choice+" or poll "+payload.unit);
					var objPollUnitProps = poll_unit_rows[0];
					if (objPollUnitProps.main_chain_index === null || objPollUnitProps.main_chain_index > objValidationState.last_ball_mci)
						return callback("poll unit must be before last ball");
					if (objPollUnitProps.sequence !== 'good')
						return callback("poll unit is not serial");
					return callback();
				}
			);
			break;
```

**File:** validation.js (L1844-1859)
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

**File:** main_chain.js (L1630-1646)
```javascript
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
```

**File:** main_chain.js (L1757-1780)
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
	let values = [];
	for (let address in balances)
		values.push(`(${db.escape(address)}, ${balances[address]})`);
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

**File:** main_chain.js (L1850-1899)
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
```

**File:** network.js (L3435-3502)
```javascript
		case 'get_system_var_votes':
			let votes = {
				op_list: [],
				threshold_size: [],
				base_tps_fee: [],
				tps_interval: [],
				tps_fee_multiplier: [],			
			};
			let assocAddresses = {}
			let is_stable = 1;
			db.query("SELECT * FROM op_votes ORDER BY address, op_address", op_rows => {
				let prev_address, vote;
				for (let { address, op_address, unit, timestamp } of op_rows) {
					if (address !== prev_address) {
						vote = { address, unit, timestamp, value: [], is_stable };
						votes.op_list.push(vote);
						assocAddresses[address] = true;
						prev_address = address;
					}
					vote.value.push(op_address);
				}
				db.query("SELECT * FROM numerical_votes", n_rows => {
					for (let { subject, address, unit, value, timestamp } of n_rows) {
						votes[subject].push({ address, unit, timestamp, value, is_stable });
						assocAddresses[address] = true;
					}

					// unconfirmed votes
					is_stable = 0;
					for (let unit in storage.assocUnstableMessages) { // undefined order of iteration, we might handle unstable votes from the same address in the wrong order
						const arrUnstableMessages = storage.assocUnstableMessages[unit];
						for (let message of arrUnstableMessages) {
							if (message.app !== 'system_vote')
								continue;
							const { subject, value } = message.payload;
							const { author_addresses, timestamp, sequence } = storage.assocUnstableUnits[unit];
							if (sequence !== 'good')
								continue;
							for (let address of author_addresses) {
								const prev_vote = votes[subject].find(vote => vote.address === address);
								if (prev_vote) {
									prev_vote.value = value;
									prev_vote.timestamp = timestamp;
									prev_vote.unit = unit;
									prev_vote.is_stable = 0;
								}
								else {
									votes[subject].push({ address, unit, timestamp, value, is_stable });
									assocAddresses[address] = true;
								}
							}
						}
					}
					// read the balances of all voting addresses
					let balances = {};
					const arrAddresses = Object.keys(assocAddresses);
					const strAddresses = arrAddresses.map(db.escape).join(', ');
					db.query(`SELECT address, SUM(amount) AS balance 
						FROM outputs
						LEFT JOIN units USING(unit)
						WHERE address IN(${strAddresses}) AND is_spent=0 AND asset IS NULL AND sequence='good' 
						GROUP BY address`,
						bal_rows => {
							for (let { address, balance } of bal_rows) {
								balances[address] = balance;
							}
							sendResponse(ws, tag, { votes, balances });
						}
```
