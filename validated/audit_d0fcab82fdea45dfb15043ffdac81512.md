### Title
Voter balance for system parameter votes is read at vote-tally time, not at vote-cast time, allowing voting-power inflation - ([File: main_chain.js])

### Summary
`system_vote` messages (used to vote on `op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`) can be posted by any unprivileged unit author with no minimum-balance requirement at cast time. The actual voting weight of each cast vote is only computed later, in `countVotes()`, by querying each voter's *current* stable-good byte balance at the moment the relevant main-chain-index (MCI) stabilizes — not the balance the voter held when the vote was cast.

### Finding Description
`system_vote` is validated in `validation.js` with essentially no balance/stake gate — only structural checks (subject whitelist, value format, etc.) are performed: [1](#0-0) 

The vote is recorded (with its `unit`, `address`, `subject`, `value`, `timestamp`) once its containing unit stabilizes: [2](#0-1) 

Weighting/tallying happens separately in `countVotes()`, which is invoked once per MCI after stabilization. It fetches the *live* balance of every address that has ever voted on that subject, as of the current stable state, and uses that live balance to weight the vote regardless of when the vote was actually cast: [3](#0-2) 

The stored comment explicitly acknowledges that balance changes after the vote is cast — up to and including the counting MCI — are counted: [4](#0-3) 

This is structurally the same bug class as the reported Sherlock finding: a governance-relevant quantity (`totalTokenVotingPower` in frankendao, here "voter balance/weight") is supposed to represent the voter's stake at the time of participation, but is instead recomputed from mutable, attacker-controllable current state at a later, unpinned point in time (vote-count time rather than vote-cast time). Because ocore's votes have no expiration and are only overridden by a newer vote from the same address (`PRIMARY KEY (address, subject)` in `numerical_votes`/`op_votes`), an address's very first (possibly minimal-balance) vote for `op_list` or `threshold_size` etc. remains in effect and gets re-weighted with whatever balance that address holds when `countVotes()` eventually runs — potentially much later and after receiving a large amount of bytes.

### Impact Explanation
`op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier` are core network/consensus parameters: `op_list` determines the order-provider/witness set used for main-chain stability determination, and the TPS-fee/threshold parameters affect fee economics and unit validity across the whole network. An attacker can:
1. Post a `system_vote` for a desired outcome (e.g., a manipulated OP list or an extreme `threshold_size`) while holding a negligible balance, so the vote is cheap and easily included.
2. Later acquire a large byte balance (purchase, internal transfer, or simply wait for existing holdings to be recognized) before the MCI that triggers `countVotes()` for that subject.
3. Because the tally uses the balance at count time, the attacker's earlier low-cost vote is retroactively weighted with the large balance, letting them dominate the vote outcome for a fraction of the honest cost, and without other voters getting a chance to react since votes are only re-tallied at (relatively infrequent) `system_vote_count` events.

This can bias or hijack a network-wide governance parameter (including the witness/OP set, which is foundational to MC stability), which the rules classify as a legitimate "node disagreement on validity or stability" / consensus-parameter-manipulation risk rather than a mere UI/no-impact issue.

### Likelihood Explanation
`system_vote` is reachable by any unprivileged address that can post a unit — no special privilege, minimum stake, or timing restriction is enforced at cast time [1](#0-0) . The only friction is the cost of eventually acquiring the balance before the count event, which is far less than having to pre-commit that balance before voting, and easily automatable. The counting logic guarantees the exploit works because it always reads current balances rather than a value pinned to the vote's timestamp [5](#0-4) .

### Recommendation
Snapshot and pin each voter's balance (or a "balance as of vote timestamp / last stable MCI at cast time") when the `system_vote` is recorded, rather than re-reading the live balance in `countVotes()`. Alternatively, weight votes using the balance history at the vote's own timestamp (similar to how `since_timestamp` already filters by vote recency) so that balance increases occurring strictly after a vote was cast cannot retroactively inflate that vote's weight.

### Proof of Concept
1. Attacker address `A` holds a minimal byte balance (e.g., dust amount).
2. `A` posts a `system_vote` unit for `subject: "threshold_size"` (or `op_list`) with an extreme/malicious `value`; this passes validation with no stake check [6](#0-5) .
3. The unit stabilizes; the vote is stored keyed by `(address, subject)` in `numerical_votes`/`op_votes` [7](#0-6) .
4. Before the MCI at which `countVotes()` next runs for that subject, `A` receives/consolidates a very large byte balance into that same address.
5. When `countVotes()` executes, it queries `A`'s current (now large) balance and uses it as `A`'s voting weight for the previously-cast, cheap vote [8](#0-7) , letting `A` dominate the median/threshold computation or OP-list selection disproportionately to the stake it held when it actually voted.

### Citations

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

**File:** validation.js (L1884-1892)
```javascript
				case "threshold_size":
					if (!isPositiveInteger(payload.value))
						return callback(payload.subject + " must be a positive integer");
					if (!constants.bTestnet || objValidationState.last_ball_mci > 3543000) {
						if (payload.value < 1000)
							return callback(payload.subject + " must be at least 1000");
					}
					callback();
					break;
```

**File:** main_chain.js (L1619-1636)
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
```

**File:** main_chain.js (L1638-1646)
```javascript
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

**File:** main_chain.js (L1751-1780)
```javascript
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
```

**File:** initial-db/byteball-sqlite.sql (L990-990)
```sql
-- new record added after system_vote_count. Votes are counted after the MCI is completed, therefore counted only once per MCI even if there are two system_vote_count commands on this MCI. All votes and balance updates up to and including this MCI are taken into account, even if they happen after system_vote_count on its MCI.
```
