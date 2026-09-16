### Title
Unbounded `system_votes` table causes `countVotes` to build an ever-growing SQL query, risking stalled main-chain stabilization - (File: main_chain.js)

### Summary
`main_chain.js`'s `countVotes()` function builds its voter list by selecting **every distinct address that has ever cast a `system_vote`** for a subject, with no cap, pagination, or pruning, and then embeds that address list directly into follow-up SQL query strings. Because any unprivileged unit author can cheaply grow `system_votes` forever (it is explicitly documented as "just a log of all votes, including overridden ones" and rows are never deleted), the query built inside `countVotes` grows without bound over the life of the network. This mirrors the `BondAggregator.liveMarketsBy` bug class: a piece of consensus-critical logic that loops/queries over an ever-growing, attacker-inflatable dataset with no pagination, eventually becoming so expensive that it threatens to stall progress rather than simply reverting a view call.

### Finding Description
`countVotes` is invoked from `markMcIndexStable` → `advanceMcStability`, once per `system_vote_count` message, and *must* complete before main-chain stabilization for that MCI can finish: [1](#0-0) 

Inside it, the voter address set is read with no limit: [2](#0-1) 

That unbounded `addresses` array is then serialized into a raw SQL string and reused in multiple subsequent queries: [3](#0-2) 

The underlying `system_votes` table is explicitly a permanent, never-pruned log: [4](#0-3) 

Any unprivileged unit author can add a new row cheaply just by posting a `system_vote` message from a fresh author address; validation only checks the subject name and does not cap the number of distinct historical voters: [5](#0-4) 

The persistence path that appends to `system_votes` for every author of every `system_vote` unit, with no deduplication against historical size: [6](#0-5) 

Because `system_votes` never shrinks, an attacker who repeatedly posts `system_vote` messages from many distinct addresses (each a normal, cheap unit) can grow the `DISTINCT address` set for a subject indefinitely. Every time anyone (including the attacker) later posts a `system_vote_count` message, all full nodes must synchronously execute `countVotes`, which:
- builds an ever-larger `IN(...)` address list embedded in SQL text,
- creates and populates a temporary table sized to that same ever-growing list,
- performs several full scans/joins keyed on it.

This computation happens deterministically inside the synchronous stabilization critical path (`markMcIndexStable`), which every node must complete before it can advance the main chain and accept further units as stable. Unlike `BondAggregator.liveMarketsBy` (an isolated view call that simply reverts once gas runs out), here the equivalent unbounded work sits on the hot path of consensus advancement itself.

### Impact Explanation
As the address list grows without bound and cannot be pruned or paginated, the per-stabilization cost of `countVotes` grows unboundedly too. Once the query/temp-table size becomes large enough (bounded practical DB limits, memory, or simply node processing time exceeding the time available before the next MCI must stabilize), stabilization for MCIs containing `system_vote_count` can stall or slow dramatically for every full node simultaneously (since it is the same deterministic code path). Because MC stabilization gates finality of the entire DAG, a stall here propagates into an inability of the network to confirm new units — the same "unable to serve its function" outcome as the original report, but manifesting as a stall of consensus progress rather than an isolated read-only revert.

### Likelihood Explanation
Likelihood is limited by the cost of posting many distinct-author units over a long period (attacker must pay the normal per-unit fees for each new voting address), so this is a slow, low-cost griefing vector rather than a single-transaction exploit. It requires sustained effort, but it is fully reachable by any unprivileged unit poster (no special AA logic, node privilege, or race condition needed), and the affected table is explicitly designed to keep every historical vote forever, so there is no natural bound preventing eventual accumulation.

### Recommendation
Cap or paginate `countVotes`'s voter selection — e.g., only include addresses whose most recent vote for the subject falls within the relevant voting timeframe (`since_timestamp`) rather than `SELECT DISTINCT address FROM system_votes WHERE subject=?` over all history, or maintain a separate "latest vote per address" table analogous to `op_votes`/`numerical_votes` instead of scanning the full historical log. Add an explicit ceiling on distinct-voter count processed per `countVotes` call, with a documented pruning/aggregation strategy for `system_votes`.

### Proof of Concept
1. Attacker repeatedly creates units, each with a fresh single-use author address, containing a `system_vote` message for a fixed `subject` (e.g., `"threshold_size"`); each unit is valid and only costs normal fees.
2. Over time this inserts an ever-growing number of distinct rows into `system_votes` for that subject (rows are never deleted per schema/comments).
3. Attacker (or anyone) posts a `system_vote_count` message for that subject.
4. On stabilization, every full node's `main_chain.js` `countVotes()` executes `SELECT DISTINCT address FROM system_votes WHERE subject=?`, builds `strAddresses` from the full historical set, and performs multiple queries/temp-table operations sized to that ever-growing list — with cost scaling linearly (or worse) with the total number of historical voters, unbounded by any pagination or cap.

### Citations

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

**File:** main_chain.js (L1757-1773)
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
```

**File:** initial-db/byteball-mysql.sql (L928-943)
```sql
-- System votes

-- just a log of all votes, including overridden ones
CREATE TABLE system_votes (
	unit CHAR(44) NOT NULL,
	address CHAR(32) NOT NULL,
	subject VARCHAR(50) NOT NULL,
	value TEXT NOT NULL,
	timestamp INT NOT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (unit, address, subject)
--	FOREIGN KEY (unit) REFERENCES units(unit)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
CREATE INDEX bySysVotesAddress ON system_votes(address);
CREATE INDEX bySysVotesSubjectAddress ON system_votes(subject, address);
CREATE INDEX bySysVotesSubjectTimestamp ON system_votes(subject, timestamp);
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
