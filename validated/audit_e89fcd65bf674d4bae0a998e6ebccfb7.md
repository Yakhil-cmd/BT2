### Title
Stale system votes never expire, letting old ballots dominate current governance parameters including the OP (witness) list - (File: main_chain.js)

### Summary
Obyte's `ocore--016` implements an on-chain governance mechanism analogous to Olympus' `Governance.sol`: any unprivileged unit author can cast a `system_vote` message (subject `op_list`, `threshold_size`, `base_tps_fee`, `tps_interval`, or `tps_fee_multiplier`) and later trigger tallying with a `system_vote_count` message. Both message types are validated as ordinary payloads postable by any address (AAs are explicitly excluded), matching the "unprivileged unit poster" reachability requirement.

### Finding Description
Votes are stored forever in `system_votes` with no expiration, exactly the "active proposal never expires" pattern from the referenced report. [1](#0-0) 

Anyone can post a `system_vote_count` message for a subject; it is queued and processed once its MCI stabilizes, invoking `countVotes`: [2](#0-1) [3](#0-2) 

`countVotes` computes the tally using a widening lookback window: it starts at one year before the counting MCI's timestamp and, if the balance of addresses that voted within the window is below `SYSTEM_VOTE_MIN_SHARE`, keeps expanding the window backward (2 years, 3 years, ...) all the way to the very first ever recorded vote (`activation_timestamp`), without ever discarding a vote as "expired": [4](#0-3) 

The result of that (possibly very old) window is then applied to `system_vars`, immediately taking effect network-wide, including for the `op_list` (the Order Providers / witnesses that determine consensus and stability): [5](#0-4) [6](#0-5) 

Because there is no cutoff for how old a counted vote can be — only a minimum aggregate share requirement that is satisfied by expanding the search window arbitrarily far back — a `system_vote` cast years ago by addresses that have since become malicious, compromised, or otherwise misaligned with current network interests can still dominate a fresh count triggered today, as long as recent voter turnout for that subject remains low. This mirrors the Olympus finding precisely: "the proposal is active until [a] new one is submitted... 6 months elapses and the current active proposal might cause serious harm to the protocol... a malicious actor votes and executes proposal causing harm to the protocol" — here, an old vote instead of an old proposal persists indefinitely and can be "executed" (counted and applied) at any future time by any unprivileged unit poster issuing `system_vote_count`.

### Impact Explanation
`countVotes` directly determines `system_vars.op_list`, which is the set of Order Providers used for main-chain stability and witnessing, as well as `threshold_size`, `base_tps_fee`, `tps_interval`, and `tps_fee_multiplier`, which govern fee economics and throughput. If stale votes from long-inactive or compromised large holders can dominate a count triggered at an arbitrary future time (simply because recent turnout is thin), the network's OP set or fee/TPS parameters could be forced to values reflecting years-old, no-longer-representative intent. This can lead to nodes disagreeing on the "correct" active OP set/parameters if timing of counting differs, or to an attacker capturing witness control long after acquiring (and possibly later divesting) the funding balance used to vote — a form of governance capture with no automatic expiry safeguard, directly affecting stability/consensus of a network-critical parameter.

### Likelihood Explanation
The `system_vote_count` trigger is completely permissionless (any regular unit author can send it) and requires no coordination beyond a single message; `countVotes` runs automatically whenever this message stabilizes. The widening-window logic is a normal, always-active code path, not a rare edge case, and will silently reach back to `activation_timestamp` whenever the recent-window balance is below `SYSTEM_VOTE_MIN_SHARE` — a condition plausible during periods of voter apathy on a specific subject.

### Recommendation
Introduce a hard expiration for individual votes in `system_votes` (e.g., a `MAX_VOTE_AGE`) so that `countVotes`'s widening window in `main_chain.js` cannot reach back indefinitely to `activation_timestamp`; once the maximum age is reached, the count should either fail-safe to the previous value or require an explicit minimum-turnout floor within a bounded time period rather than an unbounded backward search.

### Proof of Concept
1. Address `A` casts `system_vote` for `subject: "op_list"` at time T0 with a large VOTES/byte balance, recorded permanently in `system_votes` [1](#0-0) .
2. Years pass; turnout on `op_list` votes drops so that the balance voting within the most recent 1–N year windows never reaches `SYSTEM_VOTE_MIN_SHARE` of `TOTAL_WHITEBYTES` [4](#0-3) .
3. Address `A` (now potentially compromised or acting maliciously, having kept/re-acquired the balance) or any unrelated user posts a `system_vote_count` message for `op_list` [2](#0-1) .
4. Once that unit stabilizes, `countVotes` expands its lookback window all the way back to T0, counts `A`'s stale vote, and applies the resulting OP list to `storage.systemVars.op_list`, taking effect network-wide [7](#0-6) .

### Citations

**File:** initial-db/byteball-sqlite.sql (L950-960)
```sql
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
);
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

**File:** main_chain.js (L1657-1664)
```javascript
					async function() {
						// vote count must be processed last, after all system_votes, and once for the entire mci
						for (let subject of voteCountSubjects)
							await countVotes(conn, mci, subject);
						// next op
						updateRetrievable();
					}
				);
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

**File:** main_chain.js (L1908-1912)
```javascript
	console.log(`new`, subject, value);
	// a repeated emergency vote on the same mci would overwrite the previous one
	await conn.query(`${is_emergency || mci === 0 ? 'REPLACE' : 'INSERT'} INTO system_vars (subject, value, vote_count_mci, is_emergency) VALUES (?, ?, ?, ?)`, [subject, value, mci === 0 ? -1 : mci, is_emergency]);
	await conn.query(conn.dropTemporaryTable('voter_balances'));
	eventBus.emit('system_vars_updated', subject, value);
```
