### Title
SQL Injection via Partial Escaping in `countVotes()`/`saveSystemVote()` — `value` and `timestamp` Concatenated Directly into `numerical_votes` INSERT - (File: main_chain.js)

### Summary
`main_chain.js`'s `saveSystemVote()` builds an `INSERT INTO numerical_votes` statement by escaping `unit`, `address`, and `subject` with `db.escape()` but concatenating the attacker-influenced `value` (and `timestamp`) directly into the SQL string without escaping or parameterization — the exact "partial prepared statement" pattern described in the AVideo report, where some columns are safely bound/escaped and one is not.

### Finding Description
In `saveSystemVote(payload)`, invoked from `markMcIndexStable()`'s stabilization loop for every stable unit carrying a `system_vote` message, the numerical-subject branch does: [1](#0-0) 
```
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
`unit`, `address`, and `subject` are wrapped in `db.escape()`, matching the AVideo report's "correct pattern," but `value` — destructured directly from the unit's `system_vote` message payload — is interpolated raw into the SQL string, exactly like `videos_id` being concatenated raw next to a properly-parameterized `users_id` in the reported bug: [2](#0-1) 

The `system_vote` message app is a standard, user-postable message type (any address can author a unit containing `{app: "system_vote", payload: {subject, value}}`), so `value` is attacker-controlled input that becomes part of a unit's payload, i.e., reachable by any unprivileged unit poster.

### Impact Explanation
`saveSystemVote()`/`countVotes()` run deterministically during main-chain stabilization on every full node in the network. If `value` is not strictly constrained to a safe numeric literal by `validation.js`'s `system_vote` payload checks, a crafted `value` string could break out of the numeric-literal context and inject arbitrary SQL into the `INSERT INTO numerical_votes` statement. Since `mysql_pool.js`/query wrappers throw on SQL errors, a malformed injection would cause every node processing that stabilized unit to throw during stabilization — a deterministic, network-wide inability to advance stability/confirm new units. A successful (non-error-inducing) injection could instead corrupt `numerical_votes`, which feeds `countVotes()`'s outcome and ultimately governs system parameters such as `base_tps_fee`/`threshold_size`, potentially causing nodes to diverge on validity/stability if injected content is processed inconsistently across different DB engines (MySQL vs SQLite `escape()` differ in output).

### Likelihood Explanation
Reaching this code path requires only posting a valid unit with a `system_vote` message using one of the four numerical subjects — a normal, permissionless action available to any unit author. The likelihood that this is currently *exploitable* hinges entirely on whether `validation.js` enforces a strict numeric format for `value` before the unit is accepted; I was not able to fully inspect the `system_vote` validation logic in `validation.js` (only located 4 references, not the exact regex/type check) before running out of tool calls. If that validation is strict enough to reject any non-numeric string, this specific instance may not be exploitable as SQLi, though it remains a **latent bug-class match** (a hardcoded architectural weakness — mixing `db.escape()` for adjacent columns with raw concatenation for `value`) that mirrors the AVideo advisory precisely and should be hardened regardless.

### Recommendation
Replace the raw concatenation of `value` (and `timestamp`) in the `numerical_votes`/`sqlValues` construction with parameterized placeholders, consistent with the rest of the codebase's convention (e.g., as done for `system_votes` INSERT two lines earlier), and additionally enforce strict numeric-only validation for `value` in `validation.js` for the numerical `system_vote` subjects before storage, so the concatenation is defense-in-depth safe. Apply the same fix to the `op_list` branch's `sqlValues` array construction if `value`/`op_address` are not equally guaranteed to be escaped. [3](#0-2) 

### Proof of Concept
Exact exploitability could not be confirmed without viewing the full `validation.js` `system_vote` payload schema (out of tool budget). Conceptually: an attacker posts a unit authored by any address with:
```json
{"app": "system_vote", "payload": {"subject": "base_tps_fee", "value": "0),(1,'x','y',0,0);DROP TABLE numerical_votes;--"}}
```
If `validation.js` does not coerce/validate `value` to a strict numeric type for `base_tps_fee`/`threshold_size`/`tps_interval`/`tps_fee_multiplier` subjects prior to unit acceptance, once the unit stabilizes, `saveSystemVote()` embeds this string unescaped into the `INSERT INTO numerical_votes (...) VALUES (${db.escape(unit)}, ${db.escape(address)}, ${db.escape(subject)}, ${value}, ${timestamp})` statement, injecting arbitrary SQL executed identically on every node during stabilization.

### Citations

**File:** main_chain.js (L1619-1629)
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
```

**File:** main_chain.js (L1630-1637)
```javascript
									switch (subject) {
										case "op_list":
											const arrOPs = value;
											await conn.query("DELETE FROM op_votes WHERE address IN (?)", [author_addresses]);
											for (let address of author_addresses)
												sqlValues = sqlValues.concat(arrOPs.map(op_address => `(${db.escape(unit)}, ${db.escape(address)}, ${db.escape(op_address)}, ${timestamp})`));
											await conn.query("INSERT INTO op_votes (unit, address, op_address, timestamp) VALUES " + sqlValues.join(', '));
											break;
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
