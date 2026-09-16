# Title
SQL injection via unescaped `value` in system-vote numerical vote insertion - (File: main_chain.js)

## Summary
`main_chain.js`'s `saveSystemVote()` function builds an `INSERT INTO numerical_votes` SQL statement by directly string-interpolating the vote `value` taken from a `system_vote` message payload, without using `db.escape()` or a parameterized `?` placeholder, unlike every other value in the same statement. [1](#0-0) 

## Finding Description
`saveSystemVote(payload)` is invoked for every stabilized unit that carries a `system_vote` message, once per author address, during main-chain stabilization (a deterministic, consensus-critical code path executed identically by every full node): [2](#0-1) 

For the numerical-vote subjects (`threshold_size`, `base_tps_fee`, `tps_interval`, `tps_fee_multiplier`), the code builds each row string with `db.escape()` applied to `unit`, `address`, and `subject`, but **not** to `value`:
```
sqlValues.push(`(${db.escape(unit)}, ${db.escape(address)}, ${db.escape(subject)}, ${value}, ${timestamp})`);
await conn.query("INSERT INTO numerical_votes (unit, address, subject, value, timestamp) VALUES " + sqlValues.join(', '));
``` [1](#0-0) 

This is structurally the same bug class described in the external report: user-controlled input (here, the `value` field of an attacker-crafted `system_vote` message) is concatenated unescaped into a raw SQL string that is subsequently executed by the database engine (`conn.query`), rather than being passed as a bound parameter. In the referenced Archery advisory, `tb_name`/`db_name`/`schema_name` were concatenated unescaped into `describe_table`; here, `value` is concatenated unescaped into the `numerical_votes` insert. The asymmetry within the same line — `op_address` in the `op_list` branch is escaped via `db.escape()`, while `value` in the numerical-vote branch is not — indicates the omission is an oversight rather than an intentional design choice, and strongly suggests the developers implicitly assumed `value` would always already be a safe JS number by this point.

I was not able to fully re-confirm, within the available tool calls, the exact type/format enforcement that `validation.js` applies to the `value` field of `system_vote` messages before a unit is accepted and its message stored as "unstable" (pending stabilization). If that validation strictly coerces/validates `value` to a JS `Number` (not a string) before it is placed in `objValidationState`/stored message payload, then the interpolation would only ever produce numeric digits and this would not be exploitable. If, however, validation only checks the value loosely (e.g., permits a numeric-looking string, or does not re-validate type before the object reaches `saveSystemVote` at stabilization time, which runs on a different code path/tick than the original validator), a crafted payload value could break out of the numeric-position context and inject arbitrary SQL into a query that every full node executes identically.

## Impact Explanation
Because `saveSystemVote` runs identically on every full node during deterministic main-chain stabilization, a successful injection would be a **network-wide, deterministic side effect** triggered by a single posted unit containing a `system_vote` message — not a single-node/local issue. Depending on the injected payload this could:
- Corrupt or overwrite unrelated tables in the node's database (arbitrary INSERT/UPDATE/DELETE chained via `;`-separated statements, depending on the underlying driver's statement batching), potentially affecting balance/output bookkeeping tables consulted during validation of subsequent units.
- Cause query execution errors that crash or desync individual full nodes at the exact same MCI, producing **node disagreement on validity/stability** if the SQL driver behavior differs slightly between node database backends (MySQL vs SQLite), or halting further processing on affected nodes and contributing to a network that is unable to confirm new units on those nodes.
- Manipulate `numerical_votes`, which feeds vote counting (`countVotes`) for governance parameters like `base_tps_fee`/`tps_interval`/`tps_fee_multiplier`/`threshold_size`; corrupting this table could distort the aggregated vote result computed independently by each node, again producing node disagreement on system-parameter state, which downstream affects fee calculation and could freeze legitimate transactions (fees suddenly disallowed) or enable spam that degrades network availability.

## Likelihood Explanation
`system_vote` messages are a standard oscript-level message type postable by any ordinary unit author (not restricted to witnesses/order-providers), matching the "unpriviledged unit poster" reachability required by scope. The trigger requires only crafting a single well-formed unit with a `system_vote` message whose `subject` is one of the four numerical-vote subjects and whose `value` field is not fully sanitized by validation before reaching `saveSystemVote`. Likelihood is therefore contingent entirely on the strictness of `validation.js`'s type checking of `value` for these subjects, which I could not fully verify with the remaining tool budget — this is the single largest source of uncertainty in this finding.

## Recommendation
Regardless of the current validation strength, `value` should be inserted via a bound parameter (`?`) rather than string interpolation, exactly like `unit`, `address`, `subject`, and `timestamp` are handled elsewhere in the same function, e.g.:
```
sqlValues.push([unit, address, subject, value, timestamp]);
await conn.query("INSERT INTO numerical_votes (unit, address, subject, value, timestamp) VALUES (?,?,?,?,?)", [unit, address, subject, value, timestamp]);
```
(or continue batching but call `db.escape(value)` after asserting `typeof value === 'number' && Number.isFinite(value)`). Defense-in-depth here removes reliance on upstream validation code remaining correct forever.

## Proof of Concept
Not independently verified end-to-end (would require confirming the exact `system_vote.value` validation rules in `validation.js`, which I could not fully retrieve). Conceptually: post a unit whose `authors[].address` triggers a `system_vote` message such as `{subject: "tps_interval", value: "1, (SELECT ...))-- "}` (or an equivalent string that survives whatever validation is applied to numerical-vote values) and wait for the unit to stabilize; observe the SQL executed in `saveSystemVote` at `main_chain.js:1644-1645` to confirm the un-escaped `value` is embedded verbatim in the executed `INSERT INTO numerical_votes` statement.

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
