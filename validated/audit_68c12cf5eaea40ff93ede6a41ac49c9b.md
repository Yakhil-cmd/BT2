## Title
Unhandled exception in `definition template` evaluation crashes any node validating a unit signed with a stale/invalid template reference - (File: definition.js)

## Summary
`libyang`'s `read_yin_container()` bug (CVE‑2021‑28902) crashes the process because it assumes an internal array slot (`retval->ext[r]`) is always populated and dereferences it without a NULL check. `ocore`'s address-definition evaluator has the same class of bug: it assumes a SQL lookup for a `definition_template` message always returns **exactly one row**, and instead of handling the "not found" case gracefully it `throw`s an uncaught `Error`, crashing the whole Node.js process.

## Finding Description
When an address is defined (or partially defined) using the `definition template` operator, `Definition.validateAuthentifiers()` resolves the referenced template with a plain SQL query and hard-asserts the row count: [1](#0-0) 

```js
case 'definition template':
    // ['definition template', ['unit', {param1: 'value1'}]]
    var unit = args[0];
    var params = args[1];
    conn.query(
        "SELECT payload FROM messages JOIN units USING(unit) \n\
        WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
        [unit, objValidationState.last_ball_mci],
        function(rows){
            if (rows.length !== 1)
                throw Error("not 1 template");
            var template = rows[0].payload;
            ...
```

`rows.length !== 1` is treated as an "impossible" invariant and handled with `throw Error(...)` instead of returning a validation error through `cb2`. This function is invoked from `validateAuthentifiers()`, which is called directly (not inside a caller-supplied try/catch boundary that turns thrown errors into unit-validation failures) from `validateAuthor()` in `validation.js` whenever a unit is signed by an address whose bound definition contains a `definition template` node: [2](#0-1) 

Because an address's definition is permanently bound to the address (verified via `chash160`), a malicious actor can register an address whose definition references a `definition template` unit that:
- does not exist,
- is not yet stable at the referencing unit's `last_ball_mci`, or
- was on a non-good sequence,

any of which makes the query return zero rows. Every full node (and light-serving node) that later validates *any* unit signed by that pre-registered address will hit `rows.length !== 1` and crash with an uncaught exception, since the `conn.query` callback executes asynchronously outside the `try { ... } catch` blocks used elsewhere in this codebase for similar operations (e.g. the `sig`/`hash` cases guard with `fatal_error`/`cb2(false)` instead of throwing).

## Impact Explanation
An uncaught exception thrown from inside an async DB callback in Node.js terminates the process (no calling stack frame catches it). Any full node — hub, witness, or ordinary node — that processes a unit signed by an address using this `definition template` pattern will crash, matching "a network unable to confirm new units" if enough validating nodes hit the same poisoned unit. This is a direct analog of the libyang bug: an assumed-always-non-null/always-exactly-one value is dereferenced/used without a defensive check, and the flaw is reachable purely by posting ordinary application data (units signed by a crafted address definition) — no special network position or leaked key is required.

## Likelihood Explanation
Reaching this code path requires only:
1. Registering an address whose definition includes `['definition template', [<bogus_or_stale_unit>, {...}]]` (the c-hash of any such array can be pre-computed off-chain and does not require the referenced unit to exist at registration time).
2. Signing and posting any ordinary unit from that address.

Both actions are available to any unprivileged unit poster; no elevated network role, hub cooperation, or private key compromise of another party is needed. The trigger condition (`rows.length !== 1`) is easy to guarantee deterministically by choosing a unit id that is guaranteed not to satisfy the filter (e.g., an unrelated/non-`definition_template` unit, or a template unit that will never become stable before the referencing unit's last ball).

## Recommendation
Replace the `throw Error("not 1 template")` invariant with a graceful validation failure returned through the callback chain (`cb2(false)` / propagate an error string), consistent with how other operators in the same `evaluate()` switch (`sig`, `hash`, `address`) handle unexpected or missing data. Additionally, wrap the `definition template` DB-lookup callback (and any other `throw`-based invariant checks reachable from unit validation) in try/catch, or convert them to return validation errors, so that malformed/stale references cannot crash the validating process.

## Proof of Concept
1. Create definition `D = ['definition template', ['ANY_UNSTABLE_OR_NONEXISTENT_UNIT', {}]]` and derive `addr = chash160(D)`.
2. Post a unit that defines address `addr` with `D` as its definition (via a normal `author.definition` in a first spend), matching `chash160(D) === addr`.
3. From `addr`, sign and broadcast any subsequent unit.
4. When any node validates that subsequent unit, `validateAuthor` → `validateAuthentifiers` → the `definition template` case executes the SQL query, gets `rows.length !== 1` (0 rows, since the referenced unit is not a stable `definition_template` message), and `throw Error("not 1 template")` crashes the node process. [3](#0-2) 

Note: I was unable to fully confirm within the available context whether `definition template` remains an accepted op inside `validateDefinition()`'s own opcode whitelist for *newly created* definitions in this exact repository revision (the relevant code sections were only partially retrieved). If `validateDefinition` currently rejects `definition template` as an "unknown op" for new definitions, the same crash would still be reachable via any address that was defined with this op prior to such a restriction being introduced (definitions are permanent and re-evaluated on every subsequent spend), but I could not verify the current upgrade/mci gating for this operator with full certainty from the retrieved code.

### Citations

**File:** definition.js (L802-819)
```javascript
			case 'definition template':
				// ['definition template', ['unit', {param1: 'value1'}]]
				var unit = args[0];
				var params = args[1];
				conn.query(
					"SELECT payload FROM messages JOIN units USING(unit) \n\
					WHERE unit=? AND app='definition_template' AND main_chain_index<=? AND +sequence='good' AND is_stable=1",
					[unit, objValidationState.last_ball_mci],
					function(rows){
						if (rows.length !== 1)
							throw Error("not 1 template");
						var template = rows[0].payload;
						var arrTemplate = JSON.parse(template);
						var arrFilledTemplate = replaceInTemplate(arrTemplate, params);
						evaluate(arrFilledTemplate, path, cb2);
					}
				);
				break;
```

**File:** validation.js (L1190-1208)
```javascript
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){
				storage.readAADefinition(conn, objAuthor.address, objValidationState.last_ball_mci, function (arrAADefinition) {
					if (arrAADefinition)
						return callback(createTransientError("will not validate unit signed by AA"));
					if (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci)
						return callback("definition " + definition_chash + " bound to address " + objAuthor.address + " not found before last ball");
					findUnstableInitialDefinition(definition_chash, function (arrDefinition) {
						if (!arrDefinition)
							return callback("definition " + definition_chash + " bound to address " + objAuthor.address + " is not defined");
						bInitialDefinition = true;
						validateAuthentifiers(arrDefinition);
					});
				});
			},
			ifFound: function(arrAddressDefinition){
				validateAuthentifiers(arrAddressDefinition);
			}
		});
```
