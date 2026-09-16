## Analog Found

### Title
Unprivileged unit authors can pre-define an AA at an address a factory AA expects to own, front-running/DoS-ing AA-factory patterns - (File: `validation.js`, `storage.js`)

### Summary
The Mochi bug allowed anyone to call `MochiVaultFactory.deployVault()` directly and pre-occupy a deterministic vault address, so that when the legitimate, permissioned caller (`engine`) later tried to deploy the same vault, the deployment reverted, yet the protocol still recognized the address as a "valid vault" because validity is checked purely by comparing against the deterministically computed address, not by who deployed it. The same root cause — permission-free creation of an object whose identity/address is fully content-derived, combined with a "first writer wins" acceptance rule — exists in ocore's `app: "definition"` message, which defines Autonomous Agents (AAs) at an address equal to `chash160(definition)`.

### Finding Description
The `definition` message type is documented as being "for AAs only" but the code does not actually restrict it to AA-response context. In `validateMessage`/`validateInlinePayload`, the only app-specific gating that applies is: [1](#0-0) 
which only forces `definition` to be inline, and, *if* `objValidationState.bAA` is true (i.e., the unit is an AA response), restricts the set of allowed apps via `aaApps`. There is no corresponding check that forbids a plain, unprivileged unit author (`objValidationState.bAA === false`) from including an `app: "definition"` message. The actual validation of the message content is only: [2](#0-1) 
i.e., it only requires that `payload.address === chash160(payload.definition)` — a self-consistency check, not an authorization check. Anyone who can construct a valid `arrDefinition` (including one that a *different* AA's `init` formula would also construct deterministically, e.g. via `chash160($child_aa)`, as demonstrated in the "factory AA" test) can post it first from a regular unit.

Acceptance of these definitions is "first writer wins", exactly like Mochi's CREATE2 collision: [3](#0-2) 
`INSERT IGNORE INTO aa_addresses (address, ...)` uses `address` as PRIMARY KEY (see schema below); if the address already exists from an earlier unit, the row is silently dropped and the log states "ignoring repeated definition of AA ... in another unit", even though the true logical owner (e.g. a factory AA's own trigger-chain response) expected to be the one defining it. [4](#0-3) 

This mirrors the pattern shown in the test that models a legitimate on-chain "factory": a parent AA computes a child AA's address deterministically off-chain-visible logic (`chash160($child_aa)`) and then, in the *same* trigger-response chain, posts the `definition` message and forwards funds to that address: [5](#0-4) 

Because the child AA's bytecode/template is fully knowable from the parent AA's public definition (all AA definitions are public on the DAG), an unprivileged unit author can compute the same `arrDefinition`/address and submit their own `app: "definition"` unit first — exactly as the Mochi attacker called `deployVault()` directly instead of going through `engine`.

### Impact Explanation
When the attacker's unit wins the race:
- The legitimate factory AA's own `definition` message for that address is ignored ("ignoring repeated definition of AA ... in another unit"), per `storage.js:922-936`, meaning the resulting on-chain child-AA "owner" is not the factory-triggered unit the higher-level protocol logic assumed.
- The factory AA's subsequent payment message still sends funds to the (now attacker-first-defined) address, exactly as in the Mochi PoC where `registerAssetByGov` still trusted the address computed by the factory even though it wasn't deployed through `engine`.
- Downstream state bookkeeping in the factory AA (e.g., `var['new_aa'] = unit[response_unit].messages[[.app='definition']].payload.address`) can diverge from the actual first-definition unit, or funds sent to the address may be received by an AA whose "official" deployment never went through, disrupting the intended workflow, freezing/misdirecting AA funds, and creating a governance/DoS situation for any protocol relying on the factory pattern to reliably self-register at predictable addresses.
- This is classified Medium severity, consistent with the original finding's confirmed-but-medium status, since it requires the target factory AA design to rely on this deterministic-address self-registration pattern (an established, documented ocore pattern per the test suite) but does not require any privileged access to trigger.

### Likelihood Explanation
Likelihood is Medium: exploitation requires (1) a widely-used AA factory pattern that defines child AAs deterministically and forwards funds in the same response chain (a pattern explicitly supported and tested in ocore, see `test/aa_composer.test.js:922-1010`), and (2) an attacker able to read the parent AA's public source (always true on Obyte, since AA code is public) and race a `definition`-carrying unit ahead of the factory's own response unit. No special privileges, keys, or protocol roles are needed — any unit poster can do this, matching the "anyone can call the factory directly" pattern in the original report.

### Recommendation
Restrict the `app: "definition"` message so that it can only be included by AA-response units (`objValidationState.bAA === true`), i.e. move the "for AAs only" comment into an enforced check, rejecting `definition` messages from ordinary (non-AA) unit authors:
```js
case "definition":
    if (!objValidationState.bAA)
        return callback("definition message allowed only in AA responses");
    ...
```
Additionally, consider having `insertAADefinitions` treat a collision from a non-matching unit as a hard validation error for the AA response that intended to own that address (bounce/fail the trigger) rather than silently ignoring it, so that a factory AA can detect and safely react to front-running instead of proceeding with stale assumptions.

### Proof of Concept
1. Observe a public factory AA definition (e.g. the `factory_aa` pattern in `test/aa_composer.test.js:944-986`) whose `init` formula deterministically builds `$child_aa` and computes `$child_aa_address = chash160($child_aa)`.
2. Compute the identical `arrDefinition` off-chain and its `chash160`.
3. As an ordinary wallet (non-AA), post a unit containing `{ app: "definition", payload: { address: <computed_address>, definition: <arrDefinition> } }` before the factory AA's trigger executes.
4. Because `validateMessage`/`validateInlinePayload` does not require `objValidationState.bAA` for the `definition` app (`validation.js:1620-1629`, `1747-1758`), this unit validates and is accepted.
5. When the factory AA later executes and tries to define the same address, `storage.js:921-936` logs `"ignoring repeated definition of AA ... in another unit"` and skips re-insertion, while the factory's payment message still forwards funds to that (attacker-preempted) address — reproducing the "recognized as valid despite bypassing the intended privileged/deterministic-owner flow" impact of the original Mochi finding.

### Citations

**File:** validation.js (L1620-1629)
```javascript
	var arrInlineOnlyApps = ["address_definition_change", "data_feed", "definition_template", "asset", "asset_attestors", "attestation", "poll", "vote", "definition", "system_vote", "system_vote_count", "temp_data"];
	if (arrInlineOnlyApps.indexOf(objMessage.app) >= 0 && objMessage.payload_location !== "inline")
		return callback(objMessage.app+" must be inline");

	if (objValidationState.bAA) {
		if (!aa_validation.aaApps.includes(objMessage.app))
			return callback("unsupported app in AA response: " + objMessage.app);
		if (objMessage.payload_location !== "inline")
			return callback("AA response must be inline");
	}
```

**File:** validation.js (L1747-1758)
```javascript
		case "definition": // for AAs only
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["address", "definition"])) // AA definition cannot be changed and its address is also its definition_chash
				return callback("unknown fields in app definition");
			try{
				if (payload.address !== objectHash.getChash160(payload.definition))
					return callback("definition doesn't match the chash");
			}
			catch(e){
				return callback("bad definition");
			}
```

**File:** storage.js (L904-940)
```javascript
function insertAADefinitions(conn, arrPayloads, unit, mci, validation_mci, bForAAsOnly, onDone, bDryRun) {
	if (!onDone)
		return new Promise(resolve => insertAADefinitions(conn, arrPayloads, unit, mci, validation_mci, bForAAsOnly, resolve, bDryRun));
	var aa_validation = require("./aa_validation.js");
	async.eachSeries(
		arrPayloads,
		function (payload, cb) {
			var address = payload.address;
			var json = JSON.stringify(payload.definition);
			var base_aa = payload.definition[1].base_aa;
			var bAlreadyPostedByUnconfirmedAA = false;
			var readGetterProps = function (aa_address, func_name, cb) {
				if (conf.bLight)
					return cb({ complexity: 0, count_ops: 0, count_args: null });
				readAAGetterProps(conn, aa_address, func_name, mci, cb);
			};
			aa_validation.determineGetterProps(payload.definition, readGetterProps, validation_mci, function (getters) {
				conn.query("INSERT " + db.getIgnore() + " INTO aa_addresses (address, definition, unit, mci, base_aa, getters) VALUES (?,?, ?,?, ?,?)", [address, json, unit, mci, base_aa, getters ? JSON.stringify(getters) : null], async function (res) {
					if (res.affectedRows === 0) { // already exists
						if (bForAAsOnly){
							console.log("ignoring repeated definition of AA " + address + " in AA unit " + unit);
							return cb();
						}
						var old_payloads = getUnconfirmedAADefinitionsPostedByAAs([address]);
						if (old_payloads.length === 0) {
							console.log("ignoring repeated definition of AA " + address + " in unit " + unit);
							return cb();
						}
						const [{ unit: prev_unit }] = await conn.query("SELECT unit FROM aa_addresses WHERE address=?", [address]);
						if (prev_unit !== unit) {
							console.log(`ignoring repeated definition of AA ${address} in another unit ${unit}, first definition unit ${prev_unit}`);
							return cb();
						}
						// we need to recalc the balances to reflect the payments received from non-AAs between definition and stabilization
						bAlreadyPostedByUnconfirmedAA = true;
						console.log("will recalc balances after repeated definition of AA " + address + " in unit " + unit);
					}
```

**File:** initial-db/byteball-sqlite.sql (L812-822)
```sql
CREATE TABLE aa_addresses (
	address CHAR(32) NOT NULL PRIMARY KEY,
	unit CHAR(44) NOT NULL, -- where it is first defined.  No index for better speed
	mci INT NOT NULL, -- it is available since this mci (mci of the above unit)
	base_aa CHAR(32) NULL,
	storage_size INT NOT NULL DEFAULT 0,
	definition TEXT NOT NULL,
	getters TEXT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT aaAddressesByBaseAA FOREIGN KEY (base_aa) REFERENCES aa_addresses(address)
);
```

**File:** test/aa_composer.test.js (L922-986)
```javascript
test.cb.serial('AA with generated definition of new AA and immediately sending to this new AA', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { x: 5 }, address: trigger_address };

	var child_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		doc_url: 'https://myapp.com/description.json',
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					init: "{response['received_amount'] = trigger.output[[asset=base]];}",
					outputs: [
						{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
					]
				}
			}
		]
	}];
	var child_aa_address = objectHash.getChash160(child_aa);
	
	var factory_aa = ['autonomous agent', {
		init: `{
			$child_aa = ['autonomous agent', {
				bounce_fees: { base: 10000 },
				doc_url: 'https://myapp.com/description.json',
				messages: [
					{
						app: 'payment',
						payload: {
							asset: 'base',
							init: "{response['received_amount'] = trigger.output[[asset=base]];}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
							]
						}
					}
				]
			}];
			$child_aa_address = chash160($child_aa);
		}`,
		messages: [
			{
				app: 'definition',
				payload: {
					definition: `{$child_aa}`
				}
			},
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [{address: `{$child_aa_address}`, amount: 8000}]
				}
			},
			{
				app: 'state',
				state: `{
					var['child_aa1'] = $child_aa_address;
					var['child_aa2'] = unit[response_unit].messages[[.app='definition']].payload.address;
				}`
			}
		]
	}];
```
