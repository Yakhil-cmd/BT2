### Title
Capped asset can be issued more than once via AA-to-AA reentrant trigger chain, bypassing the "already issued" check - (File: aa_composer.js)

### Summary
The reported Backd bug shows that an ERC777 token's `tokensToSend` hook lets a depositor re-enter `depositFor` before the pool's running total is updated, so the `depositCap` check is evaluated against stale state and can be bypassed. In `ocore`, Autonomous Agents (AAs) have an analogous "check the DB, then act" pattern when issuing a capped asset: `issueAsset()` in `aa_composer.js` decides whether an asset with a `cap` has "already issued" by querying `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` [1](#0-0) . This query only sees `issue` inputs that have actually been persisted to the `inputs` table (written later by the unit writer), not issuances that are merely in-flight inside the current AA-response chain being composed.

### Finding Description
AAs can call each other synchronously in a single trigger-processing transaction: a primary trigger is handled inside one `BEGIN...COMMIT` block [2](#0-1) , and any AA that receives payment output from a response unit is immediately re-triggered as a "secondary trigger" from within `handleSecondaryTriggers`, which recursively calls `handleTrigger` before the outer transaction commits [3](#0-2) . This is exactly the pattern demonstrated in `test/aa_composer.test.js`'s "issue recently defined asset" test, where AA A defines an asset, sends bytes to a "bouncer" AA B, B immediately reflects the bytes back to A as a secondary trigger, and A then issues the asset in response to that secondary call [4](#0-3) .

The capped-asset issuance guard in `issueAsset()` relies solely on a `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` check against the database [1](#0-0) . The `addIssueInput` callback that "records" the issuance only pushes the `issue` input into the in-memory `payload.inputs` array of the unit currently being composed [5](#0-4) ; it is not written into the `inputs` table until the composed unit is actually saved by the writer. If an AA can be re-entered (via a secondary-trigger chain that loops back to the same AA, or via multiple independent trigger paths converging on the same AA within one primary-trigger transaction) before its previously-composed `issue` unit is persisted, the second `issueAsset()` call's `SELECT 1 FROM inputs ...` check will not see the first issuance and will incorrectly conclude the capped asset has not yet been issued, allowing `addIssueInput` to run a second time and mint the capped supply twice.

This mirrors the root cause of the ERC777 finding: a state-changing action is preceded by a read-only guard against not-yet-updated persistent state, and control flow can loop back into the guarded function before the first action's effect is committed.

### Impact Explanation
A double issuance of a nominally capped asset is a supply-inflation bug: the asset's `cap` invariant (enforced elsewhere in unit validation only against `serial_number=1` for the *unit-level* issue input, not against cross-unit double issuance from the same AA logic path) would be violated at the application/AA level, since the AA's own code — not consensus validation — is what is supposed to prevent it from issuing more than once. Downstream holders and any code (including other AAs) that assume `cap` represents the true maximum circulating supply of the asset would be misled, and asset value assumptions used in DeFi-style AAs built on top of ocore could be broken.

### Likelihood Explanation
Exploitability depends on being able to force a capped-asset-issuing AA to be reentered as a secondary trigger before the transaction that recorded its first issuance is committed — a pattern the project's own test suite already exercises for legitimate purposes ("issue recently defined asset" test uses a bouncer AA to loop back into the same AA within one primary trigger) [4](#0-3) . This makes the reentrant-call topology realistic and reachable by an ordinary AA author, without needing any privileged role, and is directly analogous to the "posted unit/AA trigger sender" reachability class.

### Recommendation
Enforce the "already issued" guard for capped assets against in-memory/transaction-scoped state (e.g., a per-transaction set of assets issued so far in the current trigger-handling transaction, checked in addition to the DB query), not only against already-committed `inputs` rows, so that a capped asset cannot be issued more than once within a single chain of AA-to-AA triggers before commit.

### Proof of Concept
1. Define AA `asset_aa` whose `messages` (per the existing test) define a capped asset (`cap: 1e6`) and, in the same or later response, sends part of its balance to a `bouncer_aa`.
2. `bouncer_aa` immediately reflects the payment back to `asset_aa` as a secondary trigger within the same primary-trigger transaction, as shown in the "issue recently defined asset" test [6](#0-5) .
3. Craft `asset_aa`'s logic so that the branch handling the secondary bounce-back trigger issues the capped asset via an `asset` payment output using `issueAsset()`'s cap path [1](#0-0) , and arrange for a further loop (e.g., a second bouncer or additional secondary hop) causing the same AA to reach the issuing branch a second time before the outer `COMMIT` in `handlePrimaryAATrigger` runs [2](#0-1) .
4. Because the `SELECT 1 FROM inputs WHERE type='issue' AND asset=?` check only reflects committed `inputs` rows, the second pass does not see the first (uncommitted) issuance and mints the capped asset a second time, exceeding the declared `cap`.

### Citations

**File:** aa_composer.js (L92-116)
```javascript
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = kvstore.batch();
			readMcUnit(conn, mci, function (objMcUnit) {
				readUnit(conn, unit, function (objUnit) {
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
							var batch_start_time = Date.now();
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
								conn.query("COMMIT", function () {
									conn.release();
```

**File:** aa_composer.js (L1181-1193)
```javascript
				function addIssueInput(serial_number){
					var input = {
						type: "issue",
						amount: issue_amount,
						serial_number: serial_number
					};
					payload.inputs.unshift(input);
					total_amount += issue_amount;
					var change_amount = total_amount - target_amount;
					if (change_amount > 0)
						payload.outputs.push({ address: address, amount: change_amount });
					cb2();
				}
```

**File:** aa_composer.js (L1195-1201)
```javascript
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
				}
```

**File:** aa_composer.js (L1702-1741)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
```

**File:** test/aa_composer.test.js (L450-526)
```javascript
test.cb.serial('issue recently defined asset', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { define: true }, address: trigger_address };

	// a chain of 3 AA responses
	// 1. define asset, save var['asset'] state var, and send bytes to bouncer AA
	// 2. bouncer reflects the bytes back
	// 3. the 1st AA acts again, it reads the state var and issues the asset

	var bouncer_aa = ['autonomous agent', {
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 1000}"}
					]
				}
			},
		]
	}];
	var bouncer_address = objectHash.getChash160(bouncer_aa);
	addAA(bouncer_aa);

	var asset_aa = ['autonomous agent', {
		messages: {
			cases: [
				{
					if: "{trigger.data.define}",
					messages: [
						{
							app: 'asset',
							payload: {
								cap: 1e6,
								is_private: false,
								is_transferrable: true,
								auto_destroy: false,
								fixed_denominations: false,
								issued_by_definer_only: true,
								cosigned_by_definer: false,
								spender_attested: false,
							}
						},
						{
							app: 'payment',
							payload: {
								asset: 'base',
								outputs: [
									{address: bouncer_address, amount: "{trigger.output[[asset=base]] - 1000}"}
								]
							}
						},
						{
							app: 'state',
							state: `{
								var['asset'] = response_unit;
							}`
						}
					]
				},
				{
					if: `{trigger.address == '${bouncer_address}' AND var['asset']}`,
					messages: [{
						app: 'payment',
						payload: {
							asset: "{var['asset']}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{asset[var['asset']].cap}"}
							]
						}
					}]
				},
			]
		}
	}];
	var asset_address = objectHash.getChash160(asset_aa);
```
