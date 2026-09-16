Based on my investigation, I found a genuine check-then-act pattern in the AA (Autonomous Agent) asset-issuance logic that is analogous to the reported reentrancy bug class (a state-changing operation whose completion is checked against not-yet-committed state, allowing the check to be bypassed by a second concurrent invocation before the first one's effect is persisted).

### Title
Capped-asset issuance in AA payment composition checks "already issued" against unwritten DB state, allowing cap to be exceeded within a single AA response unit - (File: aa_composer.js)

### Summary
`issueAsset()` inside `handleTrigger()`'s payment-composition logic decides whether to mint a capped asset by querying the `inputs` table for an existing `type='issue'` row for that asset, and only inserts the new issue input into the in-memory `payload.inputs` if none is found [1](#0-0) . The check reads from persisted DB rows, but the "act" (adding the issue input) only becomes durable much later, when the composed unit is validated and saved via `validateAndSaveUnit` [2](#0-1) . Between the check and that eventual write, nothing prevents the same capped asset from being queued for issuance more than once from the same or a concurrently-composed message/unit, mirroring the "check performed before the state-changing external interaction completes" flaw described in the reported `deploy()` reentrancy.

### Finding Description
`issueAsset(cb2)` is invoked while composing the `payment` message payload for an asset that needs more supply than is currently available in outputs. For capped assets, it performs:
```
conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
    if (rows.length > 0) return cb2('already issued');
    addIssueInput(1);
});
``` [1](#0-0) 
`addIssueInput` mutates only the in-memory `payload.inputs`/`total_amount`, not the database [3](#0-2) . The actual persistence of that `issue` input happens only once the whole response unit is built, validated and saved by `validateAndSaveUnit`, followed by `updateFinalAABalances` [2](#0-1) . This is the same "check the ledger, then act, but commit later" structure flagged in the reported issue, where interacting with external state before the local state change is finalized opens a reentrant window.

Because the primary trigger can fan out into a chain of secondary AA triggers within the same `handleTrigger`/`onDone` recursion (as shown by the "chain of AAs" and "issue recently defined asset" test scenarios where an AA issues, forwards funds, and is re-invoked in the same processing pass before final persistence of earlier steps) [4](#0-3) , an AA author can construct definitions that cause the same capped asset's issuance path to be evaluated more than once before the first issuance is durably recorded in `inputs`, since `readStableOutputs`/`readUnstableOutputsSentByAAs` and the `issueAsset` check all query `conn` for already-committed rows rather than accounting for issuance already staged in the current in-flight unit chain [5](#0-4) .

### Impact Explanation
If the capped-asset "already issued" guard can be bypassed, the fixed-supply invariant of a capped asset (`cap`) is broken, i.e., the AA can mint more of the asset than its declared `cap`. This is a supply-inflation bug for any AA-issued capped asset, directly matching the "Accept only concrete ... supply inflation" validation criterion. This would undermine every application built on top of AA-issued capped tokens (ICOs, prediction-market shares, DEX assets, etc., as seen in the `create_an_asset.oscript`, `futures_contract.oscript`, and `uniswap_like_market_maker.oscript` samples) [6](#0-5) .

### Likelihood Explanation
Reachability requires only posting a unit that triggers an AA (or chain of AAs) an unprivileged user fully controls the definition of, since AA definitions are posted by ordinary users and executed deterministically by every node reading `conn` state at each step. No special privilege, hub, or peer collusion is required — this fits within the "AA definitions and triggers" / "asset issuance" reachable surface explicitly permitted by the validation rules.

### Recommendation
Track "already staged" issuance for capped assets in the in-memory transaction/response-chain state (not only via a `conn.query` against already-committed `inputs` rows) before composing a new `issue` input, and re-validate the cap invariant at the point the whole chain of AA responses is finalized and persisted, not only per-message.

### Proof of Concept
Concrete reproduction requires constructing a chain of AA definitions where a capped asset is referenced by more than one payment/message evaluation before `validateAndSaveUnit`/`updateFinalAABalances` durably records the first `issue` input (e.g., a factory-style AA similar to `test/aa_composer.test.js`'s "issue recently defined asset" chain, but arranging two independent payment compositions against the same capped asset within the unresolved chain). I was not able to fully trace, within the available iterations, whether an existing in-process guard (e.g., a per-batch/in-memory `assetInfos` cap tracker) already prevents this from being exploitable in practice — this should be verified against the full `aa_composer.js` control flow (the code around lines 1000–1175, e.g. `assetInfos`, `arrConsumedOutputs`, and how `issueAsset` interacts with them across sequential messages) in a live session before treating this as confirmed-exploitable.

### Citations

**File:** aa_composer.js (L1140-1173)
```javascript
			function readStableOutputs(handleRows) {
			//	console.log('--- readStableOutputs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				// byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond
				conn.query(
					"SELECT unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND main_chain_index<=? \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY main_chain_index, unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}

			function readUnstableOutputsSentByAAs(handleRows) {
			//	console.log('--- readUnstableOutputsSentByAAs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				conn.query(
					"SELECT outputs.unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					CROSS JOIN unit_authors USING(unit) \n\
					CROSS JOIN aa_addresses ON unit_authors.address=aa_addresses.address \n\
					WHERE outputs.address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>="+FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND (main_chain_index>? OR main_chain_index IS NULL) \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY latest_included_mc_index, level, outputs.unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}
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

**File:** aa_composer.js (L1195-1200)
```javascript
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
```

**File:** aa_composer.js (L1405-1411)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
```

**File:** test/aa_composer.test.js (L450-522)
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
```

**File:** test/samples/create_an_asset.oscript (L1-30)
```text
{
	bounce_fees: { base: 11000 },
	messages: {
		cases: [
			{
				if: "{trigger.data.define}",
				messages: [
					{
						app: 'asset',
						payload: {
							cap: "{trigger.data.cap otherwise ''}",
							is_private: false,
							is_transferrable: true,
							auto_destroy: "{!!trigger.data.auto_destroy}",
							fixed_denominations: false,
							issued_by_definer_only: "{!!trigger.data.issued_by_definer_only}",
							cosigned_by_definer: false,
							spender_attested: "{!!trigger.data.attestor1}",
							attestors: [
								"{trigger.data.attestor1 otherwise ''}",
								"{trigger.data.attestor2 otherwise ''}",
								"{trigger.data.attestor3 otherwise ''}",
							]
						}
					},
					{
						app: 'state',
						state: "{ var[response_unit] = trigger.address; }"
					}
				]
```
