### Title
`asset[...].is_issued` getter can report an asset as "issued" based on an unrelated/unstable AA response due to an operator‑precedence flaw in its SQL query - (File: formula/evaluation.js)

### Summary
The oscript built‑in `asset[<asset>].is_issued` getter, used by AA (Autonomous Agent) authors to check whether an asset has already been issued (analogous to the reported `isBuyed` pattern of exposing a derived "state" flag that downstream logic trusts for gating), computes its result using a SQL query whose `WHERE` clause has an operator‑precedence bug: `AND (main_chain_index<=? AND is_stable=1 AND sequence='good' OR is_aa_response=1)` is parsed as `AND ((main_chain_index<=? AND is_stable=1 AND sequence='good') OR is_aa_response=1)`. As a result, when called inside an AA (`bAA` true), *any* row with `is_aa_response=1` satisfies the whole condition — regardless of whether it is stable, confirmed, or even `sequence='good'` — as long as it is a `type='issue'` input for the matching asset.

### Finding Description
`asset[...].is_issued` is implemented in [1](#0-0) :
```
if (field !== 'is_issued')
    return cb(!!objAsset[field]);
if (objAsset.is_private)
    return cb(false); // not issued if private
conn.query("SELECT 1 FROM inputs CROSS JOIN units USING(unit) WHERE type='issue' AND asset=? AND (main_chain_index<=? AND is_stable=1 AND sequence='good' " + (bAA ? "OR is_aa_response=1" : "") + ") LIMIT 1", [asset, mci], function(rows){
    cb(rows.length > 0);
});
```
The intent (mirrored elsewhere, e.g. the correctly-parenthesized confirmation-condition builders in [2](#0-1)  and [3](#0-2) , which always wrap the "OR" alternative in its own parentheses) is presumably: "the issue is confirmed stable, OR it was produced by this same AA-trigger chain and therefore already deterministically known." Instead, because the `OR is_aa_response=1` clause is not separately parenthesized against the `main_chain_index<=? AND is_stable=1 AND sequence='good'` group, `is_aa_response=1` alone (for the matching `type='issue' AND asset=?` row) is sufficient to mark the asset as issued — with no requirement that the response be part of the current AA's own causal chain, be stable, or even have `sequence='good'`.

This state getter is analogous to the reported `isBuyed`/`remainingAmount` bug: a helper meant to reflect the true, current asset-issuance state (used by AA authors to gate "first issue only" logic, e.g. `if (!asset[$my_asset].is_issued) { issue... } else { ... }`) returns a value based on a broader/looser condition than what the actual issuance/consensus rules enforce, producing a mismatch between the reported state and reality.

### Impact Explanation
An AA author relying on `asset[X].is_issued` to gate a "only issue once"/"initial supply" branch of oscript logic can be misled:
- The getter can return `true` even though the matching issue input belongs to a `sequence != 'good'` (i.e., invalid/reverted) unit or to an unrelated/unstable AA response elsewhere in the DAG, meaning the asset was never actually validly issued from the consensus's point of view. An AA that trusts `is_issued === true` to skip its issuance path would then never issue the asset it was designed to issue, permanently freezing that logic path (AA fund/asset freezing / stuck state).
- Because the check only requires `is_aa_response=1` (not "is_stable=1", not "sequence='good'", not restricted to the calling AA's own chain), the result can also become non-deterministic between validating nodes over time (a temporarily final-bad or not-yet-final unit could later be resolved differently), risking node disagreement about the getter's return value if that value feeds into bounce/response logic across the trigger's validation.

### Likelihood Explanation
The condition is reachable by any AA (or any oscript caller) evaluating `asset[<any_asset>].is_issued` for a capped/non-private asset it has already attempted to issue via a self- or externally-triggered response chain — this is a normal, unprivileged usage pattern for AAs that mint assets conditionally (a common pattern, as shown by asset-issuing sample AAs such as `test/samples/create_an_asset.oscript` and `test/aa_composer.test.js`'s "issue recently defined asset" test, which specifically issues assets from within multi-hop AA response chains and reads `asset[...].cap`/related fields). The precedence bug is triggered automatically by the presence of any prior `issue` input in any `is_aa_response=1` unit for that asset, without an attacker needing to do anything unusual.

### Recommendation
Fix the SQL so the intended condition is explicitly grouped:
```
"... AND ((main_chain_index<=? AND is_stable=1 AND sequence='good')" + (bAA ? " OR is_aa_response=1" : "") + ") LIMIT 1"
```
Additionally, restrict the `is_aa_response=1` shortcut to same-primary-trigger-chain response units only (as is done for `objValidationState.arrPreviousAAResponses` lookups elsewhere, e.g. [4](#0-3) ), rather than any AA response unit in the whole DAG, and exclude `sequence != 'good'` rows even in the `is_aa_response` branch.

### Proof of Concept
1. Deploy an AA that issues a capped asset `X` from a secondary/bounced response chain, as in [5](#0-4)  (define asset → send bytes to bouncer AA → bouncer reflects → issue asset).
2. Ensure the resulting `type='issue'` input ends up in a unit with `is_aa_response=1` but with `sequence` other than `'good'` (e.g., it loses a double-spend race, or its MC state has not yet stabilized).
3. Have any AA (or the same AA on a later trigger) evaluate `asset[X].is_issued`.
4. Observe that the query in [6](#0-5)  returns `true` (row found) solely because of `is_aa_response=1`, even though `main_chain_index<=mci AND is_stable=1 AND sequence='good'` is false — i.e., the asset is reported as issued while no valid, confirmed issuance actually exists, causing any AA logic gated on this getter to skip its intended "issue" branch permanently.

### Citations

**File:** formula/evaluation.js (L1561-1567)
```javascript
							if (field !== 'is_issued')
								return cb(!!objAsset[field]);
							if (objAsset.is_private)
								return cb(false); // not issued if private
							conn.query("SELECT 1 FROM inputs CROSS JOIN units USING(unit) WHERE type='issue' AND asset=? AND (main_chain_index<=? AND is_stable=1 AND sequence='good' " + (bAA ? "OR is_aa_response=1" : "") + ") LIMIT 1", [asset, mci], function(rows){
								cb(rows.length > 0);
							});
```

**File:** formula/evaluation.js (L1581-1591)
```javascript
					if (bAA) {
						// 1. check the current response unit
						if (objResponseUnit && objResponseUnit.unit === unit)
							return cb(new wrappedObject(string_utils.cloneDeep(objResponseUnit)));
						// 2. check previous response units from the same primary trigger, they are not in the db yet
						for (var i = 0; i < objValidationState.arrPreviousAAResponses.length; i++) {
							var objPreviousResponseUnit = objValidationState.arrPreviousAAResponses[i].unit_obj;
							if (objPreviousResponseUnit && objPreviousResponseUnit.unit === unit)
								return cb(new wrappedObject(string_utils.cloneDeep(objPreviousResponseUnit)));
						}
					}
```

**File:** inputs.js (L52-66)
```javascript
	var confirmation_condition;
	if (spend_unconfirmed === 'none')
		confirmation_condition = 'AND main_chain_index<='+last_ball_mci+' AND is_stable=1';
	else if (spend_unconfirmed === 'all')
		confirmation_condition = '';
	else if (spend_unconfirmed === 'own')
		confirmation_condition = 'AND ( main_chain_index<='+last_ball_mci+' AND is_stable=1 OR EXISTS ( \n\
			SELECT 1 FROM unit_authors CROSS JOIN my_addresses USING(address) WHERE unit_authors.unit=outputs.unit \n\
			UNION \n\
			SELECT 1 FROM unit_authors CROSS JOIN shared_addresses ON address=shared_address WHERE unit_authors.unit=outputs.unit \n\
			UNION \n\
			SELECT 1 FROM unit_authors WHERE unit_authors.unit=outputs.unit AND unit_authors.address IN(' + arrAddresses.map(conn.escape).join(', ') + ')\n\
		) )';
	else
		throw Error("invalid spend_unconfirmed="+spend_unconfirmed);
```

**File:** indivisible_asset.js (L406-418)
```javascript
		var confirmation_condition;
		if (spend_unconfirmed === 'none')
			confirmation_condition = 'AND main_chain_index<='+last_ball_mci+' AND +is_serial=1 AND is_stable=1';
		else if (spend_unconfirmed === 'all')
			confirmation_condition = '';
		else if (spend_unconfirmed === 'own')
			confirmation_condition = 'AND ( main_chain_index<='+last_ball_mci+' AND +is_serial=1 AND is_stable=1 OR EXISTS ( \n\
				SELECT 1 FROM unit_authors CROSS JOIN my_addresses USING(address) WHERE unit_authors.unit=outputs.unit \n\
				UNION \n\
				SELECT 1 FROM unit_authors CROSS JOIN shared_addresses ON address=shared_address WHERE unit_authors.unit=outputs.unit \n\
			) )';
		else
			throw Error("invalid spend_unconfirmed="+spend_unconfirmed);
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
