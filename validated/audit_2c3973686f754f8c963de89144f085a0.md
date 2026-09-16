## Finding: AA-issued `spender_attested` asset can be defined without an initial attestor list, permanently crashing `readAsset` for that asset

### Title
AA can define a `spender_attested` asset without an initial `attestors` list, causing `readAsset` to throw and permanently DoS the asset - (File: aa_validation.js, storage.js)

### Summary
When a regular (non-AA) unit defines an `asset` message with `spender_attested: true`, the human/wallet-authored validation path in `validation.js` enforces that a valid `attestors` list is present at definition time via `checkAttestorList(payload.attestors)` [1](#0-0) . However, the parallel validation path used for **AA-composed** `asset` definitions (`aa_validation.js`, used to validate `definition`-style messages that an autonomous agent posts as part of its response) has no equivalent requirement: `attestors` is only validated *if present* in the payload, and there is no check that forbids `spender_attested: true` combined with a missing `attestors` field [2](#0-1) .

### Finding Description
The `asset` message schema allows `spender_attested: true`, which flags the asset as requiring a currently-published attestor list before it can be spent (see `assets.spender_attested` column comment: "must subsequently publish and update the list of trusted attestors") [3](#0-2) .

For human-authored units, `validateAssetDefinition` in `validation.js` guarantees an attestor list exists at creation time:
```
if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
    return callback(err);
``` [1](#0-0) 

For AA-authored `definition` messages (an AA can post an `asset` payload as one of its response messages, exactly as demonstrated in the test suite) [4](#0-3) , the corresponding validator `validateAADefinition`'s asset-message branch in `aa_validation.js` only validates `attestors` "if `("attestors" in payload)`" — it never requires `attestors` to be present when `spender_attested` evaluates (at execution time, via formula) to `true`:
```
async.series([
    function (cb3) {
        if (!("attestors" in payload))
            return cb3();
        validateFieldWrappedInCases(payload, 'attestors', validateAttestors, cb3);
    },
    ...
``` [5](#0-4) 

Because `spender_attested` in the AA case can itself be a runtime formula string (evaluated against `trigger.data`, balances, etc., not a static boolean) [6](#0-5) , an AA author can construct a response where `spender_attested` resolves to `true` for some trigger inputs while omitting the `attestors` field entirely — this passes AA-definition-time validation because the static check only looks at the field's *type* (boolean/string formula), not its resolved value, and never cross-validates it against the presence of `attestors`.

Once such an asset is written by the AA (via `writer.js`'s handling of the `"asset"` case, which inserts into `assets` and only inserts into `asset_attestors` `if (asset.attestors)`) [7](#0-6) , the asset row in the `assets` table has `spender_attested=1` but no corresponding row exists in `asset_attestors`.

Any subsequent attempt to read/spend this asset — by a real payment, a private-payment counterparty, or another AA — goes through `storage.readAsset`, which for `spender_attested` assets always tries to look up the "latest attestor list":
```
function addAttestorsIfNecessary(byAA = false){
    if (!objAsset.spender_attested)
        return handleAsset(null, objAsset);
    conn.query(
        "SELECT unit FROM asset_attestors CROSS JOIN units USING(unit) WHERE asset=? ... ORDER BY ... LIMIT 1",
        [asset],
        function (latest_rows) {
            if (latest_rows.length === 0)
                throw Error("no latest attestor list");
            ...
``` [8](#0-7) 

Since no `asset_attestors` row was ever written, `latest_rows.length === 0` and the code hits an unconditional `throw Error("no latest attestor list")` — not a callback-style validation error, but a synchronous JS exception inside a DB-callback context. This is unrecoverable via the normal validation error paths (`ifUnitError`, etc.) and will crash/hang the node process (or at minimum abort the whole write/validation flow) for every single node that attempts to validate a payment referencing this asset, forever, since there is no message type in the protocol that can retroactively supply an initial attestor list after such an asset already exists (the `asset_attestors` message can only *add to* an existing definer-controlled list, and requires `objUnit.authors[0].address === objAsset.definer_address` [9](#0-8)  — but since the asset was created by an AA, the AA itself would need to author a signed `asset_attestors` unit, which AAs cannot do outside of a triggered response, and even a subsequent AA response defining `asset_attestors` for the same asset is limited to once per asset per unit and doesn't retroactively fix already-mined payments that already crashed nodes evaluating them).

This mirrors the reported bug class: the entity ("bond market" there / "asset" here) is fully created via one code path, but a second, procedurally-required piece of state (the `conclusion` value there / the attestor list here) can be skipped, and the codebase has no other mechanism to ever set it, permanently disabling correct functioning of the created object.

### Impact Explanation
This is a network-wide denial-of-service / node-crash primitive reachable by any AA author (an unprivileged entity — anyone can deploy an AA and construct arbitrary trigger data to make it emit this malformed `asset` definition). Every full/light node that subsequently tries to validate any payment or read the asset (including inside `validatePayment` → `loadAssetWithListOfAttestedAuthors` → `readAsset`) will hit the unhandled `throw`, causing node crashes or getting stuck, meaning **the network becomes unable to process transactions for that asset** and potentially disrupts the validating node's process entirely (an unhandled throw inside async DB callback code is not typically caught by the ordinary validation error-handling machinery). This satisfies "a network unable to confirm new units" / node disagreement risk from the validation rubric.

### Likelihood Explanation
Likelihood is moderate-to-high: deploying an AA that emits an `asset` message with `spender_attested` resolving to `true` and no `attestors` field requires no special privilege, only posting a normal AA definition and a triggering unit — well within reach of any user. The missing check is a straightforward oversight (the human-path check at `validation.js:2745-2750` is absent in `aa_validation.js`), so it is a deterministic, repeatable trigger, not a probabilistic race condition.

### Recommendation
Add a check in `aa_validation.js`'s asset-message validation (mirroring `validation.js:2745-2750`) that rejects an `asset` payload where `spender_attested` is a literal `true` (or is a formula string, since it can't be statically excluded, consider requiring `attestors` whenever `spender_attested` is not statically `false`) without a syntactically present `attestors` field. At minimum, require `attestors` to be present whenever `spender_attested` is anything other than the literal boolean `false`. Additionally, `storage.js`'s `readAsset`/`addAttestorsIfNecessary` should not use an unconditional `throw` for `"no latest attestor list"` — it should propagate this as a normal validation/read error to the caller so that malformed assets fail gracefully (return an error) instead of throwing an uncatchable exception.

### Proof of Concept
1. Deploy an AA whose response messages include a `definition` message for a new address whose definition is itself an `autonomous agent` with an `asset` message such as:
```
{
  app: 'asset',
  payload: {
     cap: 1000000,
     is_private: false,
     is_transferrable: true,
     auto_destroy: false,
     fixed_denominations: false,
     issued_by_definer_only: true,
     cosigned_by_definer: false,
     spender_attested: "{trigger.data.attest}"   // resolves to true at trigger time
     // no "attestors" field
  }
}
```
2. Trigger the AA with `trigger.data.attest = true`; `aa_validation.validateAADefinition`'s asset branch accepts this because `spender_attested` is a valid formula string and `attestors` is simply absent (skipped check) [10](#0-9) .
3. `writer.js` inserts the `assets` row with `spender_attested=1` and never inserts any `asset_attestors` row since `asset.attestors` is undefined [7](#0-6) .
4. Any later payment referencing this asset calls `storage.readAsset` → `addAttestorsIfNecessary()` → the `asset_attestors` lookup returns zero rows → `throw Error("no latest attestor list")` [8](#0-7) , crashing/aborting validation on every node that processes that payment.

### Citations

**File:** validation.js (L2745-2750)
```javascript
	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");
```

**File:** validation.js (L2829-2848)
```javascript
function validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("attestor list must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("attestor update must be a non-empty object");
	if (hasFieldsExcept(payload, ['asset', 'attestors']))
		return callback("foreign fields in attestor list update");
	storage.readAsset(conn, payload.asset, objValidationState.last_ball_mci, false, function(err, objAsset){
		if (err)
			return callback(err);
		if (!objAsset.spender_attested)
			return callback("this asset does not require attestors");
		if (objUnit.authors[0].address !== objAsset.definer_address)
			return callback("attestor list can be edited only by definer");
		err = checkAttestorList(payload.attestors);
		if (err)
			return callback(err);
		callback();
	});
}
```

**File:** aa_validation.js (L296-335)
```javascript
					}
					if (payload.cosigned_by_definer !== false)
						return cb2("cosigned_by_definer must be false because AA can't cosign");
					if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
						return cb2("asset issued by AA definer cannot be private or fixed denominations");
					async.eachSeries(
						["is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested"],
						function (field, cb3) {
							if (typeof payload[field] === 'boolean')
								return cb3();
							if (typeof payload[field] === 'string') {
								var f = getFormula(payload[field]);
								if (f === null)
									return cb3("bad formula for " + field + " in asset");
								return cb3();
							}
							cb3(field + " is missing or of wrong type");
						},
						function (err) {
							if (err)
								return cb2(err);
							async.series([
								function (cb3) {
									if (!("attestors" in payload))
										return cb3();
									validateFieldWrappedInCases(payload, 'attestors', validateAttestors, cb3);
								},
								function (cb3) {
									if (!("denominations" in payload))
										return cb3();
									validateFieldWrappedInCases(payload, 'denominations', validateDenominations, cb3);
								}
							],
							function (err) {
								if (err)
									return cb2(err);
								cb2();
							});
						}
					);
```

**File:** initial-db/byteball-sqlite.sql (L258-258)
```sql
	spender_attested TINYINT NOT NULL, -- must subsequently publish and update the list of trusted attestors
```

**File:** test/aa.test.js (L249-271)
```javascript
			{
				app: 'asset',
				payload: {
					cap: "{trigger.output[[asset=base]]}",
					is_transferrable: true,
					is_private: false,
					auto_destroy: "{trigger.data.auto_destroy}",
					fixed_denominations: false,
					issued_by_definer_only: true,
					cosigned_by_definer: false,
					spender_attested: false,
				}
			},
			{
				app: 'asset_attestors',
				payload: {
					asset: "{trigger.output[[asset!=base]].asset}",
					attestors: [
						"{trigger.data.attestor1}",
						"{trigger.data.attestor2 ? trigger.data.attestor2 : ''}",
					]
				}
			},
```

**File:** writer.js (L218-235)
```javascript
						case "asset":
							var asset = message.payload;
							conn.addQuery(arrQueries, "INSERT INTO assets (unit, message_index, \n\
								cap, is_private, is_transferrable, auto_destroy, fixed_denominations, \n\
								issued_by_definer_only, cosigned_by_definer, spender_attested, \n\
								issue_condition, transfer_condition) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", 
								[objUnit.unit, i, 
								asset.cap, asset.is_private?1:0, asset.is_transferrable?1:0, asset.auto_destroy?1:0, asset.fixed_denominations?1:0, 
								asset.issued_by_definer_only?1:0, asset.cosigned_by_definer?1:0, asset.spender_attested?1:0, 
								asset.issue_condition ? JSON.stringify(asset.issue_condition) : null,
								asset.transfer_condition ? JSON.stringify(asset.transfer_condition) : null]);
							if (asset.attestors){
								for (var j=0; j<asset.attestors.length; j++){
									conn.addQuery(arrQueries, 
										"INSERT INTO asset_attestors (unit, message_index, asset, attestor_address) VALUES(?,?,?,?)",
										[objUnit.unit, i, objUnit.unit, asset.attestors[j]]);
								}
							}
```

**File:** storage.js (L1917-1930)
```javascript
		function addAttestorsIfNecessary(byAA = false){
			if (!objAsset.spender_attested)
				return handleAsset(null, objAsset);

			// find latest list of attestors
			const before_last_ball_cond = byAA ? "" : `AND main_chain_index<=${+last_ball_mci} AND is_stable=1`;
			conn.query(
				"SELECT unit FROM asset_attestors CROSS JOIN units USING(unit) \n\
				WHERE asset=? " + before_last_ball_cond + " AND sequence='good' ORDER BY "+ (conf.bLight ? "units.rowid" : "level") + " DESC LIMIT 1",
				[asset],
				function (latest_rows) {
					if (latest_rows.length === 0)
						throw Error("no latest attestor list");
					var latest_attestor_list_unit = latest_rows[0].unit;
```
