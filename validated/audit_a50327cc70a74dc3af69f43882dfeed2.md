### Title
Asset `transfer_condition`/`issue_condition` blacklist checks via `in data feed` can be front-run by racing an earlier `last_ball_mci` - (File: `definition.js`, `validation.js`)

### Summary
An asset issuer that implements an on-chain "blacklist"/compliance restriction for a `transfer_condition` (or `issue_condition`) using the `in data feed` operator can have that restriction bypassed by a user who races to publish a transfer before the restricting data-feed unit becomes part of the referenced stable state. This is analogous to the reported `TransferRestrictor#restrict` front-run: the "blacklist" check is evaluated against a snapshot (`last_ball_mci`) chosen by the *sender*, not against the very latest state, so a party who sees an oracle about to publish a "blacklisted=1" data feed can broadcast (or has already prepared) a payment whose `last_ball_unit` predates that data feed's stabilization, evading the restriction entirely.

### Finding Description
Asset definitions in ocore allow an `issue_condition`/`transfer_condition` (validated in `validateAssetDefinition`, e.g. [1](#0-0) ) which is later enforced on every payment of that asset: [2](#0-1) 

This calls `Definition.evaluateAssetCondition`, which for the `in data feed` operator resolves against `objValidationState.last_ball_mci` — a value supplied by the unit's author (derived from whatever stable ball they choose to reference), not the current network tip: [3](#0-2) 

and `dataFeeds.dataFeedExists` only searches for stable data feeds with `main_chain_index <= max_mci` (i.e. `<= last_ball_mci`): [4](#0-3) 

If an issuer designs a compliance/blacklist scheme where an oracle posts a data feed (e.g. `BLACKLISTED_<address> = 1`) and the asset's `transfer_condition` contains `["not", ["in data feed", [[oracle], "BLACKLISTED_<address>", "=", 1]]]`, the restriction is only effective once that oracle unit is stable and its MCI is `<= last_ball_mci` of the *spending* unit. A holder who is about to be (or sees they are being) blacklisted can construct and broadcast a transfer that references an earlier, already-stable `last_ball_unit` (one whose MCI predates the oracle's blacklist unit). Because unit composition lets the sender pick any sufficiently-recent stable ball as `last_ball_unit`, and validation only requires that the chosen last ball is on the main chain and included by parents (see `validateParents`, [5](#0-4) ), nothing forces the sender to use the very latest stable state that already includes the blacklist entry. The transfer therefore validates successfully as if the blacklist had never been posted, exactly mirroring the front-running of `restrict()` in the external report: the restriction is bypassed by racing to finalize a transaction against a stale/earlier "restriction-not-yet-applied" state.

### Impact Explanation
An asset issuer's freeze/blacklist mechanism (built with the standard `transfer_condition` + `in data feed` primitives) can be defeated, letting a restricted address move funds out before the restriction is (from the protocol's perspective) enforceable. This is a real loss of the intended compliance/security guarantee for asset holders and issuers relying on this common pattern for regulated or freezable tokens — equivalent in effect to unauthorized transfer of a restricted asset.

### Likelihood Explanation
Requires an asset with a `transfer_condition`/`issue_condition` that references `in data feed` for a dynamic allow/deny list (a documented, supported, and commonly recommended pattern for building compliance features on ocore/Obyte assets) and requires the attacker to notice or anticipate an oracle publishing a restricting value. Because the DAG is public and units propagate before becoming stable, an attentive holder can react in time to compose a competing unit against an older last-ball, making this feasible for any issuer using data-feed-based restrictions.

### Recommendation
- Document this limitation explicitly for asset issuers using `in data feed` for blacklisting: MCI-snapshot conditions are inherently vulnerable to this "stale last_ball" bypass and cannot retroactively restrict a transaction whose `last_ball_mci` predates the restricting feed.
- Consider adding a validation rule that rejects overly-old `last_ball_unit` references for units carrying restricted-asset payments (i.e., require last_ball to be within some minimal lag of the known network tip) to reduce the window for this race, or provide a built-in blacklist/attestor-revocation primitive (as opposed to relying purely on `in data feed`) whose enforcement is tied to when the address became involved in the payment (its inputs), not solely to the spender's chosen snapshot.

### Proof of Concept
1. Issuer defines an asset with `transfer_condition`: `["not", ["in data feed", [["ORACLE_ADDRESS"], "BLACKLISTED_"+holder_address, "=", 1]]]` — validated per `validateAssetDefinition` ( [1](#0-0) ).
2. Oracle broadcasts a `data_feed` unit setting `BLACKLISTED_<holder_address>=1` to freeze `holder_address`.
3. Before that unit stabilizes (i.e., before its MCI is included as `<= last_ball_mci` for new units), `holder_address` composes and broadcasts a `payment` message transferring the asset, deliberately choosing an already-known-stable `last_ball_unit` whose MCI is smaller than what the oracle unit will eventually receive.
4. Validation of the payment's `transfer_condition` calls `Definition.evaluateAssetCondition` → `in data feed` → `dataFeeds.dataFeedExists(..., max_mci=last_ball_mci)` ( [3](#0-2) ), which does not find the not-yet-included blacklist feed, so the condition `["not", [...]]` evaluates true and the transfer is accepted despite the intended blacklist.

### Citations

**File:** validation.js (L720-741)
```javascript
			conn.query(
				"SELECT is_stable, is_on_main_chain, main_chain_index, ball, timestamp, (SELECT MAX(main_chain_index) FROM units) AS max_known_mci \n\
				FROM units LEFT JOIN balls USING(unit) WHERE unit=?", 
				[last_ball_unit], 
				function(rows){
					if (rows.length !== 1) // at the same time, direct parents already received
						return callback("last ball unit "+last_ball_unit+" not found");
					var objLastBallUnitProps = rows[0];
					// it can be unstable and have a received (not self-derived) ball
					//if (objLastBallUnitProps.ball !== null && objLastBallUnitProps.is_stable === 0)
					//    throw "last ball "+last_ball+" is unstable";
					if (objLastBallUnitProps.ball === null && objLastBallUnitProps.is_stable === 1)
						throw Error("last ball unit "+last_ball_unit+" is stable but has no ball");
					if (objLastBallUnitProps.is_on_main_chain !== 1)
						return callback("last ball "+last_ball+" is not on MC");
					if (objLastBallUnitProps.ball && objLastBallUnitProps.ball !== last_ball)
						return callback("last_ball "+last_ball+" and last_ball_unit "+last_ball_unit+" do not match");
					objValidationState.last_ball_mci = objLastBallUnitProps.main_chain_index;
					objValidationState.last_ball_timestamp = objLastBallUnitProps.timestamp;
					objValidationState.max_known_mci = objLastBallUnitProps.max_known_mci;
					if (objValidationState.max_parent_limci < objValidationState.last_ball_mci)
						return callback("last ball unit "+last_ball_unit+" is not included in parents, unit "+objUnit.unit);
```

**File:** validation.js (L2643-2658)
```javascript
					function(cb){
						var arrCondition = bIssue ? objAsset.issue_condition : objAsset.transfer_condition;
						if (!arrCondition)
							return cb();
						Definition.evaluateAssetCondition(
							conn, payload.asset, arrCondition, objUnit, objValidationState, 
							function(cond_err, bSatisfiesCondition){
								if (cond_err)
									return cb(cond_err);
								if (!bSatisfiesCondition)
									return cb("transfer or issue condition not satisfied");
								console.log("validatePaymentInputsAndOutputs with transfer/issue conditions done");
								cb();
							}
						);
					}
```

**File:** validation.js (L2815-2826)
```javascript
	async.series([
		function(cb){
			if (!("issue_condition" in payload))
				return cb();
			Definition.validateDefinition(conn, payload.issue_condition, objUnit, objValidationState, null, true, cb);
		},
		function(cb){
			if (!("transfer_condition" in payload))
				return cb();
			Definition.validateDefinition(conn, payload.transfer_condition, objUnit, objValidationState, null, true, cb);
		}
	], callback);
```

**File:** definition.js (L933-940)
```javascript
			case 'in data feed':
				// ['in data feed', [['BASE32'], 'data feed name', '=', 'expected value']]
				var arrAddresses = args[0];
				var feed_name = args[1];
				var relation = args[2];
				var value = args[3];
				var min_mci = args[4] || 0;
				dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, objValidationState.last_ball_mci, false, cb2);
```

**File:** data_feeds.js (L13-17)
```javascript
function dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, max_mci, bAA, handleResult){
	var start_time = Date.now();
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	if (bAA) {
		var bFound = false;
```
