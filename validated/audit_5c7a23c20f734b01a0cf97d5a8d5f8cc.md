### Title
Unhandled `throw Error` on missing `src_coin` fields in private indivisible-asset payment validation causes a crash (DoS) - ([File: validation.js])

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` validates the `transfer` type of a payment input. For private, fixed-denomination assets it takes a completely different, non-callback code path that assumes `objValidationState.src_coin` and its sub-fields (`src_output`, `denomination`, `amount`) are always present and well-formed. If any of these fields is missing, the code calls `throw Error(...)` instead of returning a validation error through `callback()`. [1](#0-0) 

### Finding Description
Throughout `validation.js`, malformed/missing fields in units, payments, and inputs are normally reported through `callback(err)` so the caller can gracefully reject the joint/private-payment chain (`ifUnitError`/`ifError`). The private, fixed-denominations transfer branch breaks this pattern:

```
if (objAsset && objAsset.is_private && objAsset.fixed_denominations){
    if (!objValidationState.src_coin)
        throw Error("no src_coin");
    var src_coin = objValidationState.src_coin;
    if (!src_coin.src_output)
        throw Error("no src_output");
    if (!isPositiveInteger(src_coin.denomination))
        throw Error("no denomination in src coin");
    if (!isPositiveInteger(src_coin.amount))
        throw Error("no src coin amount");
``` [1](#0-0) 

This code is reached via `validatePayment()` → `validatePaymentInputsAndOutputs()`, which is invoked for both public and private payments, including the private-payment-chain path used when receiving a private (indivisible) asset payment from a counterparty (`initPrivatePaymentValidationState` builds `objValidationState` for a private message, and the indivisible-asset private-payment validator is expected to pre-populate `objValidationState.src_coin` before calling into `validatePayment`). [2](#0-1) 

This mirrors the CVE-2024-34235 bug class exactly: a required field that is normally supplied by a well-behaved peer/sender is missing in a maliciously/incorrectly crafted message, and instead of the parser/validator returning a structured error, the code hits an assertion-style `throw`, deep inside a callback chain, that is not guaranteed to be caught by any surrounding `try/catch`. In Node.js, an exception thrown inside an asynchronous callback that isn't wrapped in a try/catch propagates as an uncaught exception and crashes the process, exactly like the S1AP assertion crash in Open5GS.

### Impact Explanation
A counterparty in a private (indivisible) asset payment exchange — reachable by any wallet peer performing an off-chain private payment chain exchange — can send a private payment chain whose accompanying/derived `src_coin` state is incomplete (e.g. because attacker-controlled data purposely omits `denomination`/`amount`/`src_output` in the private element it forwards). Because the receiving side's validation throws instead of rejecting gracefully, the receiving wallet/node process can crash, denying service to the wallet and interrupting participation in the network — the same "malformed input causes a crash of the message-processing component" class as the CVE.

### Likelihood Explanation
Likelihood is limited by the fact that a full exploit path requires demonstrating that an attacker fully controls the malformed private-element content that populates `objValidationState.src_coin` before this validator runs (this pre-population happens in `indivisible_asset.js`, which was not able to be fully inspected in this session). If an attacker can supply a private payment chain (or spoof `src_coin` construction inputs) that omits these fields, the crash is trivially triggered without any privileged access — matching a "High" severity DoS similar to the CVE. Because I could not fully trace `indivisible_asset.js`'s population of `src_coin` in this session, the exact reachability of attacker control over these three fields should be verified before treating this as fully confirmed.

### Recommendation
Replace the `throw Error(...)` calls at `validation.js:2416-2424` with `return cb(...)` (using the existing `cb` callback of the `async.forEachOfSeries` loop) so malformed/incomplete `src_coin` state during private-payment validation results in a controlled validation error (`ifError`) rather than an uncaught exception that can crash the process. Additionally, validate `src_coin` fields as early as possible in the private-payment-chain construction path (in `indivisible_asset.js` / wherever `src_coin` is populated) before it is trusted downstream.

### Proof of Concept
Not independently reproduced with a live run in this session; based on static analysis: send/receive a private (indivisible, fixed-denomination) asset payment chain where the corresponding source coin element omitted from the private element passed to `validatePaymentInputsAndOutputs` lacks `src_output`, `denomination`, or `amount` before reaching the `transfer` branch at `validation.js:2415-2424`. This drives the code into `throw Error("no src_coin")` / `"no src_output"` / `"no denomination in src coin"` / `"no src coin amount"` instead of returning a validation error, which — if not caught by an enclosing try/catch in the calling stack — crashes the receiving process.

### Citations

**File:** validation.js (L2415-2424)
```javascript
					if (objAsset && objAsset.is_private && objAsset.fixed_denominations){
						if (!objValidationState.src_coin)
							throw Error("no src_coin");
						var src_coin = objValidationState.src_coin;
						if (!src_coin.src_output)
							throw Error("no src_output");
						if (!isPositiveInteger(src_coin.denomination))
							throw Error("no denomination in src coin");
						if (!isPositiveInteger(src_coin.amount))
							throw Error("no src coin amount");
```

**File:** validation.js (L2679-2722)
```javascript
function initPrivatePaymentValidationState(conn, unit, message_index, payload, onError, onDone){
	conn.query(
		"SELECT payload_hash, app, units.sequence, units.version, units.is_stable, lb_units.main_chain_index AS last_ball_mci, lb_units.timestamp AS last_ball_timestamp \n\
		FROM messages JOIN units USING(unit) \n\
		LEFT JOIN units AS lb_units ON units.last_ball_unit=lb_units.unit \n\
		WHERE messages.unit=? AND message_index=?", 
		[unit, message_index], 
		function(rows){
			if (rows.length > 1)
				throw Error("more than 1 message by index");
			if (rows.length === 0)
				return onError("message not found");
			var row = rows[0];
			if (row.sequence !== "good" && row.is_stable === 1)
				return onError("unit is final nonserial");
			var bStable = (row.is_stable === 1); // it's ok if the unit is not stable yet
			if (row.app !== "payment")
				return onError("invalid app");
			try{
				if (objectHash.getBase64Hash(payload, row.version !== constants.versionWithoutTimestamp) !== row.payload_hash)
					return onError("payload hash does not match");
			}
			catch(e){
				return onError("failed to calc payload hash: "+e);
			}
			var objValidationState = {
				last_ball_mci: row.last_ball_mci,
				last_ball_timestamp: row.last_ball_timestamp,
				arrDoubleSpendInputs: [],
				arrInputKeys: [],
				bPrivate: true
			};
			var objPartialUnit = {unit: unit};
			storage.readUnitAuthors(conn, unit, function(arrAuthors){
				objPartialUnit.authors = arrAuthors.map(function(address){ return {address: address}; }); // array of objects {address: address}
				// we need parent_units in checkForDoublespends in case it is a doublespend
				conn.query("SELECT parent_unit FROM parenthoods WHERE child_unit=? ORDER BY parent_unit", [unit], function(prows){
					objPartialUnit.parent_units = prows.map(function(prow){ return prow.parent_unit; });
					onDone(bStable, objPartialUnit, objValidationState);
				});
			});
		}
	);
}
```
