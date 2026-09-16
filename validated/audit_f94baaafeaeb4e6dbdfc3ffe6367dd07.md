## Analysis

The bug class in the report is: a contract accepts deposits of a token whose properties violate an assumption baked into the contract (18 decimals), so the tokens get credited/received but can never be paid back out through the normal code path, permanently freezing them.

The closest reachable analog in `hirayap/ocore--003` is in the Autonomous Agent (AA) engine: an AA can receive a payment in a `fixed_denominations` ("indivisible") asset as part of a trigger, but the AA response-composer can never construct an outgoing `payment` message for that same asset, so any indivisible-asset funds sent to an AA become permanently stuck in the AA's balance.

### Title
AAs can receive fixed-denominations (indivisible) asset payments but can never send them back out, permanently freezing funds - (File: aa_composer.js)

### Summary
`validateAATriggerObject` in `aa_composer.js` allows a trigger unit to pay any existing asset — including `fixed_denominations` (indivisible) assets — to an AA address, and the AA's balance for that asset is credited normally. However, `handleTrigger`'s `sendUnit` function, which composes the AA's response unit, unconditionally drops any outgoing `payment` message whose asset is `fixed_denominations`, so the AA can never spend or forward those funds. Since AA definitions are immutable and there is no other withdrawal path, coins sent to an AA in an indivisible asset are permanently locked. [1](#0-0) 

### Finding Description
1. `validateAATriggerObject` only checks that the trigger address is valid, is not itself an AA, and that any non-base asset in `trigger.outputs` exists in the `assets` table. It does not reject `fixed_denominations` assets as trigger payments. [2](#0-1) 

2. Any unit paying such an asset to the AA passes normal payment validation exactly like a divisible-asset payment — `validatePaymentInputsAndOutputs` only special-cases `fixed_denominations` for input/output count and divisibility-by-denomination checks, not for AA-destination restrictions. [3](#0-2) [4](#0-3) 

3. Once received, the AA's balance for that asset is incremented (via `updateInitialAABalances`), so the AA's state tracks the deposited funds as spendable.

4. When the AA's oscript logic tries to respond with a `payment` message using that asset (e.g., to bounce, forward, or pay it out), `sendUnit`'s per-message processing explicitly skips completing the payload for `fixed_denominations` assets ("will skip it later"): [5](#0-4) 

5. After the first pass, a second filter unconditionally strips out any remaining `payment` message that references a `fixed_denominations` asset from the messages that will actually be included in the AA's response unit: [6](#0-5) 

6. If that filtering empties the message list, the AA silently finishes with `handleSuccessfulEmptyResponseUnit(null)` — the trigger is accepted, the deposit is recorded in the AA balance, but no compensating payment is ever produced, and the oscript author has no way to author a payment for that asset that will survive this filter, because the composer contains no indivisible-coin-picking logic (unlike `indivisible_asset.js`'s `pickIndivisibleCoinsForAmount`, which is only used by regular wallet sends, never by the AA composer).

This is structurally identical to the reported issue: the entry point (posting a trigger unit) lets *anyone* credit an AA with an asset type the receiving logic cannot re-emit, and because AA definitions are immutable oscript (no upgrade mechanism, no privileged withdrawal function), the funds are permanently stuck.

### Impact Explanation
Any user or attacker can send a `fixed_denominations` asset as a trigger payment to any AA (including AAs holding significant funds in other assets, or third-party AAs the attacker does not control). The AA:
- Accepts the trigger and updates internal balance/state for the indivisible asset (state changes, response counting, and bounce-fee accounting proceed as usual for the base-asset portion).
- Can never construct a valid outgoing payment for that asset, no matter what the AA's oscript author intended, because the response-composer categorically strips such messages.

Consequences:
- Funds locked in an indivisible asset at an AA address are permanently frozen — there is no AA-level or protocol-level mechanism to recover them, since AA addresses have no private key and AA logic cannot be redeployed/upgraded once instantiated.
- An attacker can grief a live production AA (e.g., an exchange/DEX/escrow AA) by sending it an indivisible asset it was never designed to expect, permanently reducing its reported balance-in-asset without any way for the AA (or its author) to recover or return it, which is a direct fund-freezing impact matching "AA fund loss or freezing" in the validation criteria.

### Likelihood Explanation
High reachability: this requires only posting a standard signed payment unit with a `fixed_denominations` asset output addressed to any existing AA — a completely unprivileged action available to any wallet/AA-trigger author. No special asset issuer collusion, hub/peer trust, or race condition is needed; it happens deterministically on the very first such trigger.

### Recommendation
- In `validateAATriggerObject` (`aa_composer.js`), reject trigger units whose `trigger.outputs` includes a `fixed_denominations` asset, so such payments to AA addresses are invalid at consensus-validation time rather than being silently absorbed and then dropped during response composition.
- Alternatively/additionally, in `validatePaymentInputsAndOutputs` (`validation.js`), disallow payment outputs of `fixed_denominations` assets whose destination address is a known AA address (mirroring the existing `checkNotAAs`/AA-address lookups already used elsewhere in `validation.js`), closing the gap for any payment path, not just the primary trigger.
- If AAs are intended to eventually support indivisible assets, add indivisible-coin-picking/composition logic to `aa_composer.js`'s `sendUnit`/`completePaymentPayload` rather than unconditionally filtering these messages out.

### Proof of Concept
1. Define/observe any existing AA address `AA1` (does not need any special definition — the bug affects all AAs since the filtering is unconditional in `sendUnit`).
2. Issue or acquire units of any existing `fixed_denominations` (indivisible) asset `ASSET_X`.
3. Compose and broadcast a normal payment unit that pays `>=` the AA's `bounce_fees.base` in bytes plus some amount of `ASSET_X` to `AA1`'s address, using `indivisible_asset.js` composition helpers (this is valid per `validatePaymentInputsAndOutputs`, which does not forbid an AA destination for fixed-denominations assets).
4. The trigger is validated and accepted (`validateAATriggerObject` in `aa_composer.js` lines 244-269 permits it).
5. `handleTrigger` executes; `updateInitialAABalances` credits the AA's `ASSET_X` balance.
6. Regardless of what the AA's oscript specifies (e.g., attempting `{app: 'payment', payload: {asset: '<ASSET_X unit>', outputs: [...]}}`), `sendUnit`'s processing skips completing that payload (`aa_composer.js` line 1327-1328) and then strips the message entirely (`aa_composer.js` line 1356-1360) before the response unit is built.
7. Confirm via `storage`/state that the AA's `ASSET_X` balance remains permanently non-zero and no outgoing payment for `ASSET_X` was ever produced across any subsequent trigger, demonstrating the funds are unrecoverable.

### Citations

**File:** aa_composer.js (L224-270)
```javascript
function validateAATriggerObject(trigger, handle) {
	if (!ValidationUtils.isNonemptyObject(trigger))
		return handle("no trigger");
	if (!ValidationUtils.isNonemptyObject(trigger.outputs))
		return handle("no trigger outputs");
	if (!ValidationUtils.isValidAddress(trigger.address))
		return handle("bad trigger address");
	if ("max_aa_responses" in trigger && (!ValidationUtils.isNonnegativeInteger(trigger.max_aa_responses) || trigger.max_aa_responses > constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER))
		return handle("bad trigger max_aa_responses");
	if (ValidationUtils.hasFieldsExcept(trigger, ["address", "data", "outputs", "max_aa_responses"])) // initial_address and initial_unit cannot be separately set in a primary trigger
		return handle("unexpected trigger fields");
	if (string_utils.isTooBigObj(trigger, { lengthLimit: 10e3 }))
		return handle("trigger data is too big");
	try {
		if (trigger.data)
			string_utils.getJsonSourceString(trigger.data);
	}
	catch (e) {
		return handle("invalid trigger data: " + e);
	}
	var arrAssets = Object.keys(trigger.outputs).filter(function(asset) {return asset !== 'base'});
	if (arrAssets.length >= constants.MAX_MESSAGES_PER_UNIT)
		return handle("too many assets");
	if (!ValidationUtils.isPositiveInteger(trigger.outputs.base))
		return handle("no base payment");
	if (!arrAssets.every(function(asset){return ValidationUtils.isPositiveInteger(trigger.outputs[asset])}))
		return handle("invalid output amount")

	function checkAddressIsNotAA() {
		db.query("SELECT 1 FROM aa_addresses WHERE address=?", [trigger.address], rows => {
			if (rows.length)
				return handle("trigger address must not be an AA");
			else
				return handle();
		});
	}

	if (arrAssets.length === 0)
		return checkAddressIsNotAA();
	// we have to check that assets exist otherwise foreign key constraint would fail when inserting fake outputs
	db.query("SELECT 1 FROM assets WHERE unit IN (?)", [arrAssets], function(rows) {
		if (rows.length !== arrAssets.length)
			return handle("unknown asset");
		else
			checkAddressIsNotAA();
	});
}
```

**File:** aa_composer.js (L1323-1328)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
```

**File:** aa_composer.js (L1356-1361)
```javascript
				messages = messages.filter(function (message) { return (message.app !== 'payment' || !message.payload.asset || !assetInfos[message.payload.asset].fixed_denominations); });
				if (messages.length === 0) {
					error_message = 'no messages after removing fixed denominations';
					console.log(error_message);
					return handleSuccessfulEmptyResponseUnit(null);
				}
```

**File:** validation.js (L2142-2143)
```javascript
	if (objAsset && objAsset.fixed_denominations && payload.inputs.length !== 1)
		return callback("fixed denominations payment must have 1 input");
```

**File:** validation.js (L2161-2162)
```javascript
		if (objAsset && objAsset.fixed_denominations && output.amount % denomination !== 0)
			return callback("output amount must be divisible by denomination");
```
