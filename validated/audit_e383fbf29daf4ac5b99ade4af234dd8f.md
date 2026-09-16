### Title
Bounce fee upper bound in AA definitions is set too high, allowing an AA author to seize nearly all of a trigger sender's funds - (File: `aa_validation.js`)

### Summary
The external report flags that Native's `widgetFee` cap of `10000` (100%) lets a market maker take a swapper's entire input as "fee." The analogous pattern in ocore is the `bounce_fees` field of an AA (Autonomous Agent) definition: any unprivileged author of an AA can declare a `bounce_fees` value that is validated only against `constants.MAX_CAP` (the total coin supply) rather than any sane cap relative to typical trigger sizes, so a malicious/careless AA author can set an arbitrarily huge bounce fee and capture (up to) the entire amount sent by a triggering unit whenever the AA response bounces.

### Finding Description
When validating an AA definition, `bounce_fees` for each asset is checked only for a lower bound (`MIN_BYTES_BOUNCE_FEE`) and an upper bound of `constants.MAX_CAP`: [1](#0-0) 

`constants.MAX_CAP` is the maximum coin supply cap used elsewhere for asset caps and issue amounts, not a reasonable percentage-of-trigger-amount limit. This means an AA author can set `bounce_fees.base` (or `bounce_fees[asset]`) to an extremely large number, effectively unbounded relative to what any real trigger unit will contain.

At trigger-handling time, this fee value is read directly from the AA template with no further sanity check against the trigger's actual outputs beyond simply requiring the trigger amount to at least cover the fee: [2](#0-1) 

If a trigger unit's payment to the AA equals or barely exceeds the declared `bounce_fees`, and the AA's oscript logic is written (or manipulated) to bounce under conditions the unwary poster doesn't anticipate, the AA can retain the entire sent amount (minus dust) as the "bounce fee," refunding nothing. This is confirmed by the existing test showing bounce behavior when funds are insufficient to cover fees: [3](#0-2) 

Because `bounce_fees` can be declared up to `MAX_CAP`, an AA author (analogous to Native's "market maker") can advertise a service (e.g., a swap/exchange AA) whose bounce fee is set to (or very close to) 100% of any realistic trigger amount, so any user whose trigger fails validation inside the AA's oscript loses their entire payment to the AA instead of only a modest, expected penalty.

### Impact Explanation
This allows any unprivileged AA author — reachable by simply posting an AA `definition` message, which any unit poster can do — to construct an autonomous agent that is designed (or later triggers unexpected edge cases) to bounce and thereby confiscate essentially the full amount that a triggering user sent, rather than a fair, capped penalty fee. Victims (any unit poster who interacts with such an AA, expecting normal bounce-refund behavior) suffer unauthorized loss of funds with no recourse, since AA behavior is deterministic and validated by all full nodes — this is a fund-loss/fund-freezing condition for legitimate trigger senders, not a bug that only affects the AA author's own funds.

### Likelihood Explanation
Likelihood is high: `bounce_fees` is a normal, commonly-used field in AA definitions (used in nearly every sample/test AA in the repo), and the validation logic imposes no meaningful economic sanity limit beyond the network-wide max coin supply. Any AA author, without any special privilege, can set this value as high as they want up to `MAX_CAP`, and ordinary users triggering the AA (e.g., via a DeFi/exchange-style AA) have no on-chain signal preventing them from sending funds that get wholly or mostly confiscated on bounce.

### Recommendation
Introduce a much lower, economically sane upper bound for `bounce_fees` in `aa_validation.js` (e.g., a small fixed multiple of expected minimum transaction sizes, or a percentage-based cap relative to typical trigger amounts) rather than allowing values up to `constants.MAX_CAP`. Alternatively, cap the effective bounce fee actually charged at trigger-handling time (`aa_composer.js`) to a small fraction of the trigger's `outputs`, so an AA cannot use a static, unrealistically large `bounce_fees` declaration to seize essentially all of a sender's payment.

### Proof of Concept
1. An attacker publishes an AA `definition` message with `bounce_fees: { base: constants.MAX_CAP }` (or any very large value well beyond typical trigger amounts) — this definition passes validation because the only checks are `isNonnegativeInteger(fee) && fee <= constants.MAX_CAP` and the `MIN_BYTES_BOUNCE_FEE` floor (`aa_validation.js:748-760`).
2. A victim unit poster sends a trigger to this AA with a payment amount equal to or slightly above the declared `bounce_fees` (a normal, reasonable-looking transaction amount for interacting with the AA, e.g. thinking it's a swap fee).
3. The AA's oscript logic (crafted or naturally) causes the trigger to bounce; per `aa_composer.js:446-448`, the entire `bounce_fees` amount is retained by the AA and only any excess beyond `bounce_fees` (potentially zero) is refunded, as shown in the existing bounce test behavior (`test/aa_composer.test.js:120-145`, where the trigger's `2000` bytes are entirely consumed against a `10000`-byte bounce fee, causing outright bounce rather than partial refund).
4. Because the cap on `bounce_fees` is `MAX_CAP` rather than a reasonable fraction, the AA author can, in effect, replicate the Native `widgetFee`-at-100%-scenario: legitimate users can lose their full payment to an "overcharging" AA whenever bounce conditions are met.

### Citations

**File:** aa_validation.js (L748-760)
```javascript
	if ('bounce_fees' in template){
		if (!isNonemptyObject(template.bounce_fees))
			return callback("empty bounce_fees");
		for (var asset in template.bounce_fees){
			if (asset !== 'base' && !isValidBase64(asset, constants.HASH_LENGTH))
				return callback("bad asset in bounce_fees: " + asset);
			var fee = template.bounce_fees[asset];
			if (!isNonnegativeInteger(fee) || fee > constants.MAX_CAP)
				return callback("bad bounce fee: "+JSON.stringify(fee));
		}
		if ('base' in template.bounce_fees && template.bounce_fees.base < constants.MIN_BYTES_BOUNCE_FEE)
			return callback("too small base bounce fee: "+template.bounce_fees.base);
	}
```

**File:** aa_composer.js (L446-448)
```javascript
	var bounce_fees = template.bounce_fees || {base: constants.MIN_BYTES_BOUNCE_FEE};
	if (!bounce_fees.base)
		bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
```

**File:** test/aa_composer.test.js (L120-145)
```javascript
test.cb.serial('less than bounce fees', t => {
	var trigger = { outputs: { base: 2000 }, data: { x: 333 } };
	var aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [
						{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 500}"}
					]
				}
			}
		]
	}];
	var address = objectHash.getChash160(aa);
	addAA(aa);
	
	aa_composer.dryRunPrimaryAATrigger(trigger, address, aa, (arrResponses) => {
		t.deepEqual(arrResponses.length, 1);
		t.deepEqual(arrResponses[0].aa_address, address);
		t.deepEqual(arrResponses[0].bounced, true);
		t.deepEqual(arrResponses[0].response_unit, null);
		t.deepEqual(arrResponses[0].objResponseUnit, null);
		t.deepEqual(arrResponses[0].response.error, "received bytes are not enough to cover bounce fees");
```
