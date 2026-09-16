## Analog Found

### Title
AA bounce response cost (oversize/size fees) is uncapped while `bounce_fees` collected from the trigger are fixed, letting an attacker drain an AA's balance with cheap multi-asset triggers - (File: aa_composer.js)

### Summary
The GMX report describes a keeper who must front `gas_used * tx.gasprice` for execution but is only reimbursed up to the amount the user pre-paid, so if the real market cost exceeds the pre-paid fee, the executor loses funds. The analogous pattern in `ocore` is the AA `bounce_fees` mechanism: an AA author fixes a `bounce_fees` amount (per-asset, defaulting to `constants.MIN_BYTES_BOUNCE_FEE` for `base` only) that a trigger sender must supply to have a bounced trigger refunded. When the AA actually composes and sends the bounce response unit, however, the real network cost it must pay out of its **own** balance (`headers_commission` + `payload_commission` + `oversize_fee` under the v4 fee model) is not bounded by `bounce_fees` at all — it scales with the number of distinct assets/messages in the bounce, which an unprivileged trigger sender fully controls.

### Finding Description
When a trigger bounces, `handleTrigger`'s `bounce()` function iterates over every asset present in `trigger.outputs` and builds one `payment` message per asset for any asset whose configured `bounce_fees[asset]` is less than the amount sent: [1](#0-0) 

The only fee validated **before** committing to a bounce is a fixed, per-asset check that defaults to `0` for any asset not explicitly listed in the AA's `bounce_fees` object: [2](#0-1) 

and the `bounce_fees` object itself only forces a floor on `base`, not on any other asset: [3](#0-2) 

Once `bounce()` proceeds, `sendUnit()` composes the actual response unit, whose size (`headers_commission`/`payload_commission`) grows with the number of payment messages, and — since v4 — an `oversize_fee` that grows super-linearly once the unit exceeds `threshold_size`: [4](#0-3) 

This oversize/size cost is paid entirely out of the AA's own coin balance via `completePaymentPayload`'s input-selection loop (`getOversizeFee`), not out of the fixed `bounce_fees` retained from the trigger: [5](#0-4) 

So the AA (the "keeper"/executor in this analogy — it fronts the real, market/size-driven cost) can be forced to pay a network fee that is unbounded relative to what the trigger sender (the "user") was required to pre-pay (`bounce_fees`), exactly mirroring the GMX pattern of "keeper pays real cost, but is only reimbursed the fixed amount the user provided."

### Impact Explanation
A trigger sender can craft a trigger with many distinct assets that the target AA has never configured `bounce_fees` for (fee defaults to `0` for those assets) and just enough `base` output to satisfy `bounce_fees.base`. If a condition inside the AA (or simply an intentionally malformed/incomplete trigger) causes a bounce, the AA must issue one payment message per asset in `trigger.outputs`, inflating `headers_commission`, `payload_commission`, and — once size exceeds `threshold_size` — a fast-growing `oversize_fee`, all paid from the AA's own balance. Because the attacker's cost is bounded by `bounce_fees.base` (a small, fixed, author-chosen constant) while the AA's outlay is unbounded by the number of assets/messages, an attacker can repeatedly trigger cheap bounces to drain a well-funded AA's byte balance — a concrete AA fund-loss / griefing vector reachable by any ordinary, unprivileged unit poster.

### Likelihood Explanation
No special privilege, network position, or timing is required — any address can post a trigger unit to a public AA. The only requirement is crafting a trigger with several distinct assets (assets can be freely issued on `ocore`) and enough base bytes to pass the `bounce_fees.base` check, and causing the AA to bounce (many AAs bounce on invalid/insufficient input by design, or the attacker can simply supply data that fails an AA's own guard clause). This is a low-cost, repeatable, purely on-chain interaction, making the likelihood high for any AA that (a) holds a nontrivial byte balance and (b) does not exhaustively enumerate `bounce_fees` for every asset it might ever receive.

### Recommendation
- Charge the actual response-unit network fee (headers/payload commission + oversize fee) against the trigger's `bounce_fees` collection rather than a per-asset fixed amount that defaults to `0`.
- Cap the number of distinct assets/messages a single bounce response will emit, or require `bounce_fees` to scale with (or be validated against) the number of assets present in `trigger.outputs`.
- Alternatively, require that trigger senders cover the marginal size/oversize cost of the bounce (similar to how the size-based `bounce_fees.base` floor already works) before the AA will construct a multi-asset bounce response, rejecting/absorbing (rather than refunding) triggers whose bounce cost would exceed what was collected.

### Proof of Concept
1. Deploy/target an AA that defines `bounce_fees: { base: 10000 }` (the common pattern, e.g. `test/samples/simple_aa.oscript` / `just_a_bouncer.oscript`) and holds a substantial byte balance. [6](#0-5) 
2. Issue N distinct assets (cheap, unprivileged operation) and send a single trigger unit to the AA containing: `base` output = `bounce_fees.base` (10000), plus one output of each of the N assets.
3. Structure the trigger's data so the AA's logic bounces (or simply exploit an AA whose validation naturally bounces on certain inputs).
4. In `bounce()`, since none of the N assets are configured in `bounce_fees`, `fee = bounce_fees[asset] || 0`, so the full amount of each asset is returned, and a distinct `payment` message is added for each of the N assets: [7](#0-6) 
5. `sendUnit()` composes a response unit with N+1 payment messages; its `headers_commission`, `payload_commission`, and (once above `threshold_size`) `oversize_fee` are drawn from the AA's own balance, while the attacker only ever supplied the fixed `bounce_fees.base` (10000 bytes) regardless of N.
6. Repeating this with larger N (bounded only by `MAX_INPUTS_PER_PAYMENT_MESSAGE`/message limits) increases the AA's fee outlay per bounce while the attacker's cost per bounce stays roughly constant, draining the AA's balance over repeated triggers.

### Citations

**File:** aa_composer.js (L446-448)
```javascript
	var bounce_fees = template.bounce_fees || {base: constants.MIN_BYTES_BOUNCE_FEE};
	if (!bounce_fees.base)
		bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
```

**File:** aa_composer.js (L909-944)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
```

**File:** aa_composer.js (L1084-1100)
```javascript
			const bChargeOversizeFee = (mci >= constants.v4UpgradeMci && is_base);
			// AA-generated units pay the oversize fee based on the unit size excluding its payment messages;
			// this doesn't change as we add more inputs to the payment message, so calculate it only once
			const oversize_fee_excluding_payments = (bChargeOversizeFee && mci >= constants.pemCurvesFixMci)
				? storage.getOversizeFee(objUnit.headers_commission + objectLength.getTotalPayloadSize({ ...objUnit, messages: messages.filter(message => message.app !== 'payment') }) - paid_temp_data_fee, last_ball_mci)
				: null;
			var net_target_amount = payload.outputs.reduce(function (acc, output) { return acc + (output.amount || 0); }, size);
			let target_amount = net_target_amount + getOversizeFee(size);
			var bFound = false;

			function getOversizeFee(s) {
				if (!bChargeOversizeFee)
					return 0;
				if (mci < constants.pemCurvesFixMci)
					return storage.getOversizeFee(s - paid_temp_data_fee, last_ball_mci);
				return oversize_fee_excluding_payments;
			}
```

**File:** aa_composer.js (L1850-1859)
```javascript
		// being able to pay for bounce fees is not required for secondary triggers as they never actually send any bounce response or change state when bounced
		if (!bSecondary) {
			if ((trigger.outputs.base || 0) < bounce_fees.base) {
				return bounce('received bytes are not enough to cover bounce fees');
			}
			for (var asset in trigger.outputs) { // if not enough asset received to pay for bounce fees, ignore silently
				if (bounce_fees[asset] && trigger.outputs[asset] < bounce_fees[asset]) {
					return bounce('received ' + asset + ' is not enough to cover bounce fees');
				}
			}
```

**File:** storage.js (L1147-1166)
```javascript
function getOversizeFee(objUnitOrSize, mci, bAA) {
	let size;
	if (typeof objUnitOrSize === "number")
		size = objUnitOrSize; // must be already without temp data fee
	else if (typeof objUnitOrSize === "object") {
		if (!objUnitOrSize.headers_commission || !objUnitOrSize.payload_commission)
			throw Error("no headers or payload commission in unit");
		// AA-generated units pay the oversize fee based on the unit size excluding its payment messages to avoid swelling the fee while spending dust outputs
		const payload_commission = (bAA && mci >= constants.pemCurvesFixMci)
			? objectLength.getTotalPayloadSize({ ...objUnitOrSize, messages: objUnitOrSize.messages.filter(message => message.app !== 'payment') })
			: objUnitOrSize.payload_commission;
		size = objUnitOrSize.headers_commission + payload_commission - objectLength.getPaidTempDataFee(objUnitOrSize);
	}
	else
		throw Error("unrecognized 1st arg in getOversizeFee");
	const threshold_size = getSystemVar('threshold_size', mci);
	if (size <= threshold_size)
		return 0;
	return Math.ceil(size * (exp(size / threshold_size - 1) - 1));
}
```

**File:** test/samples/just_a_bouncer.oscript (L1-14)
```text
{
	bounce_fees: { base: 10000 },
	messages: [
		{
			app: 'payment',
			payload: {
				asset: 'base',
				outputs: [
					{address: "{trigger.address}", amount: "{trigger.output[[asset=base]] - 1000}"}
				]
			}
		}
	]
}
```
