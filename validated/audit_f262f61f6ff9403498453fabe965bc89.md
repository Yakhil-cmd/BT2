Based on my analysis, `checkAAOutputs` (called from `sendMultiPayment` in `wallet.js`) only validates bounce-fee sufficiency; it does not block or warn on private-asset payments to AA addresses. Combined with the protocol-level exclusion of private outputs from AA triggering (`main_chain.js`) and AA balance accounting (`storage.js`), this confirms private payments sent to an AA are unrecoverable — not just temporarily locked, but permanently, since AAs are also explicitly forbidden from sending private assets back out (`aa_composer.js:1329-1330`).

### Title
Private-asset payments sent to an Autonomous Agent address are permanently and irrecoverably locked - (File: main_chain.js, aa_composer.js, storage.js)

### Summary
Obyte's Autonomous Agents (AAs) are triggered only by public (non-private) payment outputs. Any private-asset payment sent to an AA address is silently excluded from AA-trigger detection and from the AA's tracked balance. Because AAs are also structurally prevented from ever sending private assets in a response, funds sent this way can never be returned by the AA logic itself, unlike the reported NounsDAO issue where the payment token was only *temporarily* locked until `cancel()`. Here the lock is permanent and protocol-enforced.

### Finding Description
When a main-chain index becomes stable, `handleAATriggers()` in `main_chain.js` selects units whose outputs create AA triggers, but it explicitly filters out private outputs:
```
WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0)
``` [1](#0-0) 

This means a private-asset payment to an AA address never inserts a row into `aa_triggers`, so the AA is never invoked for it and can never react to, refund, or otherwise process the payment.

Separately, `insertAADefinitions()` in `storage.js`, which seeds an AA's tracked `aa_balances` from outputs it already received, also excludes private outputs:
```
WHERE address=? AND is_spent=0 AND sequence='good' AND ... AND (is_private=0 OR is_private IS NULL)
``` [2](#0-1) 

So even if an AA is later defined/updated, the private funds never appear in its balance and the AA's own logic (which relies on `balance[asset]`) has no way to know these funds exist.

Finally, even if an AA author tried to proactively send such funds back, the AA composer explicitly forbids AAs from sending private assets in responses:
```
if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
    return cb("sending private asset from AA");
``` [3](#0-2) 

The wallet-side safety check `checkAAOutputs()`, which is invoked before sending any multi-payment via `sendMultiPayment()`, only validates that outputs meet the AA's declared `bounce_fees`; it performs no check for and issues no warning about sending a private asset to an AA address: [4](#0-3) [5](#0-4) 

### Impact Explanation
A user (or another private-payment counterparty forwarding a chain) who sends a private asset to an AA address — whether by mistake, by a wallet UI that doesn't distinguish AA addresses for private-asset sends, or by an AA whose documentation/oscript implies it accepts arbitrary asset payments — permanently loses those funds. There is no bounce, no error surfaced to the AA (it never even sees the trigger), and no AA-side recovery mechanism exists since sending private assets from an AA is unconditionally rejected. This is a stronger version of the reported bug class: rather than "temporarily locked until `cancel()`," the funds are unconditionally and permanently unrecoverable by protocol design, constituting a fund-freezing condition for any counterparty attempting a private-asset transfer to an AA.

### Likelihood Explanation
Likelihood is realistic: nothing in the wallet payment-composition path (`sendMultiPayment`/`checkAAOutputs`) or in AA/asset validation prevents constructing and broadcasting a private-asset payment whose output address happens to be a deployed AA. Any user manually specifying an AA address, or a text-coin/private-payment workflow directed at an AA address, would trigger the permanent loss with no protocol-level warning at composition or validation time.

### Recommendation
Extend `checkAAOutputs()` (and/or `sendMultiPayment`) to detect when any output of a private-asset payment (`objAsset.is_private`) targets a known AA address and reject/warn before broadcast, mirroring the existing bounce-fee check. Additionally, consider surfacing this as a validation-time rejection (or a dedicated bounce/refund mechanism) for private outputs landing on AA addresses in `main_chain.js`'s `handleAATriggers()`, rather than silently dropping them from trigger consideration.

### Proof of Concept
1. Deploy any AA (even the simplest bouncer AA) at address `X`.
2. Issue a private (`is_private: true`) divisible or indivisible asset.
3. Use `sendMultiPayment`/`composeAndSaveDivisibleAssetPaymentJoint` (or the wallet UI) to send some of that private asset to address `X` — `checkAAOutputs` only checks base/asset bounce-fee sufficiency and raises no objection because it doesn't inspect asset privacy.
4. Once the unit stabilizes, `handleAATriggers()`'s query filters this output out via `is_private=0`, so no `aa_triggers` row is created and the AA never executes for this payment.
5. `readAABalances`/`aa_balances` for address `X` never reflect the private asset (per the `is_private=0 OR is_private IS NULL` filter in `insertAADefinitions`), so no AA logic can reference or refund it.
6. The AA can never send this asset back even if instructed to, since `sendUnit()` unconditionally bounces any attempt to include `is_private` assets in an AA response (`"sending private asset from AA"`).
7. The private asset payment is permanently stuck at address `X` with no path to recovery.

### Citations

**File:** main_chain.js (L1695-1704)
```javascript
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
```

**File:** storage.js (L960-961)
```javascript
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
```

**File:** aa_composer.js (L1329-1330)
```javascript
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```

**File:** aa_addresses.js (L120-156)
```javascript
function checkAAOutputs(arrPayments, handleResult) {
	var assocAmounts = {};
	arrPayments.forEach(function (payment) {
		var asset = payment.asset || 'base';
		payment.outputs.forEach(function (output) {
			if (!assocAmounts[output.address])
				assocAmounts[output.address] = {};
			if (!assocAmounts[output.address][asset])
				assocAmounts[output.address][asset] = 0;
			assocAmounts[output.address][asset] += output.amount;
		});
	});
	var arrAddresses = Object.keys(assocAmounts);
	readAADefinitions(arrAddresses, function (err, rows) {
		if (err)
			return handleResult(err);
		if (rows.length === 0)
			return handleResult();
		var arrMissingBounceFees = [];
		rows.forEach(function (row) {
			var arrDefinition = JSON.parse(row.definition);
			var bounce_fees = arrDefinition[1].bounce_fees;
			if (!bounce_fees)
				bounce_fees = { base: constants.MIN_BYTES_BOUNCE_FEE };
			if (!bounce_fees.base)
				bounce_fees.base = constants.MIN_BYTES_BOUNCE_FEE;
			for (var asset in bounce_fees) {
				var amount = assocAmounts[row.address][asset] || 0;
				if (amount < bounce_fees[asset])
					arrMissingBounceFees.push({ address: row.address, asset: asset, missing_amount: bounce_fees[asset] - amount, recommended_amount: bounce_fees[asset] });
			}
		});
		if (arrMissingBounceFees.length === 0)
			return handleResult();
		handleResult(new MissingBounceFeesErrorMessage({ error: "The amounts are less than bounce fees", missing_bounce_fees: arrMissingBounceFees }));
	});
}
```

**File:** wallet.js (L2186-2194)
```javascript
	if (!opts.aa_addresses_checked) {
		aa_addresses.checkAAOutputs(arrPayments, function (err) {
			if (err)
				return handleResult(err);
			opts.aa_addresses_checked = true;
			sendMultiPayment(opts, handleResult);
		});
		return;
	}
```
