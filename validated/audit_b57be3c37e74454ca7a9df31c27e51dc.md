Confirmed: `checkAAOutputs` in `aa_addresses.js` only warns about missing bounce fees; it never checks whether the payment asset is private, so nothing in the wallet-side pre-send validation stops a user from privately paying an existing AA address. The protocol-level trigger detection in `main_chain.js:handleAATriggers` explicitly excludes private outputs (`outputs.asset IS NULL OR is_private=0`), and the same exclusion is baked into the AA balance accounting query in `storage.js:insertAADefinitions` (`AND (is_private=0 OR is_private IS NULL)`). Separately, `aa_composer.js` explicitly refuses to let an AA ever send out a private asset (`"sending private asset from AA"`). Together these three facts reproduce the report's core bug class: value can land at a fund-holding AA address without ever being reflected in the AA's internal accounting (`aa_balances` / `balance[asset]` used throughout oscript, e.g. the vault-style `uniswap_like_market_maker.oscript` sample), and once there it structurally cannot be returned.

### Title
Private-asset payments to an AA are never counted in its balance and can never be paid back out - permanent fund freezing ([File: main_chain.js], [File: storage.js], [File: aa_composer.js])

### Summary
An Autonomous Agent (AA) in Obyte tracks the funds it "owns" through the `aa_balances` table, which is populated only from outputs that trigger the AA or are pre-existing at definition time, and this population explicitly excludes private outputs (`is_private=0 OR is_private IS NULL`). Because private-asset payments to an AA address never create a trigger, and because AAs are structurally forbidden from sending private assets, any private payment mistakenly or maliciously sent to an existing AA becomes permanently untracked and unspendable by that AA - directly mirroring the reported `OmoVault` issue where funds can sit "outside the vault" from the perspective of the accounting logic, corrupting the derived totals used for deposit/withdraw math.

### Finding Description
`main_chain.js#handleAATriggers` selects the outputs of a newly stabilized unit that should trigger AAs: [1](#0-0) 
Note the `WHERE ... AND (outputs.asset IS NULL OR is_private=0)` condition — a private-asset output sent to an AA address is silently excluded from the AA-trigger detection query, meaning the AA never runs to process it.

Independently, the balance bootstrap logic that seeds/refreshes `aa_balances` for an AA (used both at AA definition time and to recalc balances of payments arriving before/around definition) applies the identical exclusion: [2](#0-1) 

`aa_balances` is the sole source used by the `balance[asset]` formula operator (`formula/evaluation.js`) that AAs use to reason about the funds they currently hold: [3](#0-2) 
This is the exact analog of `OmoVault#totalAssets()`: an internally tracked accounting value that is supposed to represent all funds owned by the contract but can diverge from the real underlying funds.

Finally, even in the hypothetical case where an AA became aware of holding a private asset (e.g., through out-of-band knowledge), it is structurally unable to ever send it back out, since the composer explicitly rejects any outgoing private-asset payment message from an AA: [4](#0-3) 

On the sending side, `aa_addresses.js#checkAAOutputs`, which is the only pre-flight validation invoked by `wallet.js#sendMultiPayment` before composing a payment to an address that happens to be an AA, checks only for missing bounce fees — it never inspects whether the asset being sent is private, so nothing prevents an ordinary wallet user (or a malicious actor manipulating another user, e.g. via a textcoin/private asset transfer flow) from sending a private-asset payment straight to a live AA address: [5](#0-4) [6](#0-5) 

### Impact Explanation
Any AA that is designed to hold and account for a given asset (a vault/market-maker/exchange-style AA, exactly like the sample `uniswap_like_market_maker.oscript` which computes share issuance/redemption ratios from `balance[$asset]`) will silently miscalculate its economics if that asset is (or becomes) a private asset and someone pays it privately to the AA's address: [7](#0-6) 
The AA is never triggered to acknowledge the deposit, `aa_balances`/`balance[asset]` never reflects it, and the AA can never redeem/return it because outgoing private payments from an AA are unconditionally rejected. This is a permanent, unrecoverable loss of the deposited funds for the sender, and for any AA whose internal logic conditions on the completeness of `balance[asset]` (share pricing, collateralization checks, solvency assumptions), the discrepancy between actual and tracked holdings can also be exploited/observed by other participants interacting with the same AA, corrupting all downstream deposit/withdraw computations — the same class of impact ("Funds not always in vault... corrupt all the logic of deposit/mint and redeem") described in the source report.

### Likelihood Explanation
Reachability requires only a single unprivileged actor: any wallet holding a private asset can compose and send a private payment to any known AA address using the standard `divisible_asset.js`/`indivisible_asset.js` composer paths, with no wallet-side or protocol-side check preventing it (`checkAAOutputs` only checks bounce fees). No special privileges, malicious peers, or coordination are needed; it can also happen accidentally (a user privately paying an AA address by mistake, e.g. by reusing an address for a private asset transfer), making it Low-to-Medium likelihood but a legitimate, low-effort attack/misuse path for any AA that deals with private assets.

### Recommendation
- Reject payments (at wallet-composition time in `aa_addresses.js#checkAAOutputs` and/or at protocol validation time in `validation.js#validatePayment`/`validateAATrigger`) whose output address is a known AA and whose asset `is_private === true`, so private-asset payments to AAs are refused before being broadcast/committed.
- As defense in depth, have `main_chain.js#handleAATriggers` detect (rather than silently ignore) private outputs sent to AA addresses and either bounce them via a dedicated mechanism or refuse to stabilize such units, since currently the funds land irreversibly at the AA with no path back.

### Proof of Concept
1. Define/deploy an AA that defines or is designed to interact with a private (`is_private: true`) asset (or reuse an existing private asset and target any live AA address as recipient).
2. From a separate wallet, compose and send a private-asset payment (`divisible_asset.js#composeDivisibleAssetPaymentJoint` or `indivisible_asset.js#composeIndivisibleAssetPaymentJoint`) with `to_address` set to the AA's address.
3. Observe that `main_chain.js#handleAATriggers` (line 1702, `outputs.asset IS NULL OR is_private=0`) excludes this output, so no `aa_triggers` row is inserted and the AA never runs.
4. Query `aa_balances` for the AA address/asset and observe the balance is unaffected, while the on-chain output at the AA's address exists and `is_spent=0`.
5. Attempt, from within the AA's own oscript logic (or manually via `aa_composer.js#sendUnit`), to have the AA send that private asset out to any address — observe it is rejected with `"sending private asset from AA"` (`aa_composer.js:1329-1330`), confirming the funds are permanently stuck and permanently absent from the AA's own accounting.

### Citations

**File:** main_chain.js (L1695-1707)
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
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
			function (rows) {
```

**File:** storage.js (L954-961)
```javascript
					conn.query(
						verb + " INTO aa_balances (address, asset, balance) \n\
						SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
						FROM outputs \n\
						CROSS JOIN units USING(unit) \n\
						LEFT JOIN assets ON asset=assets.unit \n\
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
```

**File:** formula/evaluation.js (L1510-1528)
```javascript
				function readBalance(param_address, bal_asset, cb2) {
					if (bal_asset !== 'base' && !ValidationUtils.isValidBase64(bal_asset, constants.HASH_LENGTH))
						return setFatalError('bad asset ' + bal_asset, { arr }, false, cb);

					if (!objValidationState.assocBalances[param_address])
						objValidationState.assocBalances[param_address] = {};
					var balance = objValidationState.assocBalances[param_address][bal_asset];
					if (balance !== undefined)
						return cb2(new Decimal(balance));
					conn.query(
						"SELECT balance FROM aa_balances WHERE address=? AND asset=? ",
						[param_address, bal_asset],
						function (rows) {
							balance = rows.length ? rows[0].balance : 0;
							objValidationState.assocBalances[param_address][bal_asset] = balance;
							cb2(new Decimal(balance));
						}
					);
				}
```

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
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

**File:** test/samples/uniswap_like_market_maker.oscript (L33-66)
```text
			{ // invest in MM
				if: `{$mm_asset AND trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] > 0}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
						$issue_amount = balance[base];
						return;
					}
					$current_ratio = $asset_balance / $bytes_balance;
					$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
					if ($expected_asset_amount != trigger.output[[asset=$asset]])
						bounce('wrong ratio of amounts, expected ' || $expected_asset_amount || ' of asset');
					$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
					$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$mm_asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $issue_amount }"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] += $issue_amount;
						}`
					},
				]
			},
```
