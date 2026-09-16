## Analog Found

### Title
Private Textcoin Claim Permanently Blocked by Stale Pre-Funded TPS/Claim Fee - ([File: wallet.js])

### Summary
`sendMultiPayment()` funds a one-time textcoin address with a *fixed* fee estimate computed once, at send time (`constants.TEXTCOIN_ASSET_CLAIM_FEE` / `TEXTCOIN_CLAIM_FEE` plus `2 * estimateTpsFee(...)`), and stores that amount on the textcoin address. Later, the recipient's only mechanism to redeem the funds, `receiveTextCoin()`, spends exclusively from that pre-funded amount when the asset is private, exactly mirroring the vulndb pattern of a "slow/only path" that hard-codes a fee value (there `maxFee=0`, here a once-computed `tps_fee`/claim-fee) instead of recomputing it against present network conditions at execution time.

### Finding Description
When a private-asset textcoin is created, `addFeesToParams()` pre-computes the required claim fee at send time as a *fixed* value: [1](#0-0) 
including a dynamically-estimated TPS fee, `2 * composer.estimateTpsFee(...)`, sampled once at the moment of sending: [2](#0-1) 

`composer.estimateTpsFee()` and the equivalent logic inside `composeJoint()` compute the TPS fee from the *current* network throughput (`getCurrentTps`), which can rise over time as usage grows: [3](#0-2) [4](#0-3) 

When the recipient later calls `receiveTextCoin()` to redeem a private asset, the code sets `opts._private = true` and restricts spending to the textcoin address itself: [5](#0-4) 

If the actual TPS fee (or other v4 fees such as `oversize_fee`) required at claim time exceeds what was pre-funded — because network TPS increased between send and claim, or because `base_tps_fee`/`tps_fee_multiplier` system vars changed — `composeAndSaveDivisibleAssetPaymentJoint`/`composeAndSaveIndivisibleAssetPaymentJoint` will fail with "not enough funds". Critically, the `ifNotEnoughFunds` handler explicitly refuses to retry with an additional fee-paying address specifically because the payment is private: [6](#0-5) 

This is the direct analog of the reported bug class: a value hard-coded/frozen at composition time (`maxFee=0` in the original report, a stale pre-funded `tps_fee`/claim fee here) is checked against a dynamically-computed, always-increasing-over-time requirement, and the *only* redemption path for this class of transfer (private asset, no alternate fee payer allowed by design) has no way to top up the fee. The recipient is permanently unable to claim the private textcoin.

### Impact Explanation
The private-asset textcoin's underlying value becomes permanently unclaimable/frozen whenever network TPS-fee levels rise (even modestly) after the textcoin was sent, since privacy requirements prevent adding a second fee-paying address. This is a fund-freezing condition reachable by any unprivileged private-payment counterparty (the textcoin recipient), matching the "AA fund loss or freezing" / stuck-funds class called out in the validation rules.

### Likelihood Explanation
TPS fees in ocore rise automatically with increased network throughput (`getCurrentTps`), so any textcoin that sits unclaimed for a period during which usage grows is at risk, especially since textcoins are explicitly designed to be redeemable at an arbitrary later time (there is even a `claimBackOldTextcoins` function for old, unclaimed textcoins) and private textcoins cannot be topped up by third parties by design. No attacker action is required — a normal usage pattern (delayed claim) triggers it.

### Recommendation
- When composing a private-asset textcoin, recompute and re-validate the required TPS fee (and any other v4 dynamic fee) against current network conditions at claim time, not only at send time.
- Alternatively, allow the recipient (or sender, via a refund/reclaim mechanism) to top up the textcoin address with additional bytes for fees without revealing/breaking the privacy properties of the claim, e.g., by permitting fee-only funding of the address that does not participate in the private payment chain.
- Consider capping/monitoring the drift between the fee reserved at send time and the fee required at claim time, and surfacing an explicit, actionable error/retry path instead of a silent permanent failure.

### Proof of Concept
1. Send a private-asset textcoin via `sendMultiPayment` with `nonbaseAsset` private and a recipient mnemonic; `addFeesToParams` funds the textcoin address with `TEXTCOIN_ASSET_CLAIM_FEE (+HEADER/MESSAGE/BASE fees for indivisible)` plus `2 * estimateTpsFee(...)` sampled at that moment (`wallet.js:2312-2358`).
2. Wait until real network TPS (and hence `getCurrentTpsFee`/`getCurrentTpsFeeToPay`) has risen meaningfully, or `base_tps_fee`/`tps_fee_multiplier` system vars are updated upward.
3. Recipient calls `receiveTextCoin(mnemonic, addressTo, ...)`; since `objAsset.is_private` is true, `opts._private = true` and `opts.fee_paying_addresses = [addrInfo.address]` only (`wallet.js:2765-2772`).
4. `composeAndSave(Indivisible|Divisible)AssetPaymentJoint` recomputes the current TPS fee inside `composeJoint`/`estimateTpsFee`, now higher than what was pre-funded, and returns "not enough funds".
5. `ifNotEnoughFunds` sees `opts._private` and explicitly refuses to retry with a locally-funded address (`wallet.js:2699-2703`), calling back with a permanent error — the private textcoin's value is now stuck forever.

### Citations

**File:** wallet.js (L2312-2327)
```javascript
			var addFeesToParams = async function (objAsset) {
				// iterate over all generated textcoin addresses
				for (var orig_address in assocAddresses) {
					var new_address = assocAddresses[orig_address];
					const tps_fee = 2 * (await composer.estimateTpsFee([new_address], [new_address]));
					console.log(`will add tps fee ${tps_fee} to the textcoin`);
					var _addAssetFees = function() {
						var asset_fees = objAsset && objAsset.fixed_denominations ? indivisibleAssetFeesByAddress[new_address] : constants.TEXTCOIN_ASSET_CLAIM_FEE;
						asset_fees += tps_fee;
						if (!params.base_outputs) params.base_outputs = [];
						var base_output = _.find(params.base_outputs, function(output) {return output.address == new_address});
						if (base_output)
							base_output.amount += asset_fees;
						else
							params.base_outputs.push({address: new_address, amount: asset_fees});
					}
```

**File:** wallet.js (L2697-2710)
```javascript
	opts.callbacks = {
		ifNotEnoughFunds: function(err){
			if (opts.fee_paying_addresses && opts.fee_paying_addresses.length === 1) {
				if (opts._private)
					console.log(`not enough funds on the textcoin ${addrInfo.address}, will not retry with fees paid from my own address because the payment is private`);
				else if (!signWithLocalPrivateKey)
					console.log(`not enough funds on the textcoin ${addrInfo.address}, will not retry with fees paid from my own address because a local signer has not been provided`);
				else {
					console.log(`not enough funds on the textcoin ${addrInfo.address}, will add my own address to fee_paying_addresses`);
					opts.fee_paying_addresses.push(addressTo);
					return checkStability();
				}
			}
			cb("Not enough funds on the textcoin " + addrInfo.address);
```

**File:** wallet.js (L2765-2772)
```javascript
					else { // claim only the 1st asset
						opts.asset = asset;
						opts.amount = row.amount;
						opts.to_address = addressTo;
						opts._private = true; // to prevent retries with fees paid by the recipient
					}
					if (!opts.fee_paying_addresses)
						opts.fee_paying_addresses = [addrInfo.address];
```

**File:** composer.js (L374-394)
```javascript
					if (last_ball_mci >= constants.v4UpgradeMci) {
						const rows = await conn.query("SELECT 1 FROM aa_addresses WHERE address IN (?)", [arrOutputAddresses]);
						const count_primary_aa_triggers = rows.length;
						const tps_fee = await parentComposer.getTpsFee(conn, arrParentUnits, last_stable_mc_ball_unit, objUnit.timestamp, 1 + count_primary_aa_triggers * max_aa_responses);
						let recipients = storage.getTpsFeeRecipients(storage.ehcr2assoc(objUnit.earned_headers_commission_recipients), arrFromAddresses);
						if (!recipients[arrFromAddresses[0]]) // for backward compatibility with the old buggy getTpsFeeRecipients
							recipients[arrFromAddresses[0]] = 100;
						let paid_tps_fee = 0;
						for (let address in recipients) {
							const share = recipients[address] / 100;
							const [row] = await conn.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [address, last_ball_mci]);
							const tps_fees_balance = row ? row.tps_fees_balance : 0;
							console.log('composer', {address, tps_fees_balance, tps_fee})
							const addr_tps_fee = Math.ceil(tps_fee - tps_fees_balance / share);
							if (addr_tps_fee > paid_tps_fee)
								paid_tps_fee = addr_tps_fee;
						}
						objUnit.tps_fee = paid_tps_fee;
						if (count_primary_aa_triggers && typeof params.max_aa_responses === "number")
							objUnit.max_aa_responses = params.max_aa_responses;
					}
```

**File:** composer.js (L604-631)
```javascript
async function estimateTpsFee(arrFromAddresses, arrOutputAddresses) {
//	if (storage.getMinRetrievableMci() < constants.v4UpgradeMci)
//		return 0;
	const max_aa_responses = constants.MAX_RESPONSES_PER_PRIMARY_TRIGGER;
	const arrWitnesses = storage.getOpList(Infinity);
	if (conf.bLight) {
		const network = require('./network.js');
		const response = await network.requestFromLightVendor('light/get_parents_and_last_ball_and_witness_list_unit', {
			witnesses: arrWitnesses,
			from_addresses: arrFromAddresses,
			output_addresses: arrOutputAddresses,
			max_aa_responses,
		});
		return (response.last_stable_mc_ball_mci >= constants.v4UpgradeMci) ? response.tps_fee : 0;
	}
	const timestamp = Math.round(Date.now() / 1000);
	const { arrParentUnits, last_stable_mc_ball_unit, last_stable_mc_ball_mci } =
		await parentComposer.pickParentUnitsAndLastBall(db, arrWitnesses, timestamp, arrFromAddresses);
	if (last_stable_mc_ball_mci < constants.v4UpgradeMci)
		return 0;
	const rows = await db.query("SELECT 1 FROM aa_addresses WHERE address IN (?)", [arrOutputAddresses]);
	const count_primary_aa_triggers = rows.length;
	const tps_fee = await parentComposer.getTpsFee(db, arrParentUnits, last_stable_mc_ball_unit, timestamp, 1 + count_primary_aa_triggers * max_aa_responses);
	// in this implementation, tps fees are paid by the 1st address only
	const [row] = await db.query("SELECT tps_fees_balance FROM tps_fees_balances WHERE address=? AND mci<=? ORDER BY mci DESC LIMIT 1", [arrFromAddresses[0], last_stable_mc_ball_mci]);
	const tps_fees_balance = row ? row.tps_fees_balance : 0;
	return Math.max(tps_fee - tps_fees_balance, 0);
}
```
