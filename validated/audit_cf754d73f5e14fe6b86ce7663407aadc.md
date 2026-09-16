## Analog Found

### Title
Attestation-gated asset transfers force AA/payment operations to permanently fail when the recipient is de-attested, mirroring the Cooler blacklist-forced-default pattern - (File: `validation.js`, `aa_composer.js`)

### Summary
The Sherlock report describes a pattern where a mandatory, unconditional payment to a fixed counterparty address (the lender) is a hard precondition for completing an operation (repay). If that counterparty becomes unable to receive the token (blacklisted), the whole operation permanently reverts, and the victim loses value that was supposed to be released atomically with the payment (their collateral).

`ocore` has a structurally identical mechanism for `spender_attested` assets: any payment output must go to an address that is currently attested by the asset's attestor list, or the entire payment message — and therefore the whole unit — is rejected.

### Finding Description
For assets defined with `spender_attested: true`, every payment (public or private, including inside an AA response) must satisfy an attestation check on the output addresses, enforced in `validatePaymentInputsAndOutputs`: [1](#0-0) 

The same requirement is checked on the input/spending side as well ("owner address is not attested"): [2](#0-1) 

Attestation status is derived from a mutable, off-chain-controlled table (`attestations`), filtered live via `filterAttestedAddresses`/`loadAssetWithListOfAttestedAuthors`. Anyone with attestor authority for the asset can add or effectively invalidate an address's attestation at any time by not re-attesting after a `address_definition_change`, which the check explicitly accounts for: [3](#0-2) [4](#0-3) 

Critically, when an Autonomous Agent (AA) composes a response that includes a payment of a `spender_attested` asset to a counterparty address, the AA composer (`aa_composer.js`) only checks that the *AA's own address* is attested when loading asset info — it does not verify that the *recipient* output address is attested before building the unit: [5](#0-4) 

If the recipient's attestation is missing or has been revoked by the attestor at the time the unit is actually validated (which can happen after the AA already computed and "committed" its state transition in the same trigger-handling pass), the resulting unit fails the standard `spender_attested` output check in `validation.js` (`"some output addresses are not attested"`). This causes `sendUnit`'s validation-driven failure path to trigger `bounce()`: [6](#0-5) 

`bounce()` restores all state variables and balances to their pre-trigger values (`assignObject(stateVars, originalStateVars)` / `assignObject(trigger_opts.assocBalances, originalBalances)`), i.e. it reverts *the entire atomic operation*, not just the failing payment. This is the direct analog of Cooler's `repay()`: a single mandatory transfer to a party who has made themselves unable to receive the asset (via de-attestation, the ocore equivalent of a token blacklist) causes the whole bundled operation — including any state change that was supposed to happen atomically with that payment (e.g., releasing collateral, closing a position, unlocking funds) — to fail/roll back.

The same root cause also blocks ordinary (non-AA) payments and private payment chains: if a payment chain step's output address loses attestation before the chain is finalized/stable, the payment permanently fails validation and any escrowed/committed value tied to that specific payment (e.g., in an `arbiter_contract.js`-style shared address deal expecting the debt-equivalent payment to complete) can become stuck, forcing a default-like outcome for the other counterparty.

### Impact Explanation
- In an AA-mediated deal (e.g., an escrow/lending/marketplace AA) where a `spender_attested` asset payout to a counterparty is bundled with a state update (e.g., releasing collateral or marking a loan/deal as settled), the counterparty that controls attestation (or colludes with the attestor) can revoke/withhold the recipient's attestation to force `bounce()`, reverting the whole response and preventing the honest party from ever finalizing the operation — exactly the "forced default" scenario in the report.
- For non-AA private/public payment chains, an untrusted counterparty acting as attestor (or colluding with one) can make itself permanently un-payable for a specific settlement, freezing funds that were supposed to be released together with that payment.
- This is a fund-freezing/AA state-rollback issue reachable by a normal unit/trigger poster or asset counterparty, matching the "AA fund loss or freezing" acceptance criterion.

### Likelihood Explanation
This requires an asset configured with `spender_attested: true` and an AA (or payment chain) that combines a payment of such an asset to a counterparty-controlled address with an atomic state change. Since attestor lists are freely definable by the asset definer, and any party colluding with (or acting as) the attestor for their own address can revoke their own attestation, the "self-blacklisting" precondition from the original report (recipient makes themselves unpayable) is directly reproducible. The likelihood is Medium: it depends on specific AA/asset design choices (using `spender_attested` assets for value bundled with irreversible state transitions), but is not exotic — `spender_attested` is a first-class, documented asset feature intended for regulated/KYC-style assets, which are exactly the assets likely to be paired with lending/marketplace AAs.

### Recommendation
- For AA logic that sends `spender_attested` (or otherwise conditionally-blockable) assets bundled with an irreversible state transition, decouple the state transition from the transfer: record a claimable balance for the counterparty (state var) instead of unconditionally emitting the payment output, and let the counterparty pull funds once they satisfy the attestation/other conditions — mirroring the report's suggested fix of moving from push-payments to a `withdrawBalance` pull pattern.
- Alternatively, before bundling a `spender_attested` payment in an AA response, explicitly verify recipient attestation status (as is already done for the AA's own address in `aa_composer.js`) and branch to a safe fallback (e.g., escrow/claim state) rather than allowing the entire trigger response, including unrelated state changes, to bounce.

### Proof of Concept
1. Definer creates an asset `A` with `spender_attested: true` and attestor list `[Attestor]`.
2. An AA `Deal` is designed so that, upon a trigger, it (a) releases "collateral"-equivalent value/state (e.g., sets `var['settled']=true`, unlocks some other asset/state) and (b) in the same response, pays asset `A` to `counterparty_address`, which is currently attested by `Attestor`.
   - Composition path: `aa_composer.js` `handleTrigger` → `sendUnit` → per-message loop at [7](#0-6)  loads asset info (checking only the AA's own attestation) and composes the payment output to `counterparty_address` without checking that address's attestation.
3. Before the AA-generated unit becomes stable/validated, `Attestor` (who may be the same party as `counterparty_address`, or colludes with it) stops re-attesting `counterparty_address` after an `address_definition_change`, or never attested it in the first place for this specific spend.
4. Standard unit validation of the AA-produced payment message hits [1](#0-0)  and returns `"some output addresses are not attested"`.
5. This propagates as an error into `sendUnit`'s completion callback, invoking `bounce()` at [8](#0-7) , which restores `stateVars` and balances to their pre-trigger state — reverting the "collateral release"/settlement state change that was supposed to happen atomically with the payment.
6. The counterparty can repeat this at will for any trigger that would otherwise finalize the deal, permanently preventing settlement while retaining whatever leverage the un-finalized state gives them — the functional equivalent of forcing the Cooler loan into default by blacklisting the lender's own receiving address.

### Citations

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
```

**File:** validation.js (L2630-2641)
```javascript
				async.series([
					function(cb){
						if (!objAsset.spender_attested)
							return cb();
						storage.filterAttestedAddresses(
							conn, objAsset, objValidationState.last_ball_mci, arrOutputAddresses, 
							function(arrAttestedOutputAddresses){
								if (arrAttestedOutputAddresses.length !== arrOutputAddresses.length)
									return cb("some output addresses are not attested");
								cb();
							}
						);
```

**File:** storage.js (L1959-1974)
```javascript
// filter only those addresses that are attested (doesn't work for light clients)
function filterAttestedAddresses(conn, objAsset, last_ball_mci, arrAddresses, handleAttestedAddresses){
	conn.query(
		"SELECT DISTINCT address FROM attestations CROSS JOIN units USING(unit) \n\
		WHERE attestor_address IN(?) AND address IN(?) AND main_chain_index<=? AND is_stable=1 AND sequence='good' \n\
			AND main_chain_index>IFNULL( \n\
				(SELECT main_chain_index FROM address_definition_changes JOIN units USING(unit) \n\
				WHERE address_definition_changes.address=attestations.address AND main_chain_index<=? AND is_stable=1 AND sequence='good' ORDER BY main_chain_index DESC LIMIT 1), \n\
			0)",
		[objAsset.arrAttestorAddresses, arrAddresses, last_ball_mci, last_ball_mci],
		function(addr_rows){
			var arrAttestedAddresses = addr_rows.map(function(addr_row){ return addr_row.address; });
			handleAttestedAddresses(arrAttestedAddresses);
		}
	);
}
```

**File:** storage.js (L1977-1991)
```javascript
function loadAssetWithListOfAttestedAuthors(conn, asset, last_ball_mci, arrAuthorAddresses, bAcceptUnconfirmedAA, handleAsset){
	if (arguments.length === 5) {
		handleAsset = bAcceptUnconfirmedAA;
		bAcceptUnconfirmedAA = false;
	}
	readAsset(conn, asset, last_ball_mci, bAcceptUnconfirmedAA, function(err, objAsset){
		if (err)
			return handleAsset(err);
		if (!objAsset.spender_attested)
			return handleAsset(null, objAsset);
		filterAttestedAddresses(conn, objAsset, last_ball_mci, arrAuthorAddresses, function(arrAttestedAddresses){
			objAsset.arrAttestedAddresses = arrAttestedAddresses;
			handleAsset(null, objAsset);
		});
	});
```

**File:** aa_composer.js (L909-945)
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
	}
```

**File:** aa_composer.js (L1312-1344)
```javascript
				var payload = message.payload;
				if (payload.asset === 'base')
					delete payload.asset;
				var asset = payload.asset || null;
				if (asset === null) {
					if (objBasePaymentMessage)
						return cb("already have base payment");
					objBasePaymentMessage = message;
					// we'll add output addresses later, after possibly removing a send-all output
					return cb(); // skip it for now, we can estimate the fees only after all other messages are in place
				}
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
					completePaymentPayload(payload, 0, function (err) {
						if (err)
							return cb(err);
						addOutputAddresses(payload.outputs);
						if (payload.outputs.length > 0) // send-all output might get removed while being the only output
							try {
								completeMessage(message);
							}
							catch (e) {
								return cb("completeMessage failed: " + e.toString());
							}
						cb();
					});
				});
```
