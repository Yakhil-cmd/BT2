### Title
Deterministic AA addresses can be poisoned with attacker balances before the AA is defined, corrupting `balance[]`-based AA logic - ([File: storage.js])

### Summary
Autonomous Agent (AA) addresses in Obyte are deterministic hashes of their definition (`chash160`), so an AA's future address can be known and paid to before its defining unit is even posted or stable. Any unprivileged user can send a payment of an arbitrary asset to that not-yet-existing AA address. When the AA's definition finally stabilizes, `insertAADefinitions` sweeps up *all* prior unspent outputs sent to that address into `aa_balances`, with no restriction on sender or asset. AA formulas that trust `balance[asset]` as an economically meaningful figure (e.g. bonding-curve/AMM style AAs) can then have their calculations corrupted by this attacker-injected "pre-existing" balance, exactly mirroring the Teller `commitCollateral` pattern of trusting state tied to an ID/address before validating that the entity legitimately exists.

### Finding Description
AA addresses are computed as `objectHash.getChash160(definition)` and are fully deterministic and publicly computable before the AA is ever posted on-chain, as shown throughout the test suite where the address is derived off-chain (`objectHash.getChash160(child_aa)`) and then paid before the defining unit is even sent [1](#0-0) .

When the defining `definition` message eventually stabilizes, `insertAADefinitions` in `storage.js` inserts a fresh `aa_addresses` row and then aggregates **every** prior unspent, good-sequence, non-private output ever sent to that address — regardless of who sent it or what asset it is — into `aa_balances`: [2](#0-1) 

This accounting is unconditional on the sender being the AA's "intended" counterpart; any address in the DAG, including one controlled entirely by an attacker, can send any asset to the not-yet-existing AA address and have it counted as the AA's balance the moment the AA becomes active.

That balance is not an inert bookkeeping number — it is directly exposed to AA (o)script logic via the `balance[...]` operator, which reads straight from `objValidationState.assocBalances` / `aa_balances`: [3](#0-2) 

Many real AA patterns explicitly use `balance[asset]` to drive economically sensitive computations, such as AMM/bonding-curve pricing and pro-rata share payouts: [4](#0-3) [5](#0-4) 

Because `insertAADefinitions` never distinguishes "balance contributed by legitimate triggers/counterparties" from "balance dumped in by an attacker before the AA existed," an attacker who can predict a future AA's address (which is always possible, since the address is a pure function of the public definition) can pre-fund it with an arbitrary amount of an arbitrary (including malicious/rebasing-style) asset before the AA is deployed. This is the same root-cause pattern as the Teller report: state tied to an identifier that is knowable/reachable before the identified entity is validated to legitimately exist, allowing poisoning of assumptions later relied upon by legitimate logic.

### Impact Explanation
An AA whose logic assumes `balance[asset]` reflects only balances contributed through its own trigger-response accounting (e.g. bonding-curve AMMs, revenue-sharing AAs, "distribute my full balance of asset X" AAs) can have its internal invariants corrupted by attacker-injected pre-existing balance. Depending on the AA's formula, this can let the attacker extract more funds than deposited (skewing constant-product / share calculations), freeze the AA (breaking an invariant check that expects balance to equal a locally-tracked total), or otherwise misdirect AA fund flows — a concrete AA fund loss/freezing scenario reachable by any unprivileged unit poster.

### Likelihood Explanation
Likelihood is high for any AA design that is deployed via a known/predictable definition (e.g. factory-created AAs, template AAs, or any AA whose source/definition is published before being sent on-chain) and that uses `balance[asset]` in its pricing/share logic — a documented and encouraged pattern (see the bundled uniswap-like market-maker sample). The attacker only needs to know the AA's definition (or observe it while a defining unit is still unstable) and send a single payment before the AA stabilizes; no special privileges or race against validators are required.

### Recommendation
When an AA becomes active, avoid silently merging arbitrary pre-existing outputs from unrelated senders into `aa_balances` as fungible, trusted balance. Consider: (1) crediting to `aa_balances` only assets that are relevant to a discoverable "expected asset set" declared by the AA, or (2) exposing pre-AA-existence balances separately from balances accrued via normal trigger processing so AA authors can explicitly opt into trusting or rejecting them, or (3) documenting and strongly warning AA authors that `balance[asset]` may include attacker-controlled donations made before deployment, and requiring AAs that rely on `balance[]` for pricing to reconcile it against locally tracked state vars rather than the raw balance.

### Proof of Concept
1. Publish (or simply construct off-chain) an AMM-style AA definition `D` whose pricing formula uses `balance[$asset]` and `balance[base]` (as in `test/samples/uniswap_like_market_maker.oscript`).
2. Compute `address = chash160(D)` — this can be done by anyone without posting anything on-chain.
3. Before `D` is posted/stabilized as an AA (or while its defining unit is still unstable), send a payment of amount `X` of an attacker-chosen asset to `address` from an ordinary (non-AA) address.
4. Once `D`'s defining unit stabilizes, `insertAADefinitions` (storage.js:944-962) sums this output into `aa_balances[address][asset] = X`, with no association to any legitimate trigger.
5. Any subsequent legitimate trigger to the AA evaluates `balance[asset]` (formula/evaluation.js:1510-1528) including the attacker's pre-loaded `X`, skewing the AMM's constant-product invariant and letting the attacker extract more value than a legitimate counterparty deposited, or breaking any invariant checks that assume `balance[asset]` only reflects tracked deposits.

### Citations

**File:** test/aa_composer.test.js (L922-943)
```javascript
test.cb.serial('AA with generated definition of new AA and immediately sending to this new AA', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { x: 5 }, address: trigger_address };

	var child_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		doc_url: 'https://myapp.com/description.json',
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					init: "{response['received_amount'] = trigger.output[[asset=base]];}",
					outputs: [
						{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
					]
				}
			}
		]
	}];
	var child_aa_address = objectHash.getChash160(child_aa);
	
```

**File:** storage.js (L944-962)
```javascript
					var verb = bAlreadyPostedByUnconfirmedAA ? "REPLACE" : "INSERT";
					// pre-fix, the defining AA unit's own outputs are already in the outputs table and would be double-counted with its secondary trigger
					const or_sent_by_aa = (bAlreadyPostedByUnconfirmedAA || mci >= constants.pemCurvesFixMci) ? "OR is_aa_response=1" : "";
					// for AA-defined AAs, mci is the trigger mci whose triggers were already selected before this AA existed, so outputs on this mci can never trigger it and must be counted here.
					// Also count payments from other AA responses (never primary triggers) except the defining unit's own, which arrives as a secondary trigger
					const bImmediatelyVisible = bForAAsOnly && mci >= constants.pemCurvesFixMci;
					const mci_cond = bImmediatelyVisible
						? "(main_chain_index<=? OR is_aa_response=1) AND outputs.unit!=?"
						: "(main_chain_index<? " + or_sent_by_aa + ")"; // "<" for regular AAs, not including the outputs on the current mci, which will trigger the AA and be accounted for separately; is_aa_response=1 captures outputs to the not-yet-AA by AA responses
					const params = bImmediatelyVisible ? [address, mci, unit] : [address, mci];
					conn.query(
						verb + " INTO aa_balances (address, asset, balance) \n\
						SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) AS balance \n\
						FROM outputs \n\
						CROSS JOIN units USING(unit) \n\
						LEFT JOIN assets ON asset=assets.unit \n\
						WHERE address=? AND is_spent=0 AND sequence='good' AND " + mci_cond + " AND (is_private=0 OR is_private IS NULL) \n\
						GROUP BY address, asset",
						params,
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

**File:** test/samples/uniswap_like_market_maker.oscript (L102-123)
```text
			{ // exchange bytes to asset
				if: `{trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] == 0 AND var['mm_asset_outstanding']}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_asset_balance = round($p / balance[base]);
					$amount = $asset_balance - $new_asset_balance; // we can deduct exchange fees here
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
```

**File:** test/ojson.test.js (L1453-1470)
```javascript
						{ // divest MM shares
							// (user is already paying 10000 bytes bounce fee which is a divest fee)
							// the price slightly moves due to fees received and paid in bytes
							if: `{$mm_asset AND trigger.output[[asset=$mm_asset]]}`,
							init: `{
					$mm_asset_amount = trigger.output[[asset=$mm_asset]];
					$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
				}`,
							messages: [
								{
									app: 'payment',
									payload: {
										asset: "{$asset}",
										outputs: [
											{address: "{trigger.address}", amount: "{ round($investor_share * balance[$asset]) }"}
										]
									}
								},
```
