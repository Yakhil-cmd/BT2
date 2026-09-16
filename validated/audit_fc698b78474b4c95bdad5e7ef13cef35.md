### Title
Manipulable spot-price primitive `balance[address][asset]` enables atomic price-oracle manipulation of AA-based liquidity pools - (File: formula/evaluation.js)

### Summary
The oscript `balance[address][asset]` primitive returns the *live, instantaneous* reserve balance of any AA, and this value is routinely used (as demonstrated in ocore's own reference pattern, `uniswap_like_market_maker.oscript`) to derive an on-the-fly exchange rate for swaps and collateral valuation. Because AA-to-AA calls execute atomically and deterministically within the processing of a single triggering unit, an attacker can skew an AA's reserve ratio with a large trade and have a second, chained AA read that skewed `balance[]` as a price signal in the same atomic sequence — the same class of bug that let the Vesper Finance attacker manipulate a Uniswap V3 pool price and over-borrow against VUSD collateral.

### Finding Description
`balance[address][asset]` is implemented in `formula/evaluation.js`'s `case 'var': case 'balance':` handler. When an address parameter is supplied, it reads `objValidationState.assocBalances[param_address][bal_asset]`, falling back to the current `aa_balances` DB row via `readBalance()`: [1](#0-0) 

This is a pure spot balance with no time-weighting, no minimum-observation window, and no manipulation resistance — unlike Vesper's underlying Uniswap V3 pool, which at least had TWAP but was still exploitable via sustained liquidity draining; ocore's `balance[]` has *no* such mitigation at all.

Any AA author can build a liquidity/AMM-style AA that prices swaps purely from live reserves, exactly as shown in ocore's own documented sample: [2](#0-1) 

The `$current_ratio = $asset_balance / $bytes_balance` and constant-product `$p = $asset_balance * $bytes_balance` formulas are computed straight off `balance[$asset]`/`balance[base]`.

Critically, ocore's AA composer allows an AA to call another AA synchronously and atomically within the handling of a single primary trigger unit — before the unit is even stable — via `handleSecondaryTriggers`: [3](#0-2) 

and balances used by subsequent chained triggers are updated in-memory immediately after each response, as seen in `sendDummyUnit`: [4](#0-3) 

So a single attacker-authored trigger unit can:
1. Send a large payment into a liquidity-pool AA (via message A) to skew its `balance[asset]`/`balance[base]` ratio.
2. Chain to a second AA (via a secondary trigger from the pool AA's response, or via a separate payment output processed in the same unit) that reads `balance[pool_aa_address][asset]` as its price/collateral oracle to mint/borrow/issue against an inflated valuation.
3. Optionally reverse the initial trade in the same or an immediately following atomic response chain, restoring the ratio.

Because all of this happens deterministically and atomically as part of processing one unit (no other party can interleave a transaction inside that same unit's AA response chain), the attacker fully controls the "price" observed by the downstream AA at the moment it is read — directly analogous to the Vesper attacker manipulating the VUSD/USDC Uniswap V3 pool price before it was consumed by VesperLend's Rari Fuse pool oracle.

### Impact Explanation
Any AA that uses another AA's live `balance[]` (or a self-referential live balance ratio) as a valuation input for minting, lending, or asset-swap pricing is exposed to atomic spot-price manipulation. This can cause direct fund loss/drain from that AA (over-minting of an asset, under-collateralized borrowing, or a favorable swap executed at a manipulated rate), which constitutes concrete unauthorized spending / AA fund loss, matching the High-severity category of the source incident. The `balance[]` primitive itself is the root cause and offers no built-in protection, so the risk applies to the general class of AA-based liquidity/lending contracts recommended by ocore's own reference implementation, not a single misconfigured contract.

### Likelihood Explanation
Likelihood is high for AAs that follow the documented AMM pattern (`balance[$asset]/balance[base]` spot pricing) because:
- The attack requires only posting units/triggers, well within reach of an unprivileged AA trigger sender.
- No cross-unit timing, hub cooperation, or privileged access is needed — everything executes atomically inside a single unit's AA response chain via `handleSecondaryTriggers`.
- The oscript language and its official sample code encourage this exact pricing pattern without any warning or built-in TWAP/oracle-safety mechanism.

### Recommendation
- Document and strongly discourage using instantaneous `balance[]`-derived ratios as authoritative prices for lending/collateral decisions in any AA that interacts with externally-composable liquidity.
- Consider providing a built-in TWAP or checkpointed balance/price primitive (e.g., balance sampled only from stable/older MCI, or an average over a window) that AA authors can use instead of raw live `balance[]`, mirroring the mitigations DeFi protocols adopted after this class of incident.
- Audit/deprecate the `uniswap_like_market_maker.oscript` sample so it is not treated as production-safe guidance, or add explicit oracle-manipulation caveats.

### Proof of Concept
Conceptually (using ocore's own sample AMM pattern):
1. Author AA `P` (pool) per `uniswap_like_market_maker.oscript`, pricing swaps via `balance[$asset]/balance[base]`.
2. Author AA `L` (lender) that reads `balance[P][asset]` (or an equivalent ratio) via the `var`/`balance` primitive at `formula/evaluation.js:1481-1528` to value collateral for issuing a loan asset.
3. Attacker constructs one trigger unit containing:
   - Message 1: large payment into `P` to skew `asset_balance` vs `bytes_balance`.
   - Message 2 (or a chained secondary trigger reachable via `handleSecondaryTriggers`, `aa_composer.js:1702-1741`): payment/trigger into `L` that reads the now-skewed `balance[P][...]` and mints/lends against the inflated valuation.
4. Attacker's chain reverses the swap in `P` (same unit or immediate follow-up chain) restoring price, keeping the over-minted/over-borrowed proceeds from `L`.

This mirrors the Vesper Finance flow: manipulate the pool's live-reserve price via a large swap, then have a dependent lending/valuation logic consume that manipulated price before it can normalize.

### Citations

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

**File:** test/samples/uniswap_like_market_maker.oscript (L102-122)
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
```

**File:** aa_composer.js (L958-978)
```javascript
			// update balances
			var arrOutputAddresses = [];
			messages.forEach(message => {
				if (message.app !== 'payment')
					return;
				var asset = message.payload.asset || 'base';
				message.payload.outputs.forEach(output => {
					if (output.amount !== 0 && arrOutputAddresses.indexOf(output.address) === -1)
						arrOutputAddresses.push(output.address);
					if (!trigger_opts.assocBalances[address][asset])
						trigger_opts.assocBalances[address][asset] = 0;
					if (output.amount === undefined) // send all
						output.amount = trigger_opts.assocBalances[address][asset];
					// deduct from this AA's balance. It can get negative if we are issuing coins but in this case balance[] is probably meaningless
					trigger_opts.assocBalances[address][asset] -= output.amount;
				});
			});
			if (arrOutputAddresses.length === 0)
				return finish(objUnit);
			if (trigger_opts.assocBalances[address].base < 0)
				return bounce("not enough balance in base");
```

**File:** aa_composer.js (L1702-1741)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
```
