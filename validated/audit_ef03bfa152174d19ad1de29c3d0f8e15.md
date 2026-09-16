### Title
Reserve/price manipulation of AA constant-product market makers via unaccounted "donation" payments merged into unrelated cases - ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The XDKRecycle exploit worked because the vulnerable token let anyone push tokens directly into a Pancake pair and sync/skim it, silently changing the reserves that the AMM's constant-product pricing relies on, without going through the fee-checked `swap()` path. The equivalent reachable pattern in ocore is the reference constant‑product "Uniswap‑like market maker" AA pattern (`test/samples/uniswap_like_market_maker.oscript`), where an AA's `balance[asset]`/`balance[base]` are trusted as the "reserves" for pricing, but the AA's case-matching logic lets an unprivileged trigger sender attach extra, unrelated-asset outputs to a payment that matches an unrelated case (e.g. "divest"), so those extra funds are silently absorbed into the AA's balance/reserve without being priced or accounted for by that case's logic — a direct analog of the "recycle"/"skim" donation trick used against XDK.

### Finding Description
Any AA's per-asset balance (`aa_balances`, exposed via the `balance[...]` operator) is updated with **all** outputs of a triggering unit before any case logic runs: [1](#0-0) 
This means the full set of payments sent to the AA in a single unit is credited to its balance unconditionally, regardless of which `if` case ends up matching and regardless of whether that case's logic "expects" or accounts for every asset received.

In the shipped market-maker template, the case selection is based only on the presence of specific outputs, not exclusivity of the trigger's full output set. In particular, the "divest MM shares" case only checks that an `mm_asset` output was received: [2](#0-1) 
and pays out only a proportional `$investor_share` of the pool computed from a tiny `mm_asset` amount, while any other simultaneously attached asset/base amount included in the very same unit is not referenced anywhere in this case's formula, yet was already merged into `balance[$asset]`/`balance[base]` by `updateInitialAABalances`.

The "exchange" cases that implement the actual constant-product price then trust these same balances as the reserves: [3](#0-2) [4](#0-3) 
So an unprivileged trigger sender can, in a single unit, attach a negligible `mm_asset` output (to route into the "divest" case) together with a large `base` (or asset) output that the divest case does not price or refund — inflating `balance[base]` (or `balance[$asset]`) for free, exactly as the attacker in the report inflated/drained the XDK/GPC pair reserve by transferring tokens directly into the pair and calling `skim`/`sync` outside of the metered swap path.

This reserve read is not confined to the AA's own state: any other AA can query it cross-address via the two-parameter `balance[address][asset]` operator: [5](#0-4) 
and ocore executes chains of AAs triggered from the same unit atomically, within one stabilized unit, via `handleSecondaryTriggers`: [6](#0-5) 
This gives an attacker the same "flash swap" atomicity primitive used in the report: manipulate the market maker's implied reserves and consume/act on the skewed price in one and the same unit, with no possibility for anyone to intervene in between.

### Impact Explanation
Any AA built on this documented constant-product pattern (or any other AA/oracle consumer that reads its `balance[]` as a spot price) can have its reserves skewed by an unprivileged trigger sender for free, by piggy-backing unrelated outputs on a case whose formula does not fully account for every asset in the trigger. Because ocore processes AA chains atomically within a single stabilized unit, this manipulation and its exploitation (e.g., trading against the skewed price, or feeding a distorted price to a dependent AA) can be done in one atomic step, mirroring the flash-swap sandwich in the reported exploit and leading to fund loss for LPs/dependent AAs.

### Likelihood Explanation
The vulnerable pattern is the officially documented "Uniswap-like market maker" sample distributed with ocore (`test/samples/uniswap_like_market_maker.oscript`) that AA authors are likely to copy or adapt. Triggering it requires only composing a normal payment unit with two outputs to the AA (a small `mm_asset` output plus an unrelated large output) — well within reach of any unprivileged AA trigger sender, with no special privileges, timing, or race conditions needed.

### Recommendation
- In any AA implementing pooled/AMM logic, every case's `if` condition should ensure the trigger contains *only* the assets/outputs that the case's formula explicitly accounts for (e.g., reject or bounce triggers that include extra unexpected asset outputs), instead of only checking for the presence of one relevant output.
- Compute reserves defensively by validating that `Object.keys(trigger.outputs)` matches exactly the expected asset set for the matched case, bouncing otherwise.
- When one AA's `balance[]` is used as a price oracle by another AA, prefer TWAP-like state variables updated deliberately by the market-maker AA itself rather than raw current `balance[]`, to reduce single-unit manipulation potential.

### Proof of Concept
1. Attacker acquires (or already holds) a negligible amount of `mm_asset` (e.g. 1 unit) from a deployed instance of the market-maker AA.
2. Attacker composes a single unit with two payment outputs to the AA address in the same unit: `{mm_asset: 1}` and `{base: X}` (a large amount), where `X` is not tied to any expected ratio.
3. `updateInitialAABalances` credits both `mm_asset` and `base` amounts to the AA's `aa_balances` before case evaluation (`aa_composer.js:474-490`).
4. The "invest" case is skipped (it requires `trigger.output[[asset=$asset]] > 0`, not present); the "divest" case matches because it only requires `trigger.output[[asset=$mm_asset]]` truthy (`uniswap_like_market_maker.oscript:67-74`).
5. The divest case pays out a negligible `$investor_share` of the pool (since `mm_asset_amount` is tiny relative to `mm_asset_outstanding`) and decrements `mm_asset_outstanding` by 1, but never references or refunds the large `base` amount `X`.
6. `X` remains permanently merged into `balance[base]`, skewing the reserve used by the "exchange bytes to asset" / "exchange asset to bytes" cases' constant-product formula (`uniswap_like_market_maker.oscript:102-145`) for all subsequent trades in the same or later units — enabling the attacker (or a colluding secondary-triggered AA reading `balance[market_maker][...]`) to trade against, or report, a manipulated price atomically within the same unit.

### Citations

**File:** aa_composer.js (L474-490)
```javascript
	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
```

**File:** aa_composer.js (L1702-1757)
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
				},
				function (err) {
					if (err) {
						// revert
						if (bSecondary)
							return bounce(err);

						return revert({message: "one of secondary AAs bounced with error: ", callChain: {address, next: err}});
					}
					saveStateVars();
					addUpdatedStateVarsIntoPrimaryResponse();
					onDone(objUnit, bBouncing ? error_message : false);
				}
			);
		});
	}
```

**File:** test/samples/uniswap_like_market_maker.oscript (L67-74)
```text
			{ // divest MM shares 
				// (user is already paying 10000 bytes bounce fee which is a divest fee)
				// the price slightly moves due to fees received and paid in bytes
				if: `{$mm_asset AND trigger.output[[asset=$mm_asset]]}`,
				init: `{
					$mm_asset_amount = trigger.output[[asset=$mm_asset]];
					$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
				}`,
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

**File:** test/samples/uniswap_like_market_maker.oscript (L124-145)
```text
			{ // exchange asset to bytes
				if: `{trigger.output[[asset=$asset]] > 0 AND var['mm_asset_outstanding']}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]]; // 10Kb fee
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_bytes_balance = round($p / balance[$asset]);
					$amount = $bytes_balance - $new_bytes_balance; // we can deduct exchange fees here
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
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
