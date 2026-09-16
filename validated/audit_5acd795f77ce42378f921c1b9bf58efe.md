### Title
Pooled-share AAs on ocore inherit the ERC4626 "first depositor / donation" share-price inflation attack via `balance[asset]` — (File: `test/samples/uniswap_like_market_maker.oscript`)

### Summary
The Sherlock finding describes an ERC4626 vault whose share price is `totalAssets/totalSupply`; because `totalAssets` is just the token balance of the vault, an attacker can mint a dust amount of shares and then directly transfer ("donate") underlying tokens to the vault to inflate the price-per-share, causing later depositors to receive rounded-down (or zero) shares. Ocore's Autonomous Agent (AA) engine exposes the exact same primitive: any user can pay bytes/asset units directly to an AA's address, and that value is unconditionally folded into the AA's `balance[...]` regardless of whether the payment satisfies any of the AA's `if` conditions. Reference pooled-share AA templates shipped by the project (e.g. `uniswap_like_market_maker.oscript`, and by extension any user-built AA that follows this well-documented pattern) compute newly issued shares from raw `balance[$asset]` / `balance[base]` ratios, making them structurally vulnerable to the same donation/dust griefing attack described in the report.

### Finding Description
In `test/samples/uniswap_like_market_maker.oscript` the "invest in MM" case computes: [1](#0-0) 
```
$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
$bytes_balance = balance[base] - trigger.output[[asset=base]];
if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
    $issue_amount = balance[base];
    return;
}
$current_ratio = $asset_balance / $bytes_balance;
$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
...
$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
```
Shares (`mm_asset`) are minted proportionally to the ratio of the incoming deposit to the AA's *current on-chain balance*, exactly mirroring ERC4626's `totalAssets`/`totalSupply` mechanic.

Crucially, `balance[asset]` in oscript is not limited to funds that arrived via a matching trigger case — it reflects the AA address's full ledger balance, which is updated for **any** payment output sent to the AA address, independent of whether any `if` condition in the AA's `cases` matches: [2](#0-1) [3](#0-2) 
The `balance[...]` formula builtin simply reads this same aggregated balance: [4](#0-3) 

This means an attacker can:
1. Send a minimal trigger that satisfies the "initial deposit" branch (`$asset_balance == 0 OR $bytes_balance == 0`) to mint the very first unit of `mm_asset` shares cheaply, setting `var['mm_asset_outstanding']` to a small value.
2. Send a follow-up payment of the pooled asset directly to the AA's address in an amount/shape that does **not** satisfy any `if` condition of the "cases" block (e.g. below the `1e5` byte threshold, or with `trigger.output[[asset=$asset]] == 0`), which the AA does not reject — the funds are still credited to `balance[$asset]`/`balance[base]` via `aa_balances`, but no shares are minted for it and no state var is updated.
3. This inflates `$asset_balance` or `$bytes_balance` relative to `var['mm_asset_outstanding']`, distorting `$current_ratio` for the next legitimate depositor, who must now either overpay to match the manipulated ratio or receives disproportionately few shares relative to true pool value — the attacker profits when the AA's shares are later divested at the inflated valuation.

### Impact Explanation
Any pooled-share AA on ocore built with this common pattern (deposit → mint shares proportional to `balance[asset]` ratio) is exposed to fund loss for honest late depositors and a corresponding profit/fund-freezing effect for the attacker who seeded the manipulation, matching Sherlock's "Medium" classification of loss to new depositors from a first-depositor/donation share-price attack. Because the underlying primitive (AA balance updated by any payment regardless of matched case) is part of core `aa_composer.js`/`storage.js` behavior, this is not a bug in a single script but a systemic risk pattern that the project's own reference oscript template does not mitigate (no minimum-liquidity seeding, no dead-share burn).

### Likelihood Explanation
The attack requires only ordinary, unprivileged unit-posting capability — sending a payment to the AA's address is available to any wallet holder and costs only standard network fees (no special permissions, no reliance on malicious nodes/hubs). The reference AA sample ships without any first-depositor mitigation (e.g., minimum initial liquidity lock, virtual offset, or `ONE_SHARE` seeding), so any deployment following this pattern faithfully reproduces the vulnerable ERC4626-style accounting.

### Recommendation
- Seed pooled-share AAs with a fixed minimum initial deposit (analogous to `ONE_SHARE`) that is permanently locked/unspendable, so the first depositor cannot mint an arbitrarily small number of shares against the entire subsequently-donated balance.
- Alternatively, track owned/contributed balances explicitly via state variables (as `mm_asset_outstanding` already partially does) rather than deriving share price purely from the AA's raw `balance[...]`, and reject/redirect any payment that doesn't correspond to a recognized "invest" trigger (e.g., bounce or explicitly account for unsolicited transfers rather than silently absorbing them into `balance[...]`).
- Document this risk prominently for AA authors relying on the shipped `uniswap_like_market_maker.oscript` / similar pooled-asset templates as reference designs, since ocore has no protocol-level protection against unsolicited "donation" payments inflating an AA's balance outside of its explicit state accounting.

### Proof of Concept
1. Deploy the AA from `test/samples/uniswap_like_market_maker.oscript`; call `{define: true}` to create `$mm_asset`.
2. Attacker sends a trigger with `trigger.output[[asset=base]] > 1e5` and `trigger.output[[asset=$asset]] = 1` (dust) while the pool is empty — hits the "initial deposit" branch: `$issue_amount = balance[base]` (only their own dust bytes), minting a small `mm_asset_outstanding`.
3. Attacker sends a second unit that pays a large amount of `$asset` to the AA address but with `trigger.output[[asset=base]] <= 1e5` (or `== 0`), so none of the `cases` match — the transaction is not bounced-out of the balance ledger; `aa_balances`/`balance[$asset]` for the AA increases per `aa_composer.js` (`updateInitialAABalances`) even though no `mm_asset` is minted.
4. A legitimate depositor now sends a fairly-sized deposit; `$current_ratio = $asset_balance / $bytes_balance` is skewed by the attacker's uncompensated donation, forcing the depositor either to overpay in `$asset` to satisfy `$expected_asset_amount` or to receive shares (`$issue_amount`) that undervalue their true contribution relative to `mm_asset_outstanding`, at the attacker's benefit when later divesting. [5](#0-4) [6](#0-5)

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L1-66)
```text
{
	init: `{
		$asset = 'n9y3VomFeWFeZZ2PcSEcmyBb/bI7kzZduBJigNetnkY=';
		$mm_asset = var['mm_asset'];
	}`,
	messages: {
		cases: [
			{ // define share asset
				if: `{ trigger.data.define AND !$mm_asset }`,
				messages: [
					{
						app: 'asset',
						payload: {
							// without cap
							is_private: false,
							is_transferrable: true,
							auto_destroy: false,
							fixed_denominations: false,
							issued_by_definer_only: true,
							cosigned_by_definer: false,
							spender_attested: false,
						}
					},
					{
						app: 'state',
						state: `{
							var['mm_asset'] = response_unit;
							response['mm_asset'] = response_unit;
						}`
					}
				]
			},
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

**File:** aa_composer.js (L474-541)
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
		objValidationState.assocBalances[address] = {};
		var arrAssets = Object.keys(trigger.outputs);
		conn.query(
			"SELECT asset, balance FROM aa_balances WHERE address=?",
			[address],
			function (rows) {
				var arrQueries = [];
				// 1. update balances of existing assets
				rows.forEach(function (row) {
					if (constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
						reintroduceBalanceBug(address, row);
					if (!trigger.outputs[row.asset]) {
						objValidationState.assocBalances[address][row.asset] = row.balance;
						return;
					}
					conn.addQuery(
						arrQueries,
						"UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? ",
						[trigger.outputs[row.asset], address, row.asset]
					);
					objValidationState.assocBalances[address][row.asset] = row.balance + trigger.outputs[row.asset];
					if (objValidationState.assocBalances[address][row.asset] > MAX_BALANCE)
						bOverflow = true;
				});
				// 2. insert balances of new assets
				var arrExistingAssets = rows.map(function (row) { return row.asset; });
				var arrNewAssets = _.difference(arrAssets, arrExistingAssets);
				if (arrNewAssets.length > 0) {
					var arrValues = arrNewAssets.map(function (asset) {
						objValidationState.assocBalances[address][asset] = trigger.outputs[asset];
						return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", " + trigger.outputs[asset] + ")"
					});
					conn.addQuery(arrQueries, "INSERT INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
				}
				byte_balance = objValidationState.assocBalances[address].base;
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
				if (!bSecondary)
					conn.addQuery(arrQueries, "SAVEPOINT initial_balances");
				async.series(arrQueries, function () {
					conn.query("SELECT storage_size FROM aa_addresses WHERE address=?", [address], function (rows) {
						if (rows.length === 0)
							throw Error("AA not found? " + address);
						storage_size = rows[0].storage_size;
						objValidationState.storage_size = storage_size;
						cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
					});
				});
			}
		);
	}
```

**File:** storage.js (L954-962)
```javascript
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
