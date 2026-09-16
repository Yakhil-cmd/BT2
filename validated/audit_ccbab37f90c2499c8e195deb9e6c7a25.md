## Analog Found

### Title
Griefing via unconditional balance donation breaking exact-equality checks in AA logic - (File: `formula/evaluation.js`, `aa_composer.js`, `test/samples/uniswap_like_market_maker.oscript`)

### Summary
The C4 finding roots the griefing vector in a `require` that checks a contract's *cumulative balance* of a token against an *exact expected amount*, which anyone can poison by donating tokens directly to the contract. Ocore's AA formula engine exposes an equivalent primitive — `balance[asset]` — which reflects the AA address's full accumulated on-chain balance (not just the amount received in the current trigger), and this value is freely inflatable by any unprivileged unit poster simply by sending a payment to the AA's address. When an AA author (as officially demonstrated in the shipped `uniswap_like_market_maker.oscript` sample) uses this balance in a strict `==`/`!=` comparison, an attacker can permanently grief legitimate future triggers into `bounce()`, exactly mirroring the "FAILED_OUTPUT_AMOUNT" griefing pattern from the report.

### Finding Description
`balance[asset]` in AA formulas is resolved by `readBalance()`, which reads `objValidationState.assocBalances`/`aa_balances`, a value populated from **all** unspent outputs ever sent to the address, not merely the current trigger's payment: [1](#0-0) 

This balance table is updated whenever any output — including from any arbitrary unprivileged unit poster, not just the trigger sender — is received by the AA address: [2](#0-1) [3](#0-2) 

The officially shipped sample AA `uniswap_like_market_maker.oscript` uses this manipulable balance in an exact-equality gate to detect the "initial deposit" state, and a strict inequality bounce check to enforce a ratio: [4](#0-3) 

Specifically:
- Line 38: `if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit ... }` — this exact-equality check is the "initial deposit" gate, analogous to the exact-balance compare in `joinTokenSingle`.
- Line 44: `if ($expected_asset_amount != trigger.output[[asset=$asset]]) bounce('wrong ratio of amounts...')` — a strict inequality that reverts (bounces) the entire trigger, exactly like `require(outputAmount == ...)` reverting with `FAILED_OUTPUT_AMOUNT` in the report.

Because `balance[$asset]` and `balance[base]` include the AA's entire historical balance, and any unprivileged party can top up the AA's balance simply by sending it a payment (even one that matches no `if` case and is silently accepted), an attacker can:
1. Before any real investor deposits, send a dust amount of `$asset` to the AA address. This is accepted into `aa_balances` without triggering any case (no case matches a bare-asset transfer with no accompanying data), permanently setting `$asset_balance != 0`.
2. This permanently disables the "initial deposit" free-pricing branch (line 38), forcing every future investment into the ratio-checked branch (line 42-45).
3. Since the pool now has a near-zero, attacker-controlled "ratio" (dust asset vs. zero bytes), any legitimate investor's `$expected_asset_amount` will essentially never match `trigger.output[[asset=$asset]]` exactly (rounding, timing, or attacker-chosen ratio), causing `bounce('wrong ratio of amounts...')` — a denial-of-service against every future invest call.

### Impact Explanation
This is an AA-fund-freezing / node-cannot-confirm-new-units-style griefing vector: any unprivileged unit poster (anyone able to send a payment) can permanently disable the "initial deposit" and ordinary investment paths of an AA that follows this officially documented pattern, bricking the contract for all legitimate users and locking already-deposited funds behind an unreachable exact-match condition, without spending more than the dust amount and negligible fees.

### Likelihood Explanation
High. The attack requires only sending a single, tiny, standard payment to a known AA address before its first real use — no special privileges, no race condition beyond front-running the very first deposit, and it uses the exact `balance[...]` API that formula/evaluation.js exposes for all AAs.

### Recommendation
Do not use strict `==`/`!=` (or unbounded `balance[asset]`) as a state-detection or validation gate in AA logic that any unprivileged party can pre-fund; instead:
- Track "initial deposit" state via a dedicated state variable (`var['initialized']`) rather than inferring it from `balance[asset] == 0`.
- Replace strict equality bounces on user-influenced ratios with tolerance bands (`at_least`/`at_most`, as already supported in `formula/validation.js`'s `getInputOrOutputError`, which explicitly disallows `==` for input/output filters) rather than a brittle `!=` bounce.
- More generally, document/patch the sample (`test/samples/uniswap_like_market_maker.oscript`) since it is shipped as a reference implementation and currently encodes the anti-pattern directly.

### Proof of Concept
1. Deploy the AA defined by `test/samples/uniswap_like_market_maker.oscript` and issue `$mm_asset` via the `define` case.
2. Before any user performs the first "invest" trigger, send `1` unit of `$asset` directly to the AA address (a plain payment; no case's `if` condition matches this transfer alone, so funds sit in `aa_balances` untouched) — reachable per `aa_composer.js`'s `updateInitialAABalances` at [2](#0-1)  and `storage.js` balance accrual at [3](#0-2) .
3. Any subsequent genuine investor trigger now hits `$asset_balance == 0 OR $bytes_balance == 0` as `false` (since `$asset_balance` is now `1`), forcing the ratio branch at [5](#0-4) .
4. Because the attacker-seeded ratio is degenerate (1 unit of asset vs 0 bytes), `$expected_asset_amount` computed from `$current_ratio` will not exactly equal the investor's `trigger.output[[asset=$asset]]`, triggering `bounce('wrong ratio of amounts, expected ...')` for every future invest attempt, permanently denying service.

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

**File:** test/samples/uniswap_like_market_maker.oscript (L33-48)
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
```
