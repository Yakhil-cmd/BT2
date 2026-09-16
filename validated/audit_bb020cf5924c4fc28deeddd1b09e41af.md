## Analog Found

### Title
Signed order-matching AA pattern allows front-running to deny counterparty liquidity - (File: test/samples/order_book_exchange.oscript)

### Summary
The ocore oscript/AA language ships (and documents via its own parser test suite) a signed order-book exchange pattern where two independently-signed orders are matched against each other by whichever `trigger` unit an unprivileged sender posts. Because AA state (available balance to sell) is mutable shared storage and AA trigger execution order is fully determined by DAG/MC-stabilization order rather than by the original order-poster, any third party can observe a pending "match order1 vs order2" trigger and race it by consuming the resting order's (`order2`) balance first, causing the original trader's trigger to fail its balance check and bounce — reproducing the exact "Trader" front-running/denial-of-trading griefing pattern from the cited report, but inside an AA.

### Finding Description
The order-matching logic lives in the `if`/`state` case of the sample AA definition: [1](#0-0) 

Key mechanics:
- `order1` and `order2` are independently signed messages (`signed_message`), verified with `is_valid_signed_package`, exactly analogous to the `Trader` contract's two signed orders. [2](#0-1) 
- The resting order's available balance is tracked in mutable AA state vars keyed by address+asset (`var[$sell_key2]`), and the match only succeeds while `$amount_left2 <= var[$sell_key2]`. [3](#0-2) 
- On a successful match, the state update decrements `var[$sell_key2]` (i.e., consumes the resting order's liquidity) and marks the order as (partially) `executed_`. [4](#0-3) 

Any unprivileged AA trigger sender who observes an unstable trigger unit proposing to match `order1` against `order2` can construct and post their own trigger matching `order2` (or a portion of it) against a different counter-order (potentially their own), consuming `var[$sell_key2]` first. AA trigger execution order is not first-come-first-served by intent but is fixed by DAG stabilization order: [5](#0-4) 

and triggers for a stabilized MCI are further processed in a fully deterministic, but attacker-influenceable-by-unit-placement, order: [6](#0-5) 

Because inclusion order in the DAG (and hence relative `level`/`unit` ordering used for trigger sequencing) can be influenced by unit propagation speed and parent selection, an attacker can get their competing trigger unit included/stabilized ahead of the victim's, exactly mirroring the original report's "observe the mempool and front-run" scenario, except here it happens through unit/DAG-ordering races rather than a literal mempool.

### Impact Explanation
Once the attacker's trigger consumes the counter-order's tracked balance (`var[$sell_key2]`), the victim's originally-intended matching trigger will fail the `$amount_left2 > var[$sell_key2]` check, causing the `if` to return `false`. The trigger then falls through to the "silently accept coins" case, which just deposits the trigger's payment into the AA balance without executing the intended trade — i.e., the victim is denied the trade they attempted, while their bytes/asset sit unused in the AA until manually withdrawn. As in the original report, the attacker's cost is executing the countertrade themselves (paying AA + tx fees), and if they are also a party benefitting from denying a specific trade (e.g., blocking a user from restoring solvency via a matched trade), this is a concrete griefing/denial-of-service vector against legitimate AA trigger senders using this order-matching pattern.

### Likelihood Explanation
This pattern is directly shipped and validated as a first-class example of AA capability in the ocore test suite (`test/ojson.test.js` "Order book exchange" test, `test/samples/order_book_exchange.oscript`), demonstrating it is an intended, supported way to build order-matching contracts on top of oscript/AA primitives. Any AA author can deploy this or a similar exchange AA; any AA trigger sender (including automated bots) can observe unstable trigger units targeting such an AA and race to consume the referenced counter-order's balance first. No special privileges beyond normal unit posting are required, so likelihood is high wherever this pattern (or similar mutable-balance order matching) is deployed.

### Recommendation
- For any AA-based order-matching design (as demonstrated by `order_book_exchange.oscript`), avoid keying resting-order matches solely on a live, globally-mutable balance variable that any trigger can race to consume. Consider binding a match to a specific committed trigger/order pair (e.g., requiring the resting order's own signature/state commitment to include the *taker*'s identity or trigger unit hash) so that competing triggers cannot silently reallocate the same liquidity.
- Where partial/first-come matching is inherent to the design, document the front-running/denial risk explicitly (as the original report notes, this class of issue is hard to fully eliminate in an open order-matching design) and consider off-chain/bot-only submission of the matching trigger to reduce exposure, or rate/priority mechanisms that make racing uneconomical.

### Proof of Concept
1. Deploy the AA defined in `test/samples/order_book_exchange.oscript` (or an equivalent order-matching AA) that tracks `var['balance_'||address||'_'||asset]`.
2. Alice deposits and creates `order2` (a large resting sell order) and shares it off-chain; Bob has a matching smaller `order1`.
3. Bob broadcasts a trigger unit calling `trigger.data.order1`/`trigger.data.order2` to match his order against Alice's.
4. Before Bob's trigger unit stabilizes, an attacker (Mallory) observes it (via network propagation) and posts her own trigger matching Alice's `order2` against her own `order3`, engineered to be included/stabilized earlier per the deterministic `ORDER BY units.level, units.unit, address` trigger-processing rule in `main_chain.js`.
5. Once Mallory's trigger consumes/decrements `var[$sell_key2]`, Bob's trigger's condition `$amount_left2 > var[$sell_key2]` becomes true (insufficient remaining liquidity), so his `if` evaluates false; his trigger falls into the "silently accept coins" branch, and his intended trade with Alice never executes — reproducing the denial-of-trading griefing described in the source report.

### Citations

**File:** test/samples/order_book_exchange.oscript (L27-65)
```text
			{ // execute orders, order1 must be smaller or the same as order2; order2 is partially filled
				if: `{
					$order1 = trigger.data.order1.signed_message;
					$order2 = trigger.data.order2.signed_message;
					if (!$order1.sell_asset OR !$order2.sell_asset)
						return false;
					if ($order1.sell_asset != $order2.buy_asset OR $order1.buy_asset != $order2.sell_asset)
						return false;

					// to do check expiry

					$sell_key1 = 'balance_' || $order1.address || '_' || $order1.sell_asset;
					$sell_key2 = 'balance_' || $order2.address || '_' || $order2.sell_asset;

					$id1 = sha256($order1.address || $order1.sell_asset || $order1.buy_asset || $order1.sell_amount || $order1.price || trigger.data.order1.last_ball_unit);
					$id2 = sha256($order2.address || $order2.sell_asset || $order2.buy_asset || $order2.sell_amount || $order2.price || trigger.data.order2.last_ball_unit);

					if (var['executed_' || $id1] OR var['executed_' || $id2])
						return false;

					if (!is_valid_signed_package(trigger.data.order1, $order1.address)
						OR !is_valid_signed_package(trigger.data.order2, $order2.address))
						return false;

					$amount_left1 = var['amount_left_' || $id1] otherwise $order1.sell_amount;
					$amount_left2 = var['amount_left_' || $id2] otherwise $order2.sell_amount;

					if ($amount_left1 > var[$sell_key1] OR $amount_left2 > var[$sell_key2])
						return false;

					$buy_amount1 = round($amount_left1 * $order1.price);
					if ($buy_amount1 > $amount_left2) // order1 is not the smaller one
						return false;
					$expected_buy_amount2 = round($buy_amount1 * $order2.price);
					if ($expected_buy_amount2 > $amount_left1) // user2 doesn't like the price, he gets less than expects
						return false;

					true
				}`,
```

**File:** test/samples/order_book_exchange.oscript (L68-90)
```text
					state: `{
						$buy_key1 = 'balance_' || $order1.address || '_' || $order1.buy_asset;
						$buy_key2 = 'balance_' || $order2.address || '_' || $order2.buy_asset;
						$base_key1 = 'balance_' || $order1.address || '_base';
						$base_key2 = 'balance_' || $order2.address || '_base';

						var[$sell_key1] = var[$sell_key1] - $amount_left1;
						var[$sell_key2] = var[$sell_key2] - $buy_amount1;
						var[$buy_key1] = var[$buy_key1] + $buy_amount1;
						var[$buy_key2] = var[$buy_key2] + $amount_left1;

						$fee = 1000;
						var[$base_key1] = var[$base_key1] - $fee;
						var[$base_key2] = var[$base_key2] - $fee;
						if (var[$base_key1] < 0 OR var[$base_key2] < 0)
							bounce('not enough balance for fees');

						var['executed_' || $id1] = 1;
						$new_amount_left2 = $amount_left2 - $buy_amount1;
						if ($new_amount_left2)
							var['amount_left_' || $id2] = $new_amount_left2;
						else
							var['executed_' || $id2] = 1;
```

**File:** main_chain.js (L1695-1706)
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
```

**File:** aa_composer.js (L63-69)
```javascript
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
```
