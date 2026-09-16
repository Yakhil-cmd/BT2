This confirms the analog exists. All the canonical AA balance-tracking patterns in the sample scripts key balances by `trigger.address` (the direct/immediate sender) rather than `trigger.initial_address`, as seen in `test/samples/order_book_exchange.oscript:6` and `test/samples/a_bank_without_percent.oscript:6`. However, the oscript language exposes `trigger.initial_address` specifically for this purpose in multi-hop AA chains, and it behaves exactly like `tx.origin`: it is fixed once at the primary trigger and propagated unchanged through every subsequent secondary trigger in the call chain, regardless of which intermediate AA actually relayed the call.### Title
AA developers using `trigger.initial_address` for authorization/balance-keying are vulnerable to a `tx.origin`-style phishing attack via chained AA triggers - (File: aa_composer.js)

### Summary
`trigger.initial_address` in oscript is functionally identical to Solidity's `tx.origin`: it is captured once at the primary (top-level) trigger and then propagated unchanged through every secondary trigger in a multi-hop AA call chain, regardless of which intermediate AA actually relayed the message. If an AA author uses this value (instead of `trigger.address`, the immediate/direct sender) to authorize sensitive actions such as debiting a balance or authorizing a withdrawal, a user who is phished into interacting with an attacker-controlled AA can have that attacker's AA silently trigger privileged operations on a victim's behalf in a downstream target AA — exactly the class of bug described in the Vader `tx.origin`/`removeLiquidity` report, translated to ocore's Autonomous Agents.

### Finding Description
`getTrigger()` sets `trigger.address` to the direct author of the unit that funded the current AA invocation [1](#0-0) . At the primary trigger, `trigger.initial_address` is initialized to equal `trigger.address` [2](#0-1) . However, when an AA forwards funds to another AA and triggers a secondary invocation, `handleSecondaryTriggers` explicitly copies the *original* `trigger.initial_address` (and `initial_unit`) into the child trigger, overwriting whatever `trigger.address` the child trigger would naturally have (which is the immediate calling AA, not the original user) [3](#0-2) . This propagation repeats recursively for every level of the AA call chain [4](#0-3) .

This is architecturally identical to `tx.origin` in Ethereum: `trigger.address` behaves like `msg.sender` (changes at every hop, reflects the immediate caller), while `trigger.initial_address` behaves like `tx.origin` (fixed for the whole chain, reflects the original signer no matter how many AAs relay the call). The oscript formula engine exposes both to AA code via `trigger.address` and `trigger.initial_address` [5](#0-4) , and the ocore documentation/samples do not warn AA authors against using `trigger.initial_address` for authorization decisions.

The canonical, security-conscious pattern used throughout the shipped sample AAs keys balances and authorizes withdrawals by `trigger.address` (the direct sender) — e.g., the order-book exchange and bank-without-interest samples both use `'balance_'||trigger.address||...` as the balance key and gate withdrawals with `trigger.data.amount <= var[$key]` where the key is derived from `trigger.address` [6](#0-5) [7](#0-6) . This is the "correct" (msg.sender-style) design. But nothing in ocore prevents (or even flags) an AA author from instead keying balances/authorization by `trigger.initial_address`, believing it "more reliably" identifies the real end-user across a chain of routing/forwarding AAs — the same false assumption Vader made about `tx.origin` always reflecting a trusted Router.

### Impact Explanation
If a victim posts a unit to any attacker-controlled AA (e.g., disguised as an innocuous game, faucet, or dApp — attacker AAs are permissionlessly deployable by anyone), that attacker AA can, as part of its own response, forward a payment message to a legitimate "Vault"/"Bank"-style AA that authorizes withdrawals or debits balances based on `trigger.initial_address`. Because `trigger.initial_address` is force-propagated by the engine itself (not spoofable, but also not attacker-selectable — it correctly equals the victim), the attacker's AA becomes the immediate `trigger.address` at the target AA while the victim remains `trigger.initial_address`. If the target AA's withdrawal logic reads `trigger.data` (which the attacker's AA fully controls, e.g. destination address and amount) but authorizes/debits against `balance[trigger.initial_address]`, the attacker can direct the victim's stored balance in the target AA to an address of the attacker's choosing — unauthorized fund loss for the victim, and fund theft for the attacker, without the victim ever directly interacting with the target AA. This satisfies the "concrete unauthorized spending / AA fund loss" bar.

### Likelihood Explanation
Exploitability depends on an AA author choosing the insecure design (`trigger.initial_address`-keyed authorization) over the secure, idiomatic one (`trigger.address`-keyed authorization, as used in ocore's own reference samples). Since oscript's language design deliberately exposes `trigger.initial_address` as a distinct, documented primitive intended for propagating "who originally started this chain," and since composable AA-to-AA forwarding (proxies, routers, factories) is a first-class, encouraged pattern in ocore (as shown extensively in `test/aa_composer.test.js` chain-of-AA tests and `fundraising_proxy.oscript`), it is realistic that third-party AA authors will reach for `trigger.initial_address` when building multi-hop financial products (vaults, bridges, lending) that need to identify "the real depositor" through a router/proxy layer — precisely mirroring the Vader Router/Pool assumption that triggered the original finding.

### Recommendation
- Document explicitly (in AA authoring guides / oscript reference) that `trigger.initial_address` must never be used as the sole authorization/identity check for value-transferring or balance-debiting logic, because it is attacker-influenceable in the sense that any AA in the chain can be the one that ultimately "calls into" the target with arbitrary `trigger.data`, while `trigger.initial_address` misleadingly still reports the original (possibly unwitting) user.
- Recommend AA authors always authorize sensitive actions based on `trigger.address` (the immediate, non-spoofable sender of the specific message being acted upon) and, where a multi-hop flow is required, have the target AA validate that the immediate `trigger.address` is an explicitly whitelisted/trusted intermediary AA before trusting the propagated `trigger.initial_address` for crediting/debiting purposes — analogous to Vader's fix of making a router-only entry point and validating the true caller rather than blindly trusting an origin-like field.
- Consider adding a static-analysis warning in `formula/validation.js` (which already special-cases `trigger.initial_address` for feature-activation gating [8](#0-7) ) that flags AA definitions using `trigger.initial_address` as a `var[...]`/`balance[...]` key without a corresponding `trigger.address` allow-list check.

### Proof of Concept
1. Deploy `TargetVaultAA` with logic: on receiving a secondary trigger, `if (trigger.data.withdraw) { pay trigger.data.amount of asset from balance[trigger.initial_address] to trigger.data.destination; var[trigger.initial_address] -= trigger.data.amount }` — i.e., authorization/debit keyed by `trigger.initial_address` instead of `trigger.address`.
2. Victim deposits funds directly into `TargetVaultAA` at some point, building up `var[victim_address]` balance (deposits legitimately use `trigger.address`/`trigger.initial_address`, both equal to victim at this stage per [2](#0-1) ).
3. Attacker deploys `PhishAA` that, on any trigger from the victim (e.g., victim is lured to send even a small/unrelated payment to `PhishAA`, thinking it's a different service), forwards a payment message to `TargetVaultAA` with `trigger.data = {withdraw: true, amount: <victim's full balance>, destination: attacker_address}`.
4. When the AA composer processes the secondary trigger from `PhishAA` to `TargetVaultAA`, `handleSecondaryTriggers` sets `child_trigger.initial_address = trigger.initial_address` (the victim) while `child_trigger.address` is `PhishAA` [3](#0-2) .
5. `TargetVaultAA` evaluates `trigger.data.destination` (attacker-controlled, since `PhishAA` crafted it) and debits `var[trigger.initial_address]` = victim's balance, paying out to the attacker — fund loss for the victim without their consent for that specific withdrawal.

**Caveat:** This is a design-pattern-level (secure-coding-guidance) vulnerability rather than a bug in `ocore` core logic itself — the engine's propagation of `trigger.initial_address` behaves exactly as documented/intended (analogous to `tx.origin` semantics in Solidity, which is likewise not itself "buggy," but dangerous when misused for auth). I was unable to find an existing shipped AA in this repository that actually uses `trigger.initial_address` for balance-keyed authorization (the reference samples correctly use `trigger.address`), so real-world exploitability depends on third-party AA authors adopting the insecure pattern.

### Citations

**File:** aa_composer.js (L98-100)
```javascript
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
```

**File:** aa_composer.js (L375-377)
```javascript
function getTrigger(objUnit, receiving_address) {
	var trigger = { address: objUnit.authors[0].address, unit: objUnit.unit, outputs: {} };
	if ("max_aa_responses" in objUnit)
```

**File:** aa_composer.js (L1723-1725)
```javascript
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
```

**File:** aa_composer.js (L1729-1741)
```javascript

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

**File:** formula/evaluation.js (L1066-1072)
```javascript
			case 'trigger.address':
				cb(trigger.address);
				break;

			case 'trigger.initial_address':
				cb(trigger.initial_address);
				break;
```

**File:** test/samples/order_book_exchange.oscript (L4-8)
```text
			{ // withdraw funds
				if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND trigger.data.amount <= var[$key]
				}`,
```

**File:** test/samples/a_bank_without_percent.oscript (L4-10)
```text
			{ // withdraw funds
				if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					$base_key = 'balance_'||trigger.address||'_'||'base';
					$fee = 1000;
					$required_amount = trigger.data.amount + ((trigger.data.asset == 'base') ? $fee : 0);
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND $required_amount <= var[$key] AND $fee <= var[$base_key]
```

**File:** formula/validation.js (L448-459)
```javascript
			case 'trigger.initial_unit':
			case 'trigger.outputs':
			case 'previous_aa_responses':
				if (mci < constants.aa3UpgradeMci)
					return cb(op + ' not activated yet');
			case 'trigger.address':
			case 'trigger.initial_address':
			case 'trigger.unit':
			case 'mc_unit':
			case 'number_of_responses':
				if (bGetters)
					return cb(op + ' in getters');
```
