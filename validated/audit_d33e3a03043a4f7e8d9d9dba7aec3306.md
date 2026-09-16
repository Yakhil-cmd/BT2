### Title
Unbounded founder fee percentage in `51_attack_game.oscript` allows a team founder to drain nearly all contributor funds - (File: `test/samples/51_attack_game.oscript`)

### Summary
The `51_attack_game.oscript` autonomous-agent (AA) template lets any user become a "team founder" by posting a `create_team` trigger, at which point they set their own `founder_tax` percentage. This value is stored as-is with no upper- or lower-bound validation and is later used directly to compute the payout split between the founder and the team's contributors. Because nothing constrains `founder_tax` to the sane range `[0,1)`, a malicious founder can set it to `1` or higher and redirect essentially all of the winning team's pooled funds to themselves, at the expense of the other contributors — the same "unbounded fee" root cause as the reported `setplatformFee` bug, but reachable by an ordinary AA trigger sender rather than a privileged, key-leaked owner.

### Finding Description
When a user triggers team creation, the AA stores the founder tax without any range check: [1](#0-0) 

`trigger.data.founder_tax` is fully attacker-controlled formula input coming straight from the trigger's `data` payload — there is no `if`/`bounce` condition anywhere in the case that validates it is between 0 and 1 (or even non-negative). It's simply defaulted to `0` if absent (`trigger.data.founder_tax otherwise 0`), but any numeric value supplied by the trigger sender, including values `>= 1` or negative, is accepted.

That unchecked value is later consumed in the payout formula for the winning team: [2](#0-1) 

Here `$amount = round(( $share * (1-$founder_tax) + (trigger.address == $winner AND !var['founder_tax_paid'] ? $founder_tax : 0) ) * var['total'])`. If `$founder_tax >= 1`:
- For any ordinary contributor payout, `$share * (1-$founder_tax)` becomes zero or negative, so `$amount` collapses to `0` (or a negative number that would likely cause the payment message to fail/bounce, effectively locking their share).
- For the founder's own claim, `$founder_tax` alone (potentially `>1`) multiplied by `var['total']` can pay out more than their proportional share — up to the entire pooled `var['total']`, at other contributors' expense.

This is structurally identical to the reported `setplatformFee` issue: a percentage/fee value that is fully controlled by a single actor (there: contract owner; here: the AA's self-declared "team founder") is persisted and later applied to fund distribution with no maximum-limit enforcement.

### Impact Explanation
Any user who creates a team (paying only a small, fixed `team_creation_fee`) can set `founder_tax` to `1.0` or above. If that team later wins the 51% attack game, the founder can claim close to (or all of) the pooled `base` funds contributed by other, unsuspecting team members, while those contributors receive zero or an invalid (negative) payout. This is a direct AA fund loss / unauthorized redistribution of contributor funds, triggered purely by unprivileged unit/trigger data supplied by the founder at team-creation time — no leaked keys or special privileges are required.

### Likelihood Explanation
High: creating a team and setting `founder_tax` is a normal, permissionless action available to any address that can post a trigger unit with `trigger.data.create_team` and `trigger.data.founder_tax`. No special role, moderation, or off-chain approval process exists to prevent a malicious value from being accepted, and the flaw is exercised automatically as soon as the fraudulent team happens to win the game.

### Recommendation
Add explicit bounds validation on `founder_tax` at team-creation time, e.g. bounce the trigger unless `0 <= trigger.data.founder_tax < 1` (or a more conservative cap such as `<= 0.5`), mirroring how other AA fee-like parameters (e.g., `bounce_fees`) are capped in `aa_validation.js`. This should be enforced within the `init` block of the `create_team` case before persisting `founder_tax` to state: [3](#0-2) 

### Proof of Concept
1. Attacker posts a unit with `trigger.data = {create_team: true, founder_tax: 5}` and pays at least `team_creation_fee` (5000 bytes), becoming founder of a new team and asset.
2. Multiple honest users contribute to this team, each receiving proportional team-asset shares as tracked by `var['team_..._amount']`.
3. The team accumulates >51% of total contributions and, after the challenge period elapses, is finalized as the `winner` via the `finish` trigger case.
4. Contributors attempt to redeem their team-asset shares in the "pay out the winnings" case; because `founder_tax = 5`, `(1-$founder_tax) = -4`, making their computed `$amount` negative/invalid, so their payout output message fails or resolves to zero.
5. The founder redeems their own share: their term `(trigger.address == $winner AND !var['founder_tax_paid'] ? $founder_tax : 0)` contributes `5 * var['total']`, letting them claim a payout far exceeding — or equal to — the entire pooled `var['total']`, draining the funds intended for the other contributors.

### Citations

**File:** test/samples/51_attack_game.oscript (L27-32)
```text
				init: `{
					if (var['team_' || trigger.address || '_asset'])
						bounce('you already have a team');
					if (trigger.output[[asset=base]] < $team_creation_fee)
						bounce('not enough to pay for team creation');
				}`,
```

**File:** test/samples/51_attack_game.oscript (L56-63)
```text
					{
						app: 'state',
						state: `{
							var['team_' || trigger.address || '_founder_tax'] = trigger.data.founder_tax otherwise 0;
							var['team_' || trigger.address || '_asset'] = response_unit;
							response['team_asset'] = response_unit;
						}`
					}
```

**File:** test/samples/51_attack_game.oscript (L116-129)
```text
			{ // pay out the winnings
				if: `{
					if (!$bFinished)
						return false;
					$winner = var['winner'];
					$winner_asset = var['team_' || $winner || '_asset'];
					$asset_amount = trigger.output[[asset=$winner_asset]];
					$asset_amount > 0
				}`,
				init: `{
					$share = $asset_amount / var['team_' || $winner || '_amount'];
					$founder_tax = var['team_' || $winner || '_founder_tax'];
					$amount = round(( $share * (1-$founder_tax) + (trigger.address == $winner AND !var['founder_tax_paid'] ? $founder_tax : 0) ) * var['total']);
				}`,
```
