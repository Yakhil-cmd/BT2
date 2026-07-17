Looking at the external bug class: a post-operation validation check is applied uniformly to all operation types, including one where the check is semantically inapplicable (withdrawing borrowed tokens doesn't affect collateral ratio, yet the collateral check still runs and can block the withdrawal).

I need to find a nearcore analog where a validation check is applied to a transaction/action type where it is semantically inapplicable — specifically one that would *increase* the account's balance, yet the check evaluates the balance *before* that increase.

Let me trace the exact path.