Looking at the Aurora Engine codebase, I need to find an analog to the external report's vulnerability class: **a permissionless function callable by anyone without the approval of a party who has a stake in the outcome**, enabling front-running to steal value.

Let me examine the `deploy_upgrade()` function and the upgrade flow carefully.