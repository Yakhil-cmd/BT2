Let me analyze the bug pattern and search for a nearcore analog. The core issue is: **stale authorization state persists after a state transition because the clearing logic has a conditional guard that can be bypassed**.

Let me look deeper at the specific areas most analogous to the bug pattern - conditional guards in authorization/state-clearing logic.

Let me look at the `FixDelegateActionDepositWithFunctionCallError` feature flag and the `action_deploy_contract` function to understand the full picture.