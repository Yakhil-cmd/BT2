Looking at the `skip_stateful_validations` logic in the gateway's stateful validator, I need to trace whether an attacker can exploit the deploy-account + invoke UX bypass to inject an unvalidated transaction.

Let me examine the key code paths more carefully.