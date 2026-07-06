Looking at the codebase, I need to find an analog to the "token contract creator retains control over token emission" vulnerability class — specifically, an authorization/ownership control issue where an unprivileged caller can manipulate reward emission or distribution.

Let me examine the `update_rewards` function and its access control.