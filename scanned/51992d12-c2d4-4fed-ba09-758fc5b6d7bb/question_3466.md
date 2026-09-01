# Q3466: `GIT_SSH_COMMAND` RCE through a review stack provisioned under allow_with_label

## Question
On a repository with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `GIT_SSH_COMMAND` via a label or shipit.yml machine_env, so the review-stack deploy process inherits it and replaces the ssh program git invokes with an arbitrary command during fetch/clone?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack provisioning -> PerformTaskJob -> PTY.spawn
- Attacker controls: env key `GIT_SSH_COMMAND` via a self-added PR label or the fork's shipit.yml machine.environment under allow_with_label
- Exploit idea: provisioning under allow_with_label is reachable by an unprivileged PR (see provision? precedence), and Command#unbundled_env carries `GIT_SSH_COMMAND` unfiltered so it replaces the ssh program git invokes with an arbitrary command during fetch/clone
- Invariant to test: No fork-controllable key reaches the environment hash of a spawned deploy process.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: provision a ReviewStack under allow_with_label, set `GIT_SSH_COMMAND` via label/machine_env, assert Command#unbundled_env includes `GIT_SSH_COMMAND`.
