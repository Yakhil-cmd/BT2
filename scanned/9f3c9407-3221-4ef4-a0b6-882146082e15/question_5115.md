# Q5115: `SSH_ASKPASS` RCE through a review stack provisioned under allow_with_label

## Question
On a repository with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `SSH_ASKPASS` via a label or shipit.yml machine_env, so the review-stack deploy process inherits it and names a program executed to answer ssh password prompts?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack provisioning -> PerformTaskJob -> PTY.spawn
- Attacker controls: env key `SSH_ASKPASS` via a self-added PR label or the fork's shipit.yml machine.environment under allow_with_label
- Exploit idea: provisioning under allow_with_label is reachable by an unprivileged PR (see provision? precedence), and Command#unbundled_env carries `SSH_ASKPASS` unfiltered so it names a program executed to answer ssh password prompts
- Invariant to test: No fork-controllable key reaches the environment hash of a spawned deploy process.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: provision a ReviewStack under allow_with_label, set `SSH_ASKPASS` via label/machine_env, assert Command#unbundled_env includes `SSH_ASKPASS`.
