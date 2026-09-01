# Q3520: `IFS` RCE through a review stack provisioned under allow_all

## Question
On a repository with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `IFS` via a label or shipit.yml machine_env, so the review-stack deploy process inherits it and changes the shell field separator so a step string re-splits into attacker-chosen argv?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack provisioning -> PerformTaskJob -> PTY.spawn
- Attacker controls: env key `IFS` via a self-added PR label or the fork's shipit.yml machine.environment under allow_all
- Exploit idea: provisioning under allow_all is reachable by an unprivileged PR (see provision? precedence), and Command#unbundled_env carries `IFS` unfiltered so it changes the shell field separator so a step string re-splits into attacker-chosen argv
- Invariant to test: No fork-controllable key reaches the environment hash of a spawned deploy process.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: provision a ReviewStack under allow_all, set `IFS` via label/machine_env, assert Command#unbundled_env includes `IFS`.
