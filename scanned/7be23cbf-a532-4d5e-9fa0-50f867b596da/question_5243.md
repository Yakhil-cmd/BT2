# Q5243: `GEM_PATH` RCE through a review stack provisioned under prevent_with_label

## Question
On a repository with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `GEM_PATH` via a label or shipit.yml machine_env, so the review-stack deploy process inherits it and adds an attacker gem path consulted by `require`/`bundle`?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack provisioning -> PerformTaskJob -> PTY.spawn
- Attacker controls: env key `GEM_PATH` via a self-added PR label or the fork's shipit.yml machine.environment under prevent_with_label
- Exploit idea: provisioning under prevent_with_label is reachable by an unprivileged PR (see provision? precedence), and Command#unbundled_env carries `GEM_PATH` unfiltered so it adds an attacker gem path consulted by `require`/`bundle`
- Invariant to test: No fork-controllable key reaches the environment hash of a spawned deploy process.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: provision a ReviewStack under prevent_with_label, set `GEM_PATH` via label/machine_env, assert Command#unbundled_env includes `GEM_PATH`.
