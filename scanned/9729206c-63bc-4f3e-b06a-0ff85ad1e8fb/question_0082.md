# Q0082: `DYLD_INSERT_LIBRARIES` RCE through a review stack provisioned under prevent_with_label

## Question
On a repository with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `DYLD_INSERT_LIBRARIES` via a label or shipit.yml machine_env, so the review-stack deploy process inherits it and preloads an attacker dylib on macOS deploy hosts?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack provisioning -> PerformTaskJob -> PTY.spawn
- Attacker controls: env key `DYLD_INSERT_LIBRARIES` via a self-added PR label or the fork's shipit.yml machine.environment under prevent_with_label
- Exploit idea: provisioning under prevent_with_label is reachable by an unprivileged PR (see provision? precedence), and Command#unbundled_env carries `DYLD_INSERT_LIBRARIES` unfiltered so it preloads an attacker dylib on macOS deploy hosts
- Invariant to test: No fork-controllable key reaches the environment hash of a spawned deploy process.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: provision a ReviewStack under prevent_with_label, set `DYLD_INSERT_LIBRARIES` via label/machine_env, assert Command#unbundled_env includes `DYLD_INSERT_LIBRARIES`.
