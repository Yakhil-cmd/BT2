# Q3288: `BASH_ENV` RCE through a review stack provisioned under allow_all

## Question
On a repository with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `BASH_ENV` via a label or shipit.yml machine_env, so the review-stack deploy process inherits it and names a file bash sources before running a non-interactive `shipit.yml` step?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack provisioning -> PerformTaskJob -> PTY.spawn
- Attacker controls: env key `BASH_ENV` via a self-added PR label or the fork's shipit.yml machine.environment under allow_all
- Exploit idea: provisioning under allow_all is reachable by an unprivileged PR (see provision? precedence), and Command#unbundled_env carries `BASH_ENV` unfiltered so it names a file bash sources before running a non-interactive `shipit.yml` step
- Invariant to test: No fork-controllable key reaches the environment hash of a spawned deploy process.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: provision a ReviewStack under allow_all, set `BASH_ENV` via label/machine_env, assert Command#unbundled_env includes `BASH_ENV`.
