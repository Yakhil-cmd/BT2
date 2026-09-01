# Q3618: [allow_all] `GIT_EXEC_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `review.checklist` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `GIT_EXEC_PATH` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `review.checklist` section the deploy process redirects git subcommand resolution to an attacker directory?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `GIT_EXEC_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `review.checklist` section of the fork shipit.yml under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `review.checklist` step inherits `GIT_EXEC_PATH` from Command#unbundled_env and redirects git subcommand resolution to an attacker directory
- Invariant to test: The `review.checklist` step inherits no fork-controllable key such as `GIT_EXEC_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `review.checklist` step, inject `GIT_EXEC_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
