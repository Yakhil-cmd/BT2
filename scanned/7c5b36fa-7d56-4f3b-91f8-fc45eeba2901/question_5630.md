# Q5630: [allow_all] `SHELL` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `rollback.override` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `SHELL` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `rollback.override` section the deploy process changes the shell binary used to interpret a step, redirecting execution to an attacker program?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `SHELL` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `rollback.override` section of the fork shipit.yml under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `rollback.override` step inherits `SHELL` from Command#unbundled_env and changes the shell binary used to interpret a step, redirecting execution to an attacker program
- Invariant to test: The `rollback.override` step inherits no fork-controllable key such as `SHELL`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `rollback.override` step, inject `SHELL` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
