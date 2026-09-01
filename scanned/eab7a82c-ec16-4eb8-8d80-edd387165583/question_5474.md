# Q5474: [prevent_with_label] `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `dependencies.override` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `GIT_CONFIG_GLOBAL` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `dependencies.override` section the deploy process supplies an attacker git config file defining a hook or fsmonitor command git executes?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `dependencies.override` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `dependencies.override` step inherits `GIT_CONFIG_GLOBAL` from Command#unbundled_env and supplies an attacker git config file defining a hook or fsmonitor command git executes
- Invariant to test: The `dependencies.override` step inherits no fork-controllable key such as `GIT_CONFIG_GLOBAL`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `dependencies.override` step, inject `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
