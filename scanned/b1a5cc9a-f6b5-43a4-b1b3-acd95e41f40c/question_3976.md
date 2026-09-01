# Q3976: [allow_all] `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `deploy.override` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `GIT_CONFIG_GLOBAL` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `deploy.override` section the deploy process supplies an attacker git config file defining a hook or fsmonitor command git executes?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `deploy.override` section of the fork shipit.yml under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `deploy.override` step inherits `GIT_CONFIG_GLOBAL` from Command#unbundled_env and supplies an attacker git config file defining a hook or fsmonitor command git executes
- Invariant to test: The `deploy.override` step inherits no fork-controllable key such as `GIT_CONFIG_GLOBAL`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `deploy.override` step, inject `GIT_CONFIG_GLOBAL` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
