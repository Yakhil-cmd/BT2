# Q0231: [allow_all] `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `deploy.variables` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `SSH_ASKPASS` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `deploy.variables` section the deploy process names a program executed to answer ssh password prompts?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `deploy.variables` section of the fork shipit.yml under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `deploy.variables` step inherits `SSH_ASKPASS` from Command#unbundled_env and names a program executed to answer ssh password prompts
- Invariant to test: The `deploy.variables` step inherits no fork-controllable key such as `SSH_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `deploy.variables` step, inject `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
