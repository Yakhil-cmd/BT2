# Q1038: [prevent_with_label] `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `deploy.override` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `SSH_ASKPASS` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `deploy.override` section the deploy process names a program executed to answer ssh password prompts?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `deploy.override` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `deploy.override` step inherits `SSH_ASKPASS` from Command#unbundled_env and names a program executed to answer ssh password prompts
- Invariant to test: The `deploy.override` step inherits no fork-controllable key such as `SSH_ASKPASS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `deploy.override` step, inject `SSH_ASKPASS` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
