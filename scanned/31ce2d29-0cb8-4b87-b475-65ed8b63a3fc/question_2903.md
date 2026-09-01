# Q2903: [allow_with_label] `GIT_SSH` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `tasks.<name>.steps` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `GIT_SSH` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `tasks.<name>.steps` section the deploy process names an arbitrary program git executes for ssh transport?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `GIT_SSH` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `tasks.<name>.steps` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `tasks.<name>.steps` step inherits `GIT_SSH` from Command#unbundled_env and names an arbitrary program git executes for ssh transport
- Invariant to test: The `tasks.<name>.steps` step inherits no fork-controllable key such as `GIT_SSH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `tasks.<name>.steps` step, inject `GIT_SSH` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
