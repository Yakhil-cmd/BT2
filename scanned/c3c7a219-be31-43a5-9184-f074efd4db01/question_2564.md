# Q2564: [prevent_with_label] `GIT_SSH_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `fetch` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `GIT_SSH_COMMAND` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `fetch` section the deploy process replaces the ssh program git invokes with an arbitrary command during fetch/clone?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `GIT_SSH_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `fetch` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `fetch` step inherits `GIT_SSH_COMMAND` from Command#unbundled_env and replaces the ssh program git invokes with an arbitrary command during fetch/clone
- Invariant to test: The `fetch` step inherits no fork-controllable key such as `GIT_SSH_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `fetch` step, inject `GIT_SSH_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
