# Q2110: [prevent_with_label] `GIT_PROXY_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `provision.handler_name` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `GIT_PROXY_COMMAND` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `provision.handler_name` section the deploy process names an arbitrary command git runs to open transport connections?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `GIT_PROXY_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `provision.handler_name` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `provision.handler_name` step inherits `GIT_PROXY_COMMAND` from Command#unbundled_env and names an arbitrary command git runs to open transport connections
- Invariant to test: The `provision.handler_name` step inherits no fork-controllable key such as `GIT_PROXY_COMMAND`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `provision.handler_name` step, inject `GIT_PROXY_COMMAND` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
