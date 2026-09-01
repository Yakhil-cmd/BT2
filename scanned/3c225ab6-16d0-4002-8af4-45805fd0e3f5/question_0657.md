# Q0657: [prevent_with_label] `BASH_ENV` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `machine.environment` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `BASH_ENV` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `machine.environment` section the deploy process names a file bash sources before running a non-interactive `shipit.yml` step?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `BASH_ENV` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `machine.environment` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `machine.environment` step inherits `BASH_ENV` from Command#unbundled_env and names a file bash sources before running a non-interactive `shipit.yml` step
- Invariant to test: The `machine.environment` step inherits no fork-controllable key such as `BASH_ENV`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `machine.environment` step, inject `BASH_ENV` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
