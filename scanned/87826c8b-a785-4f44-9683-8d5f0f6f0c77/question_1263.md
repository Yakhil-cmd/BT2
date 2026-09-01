# Q1263: [prevent_with_label] `NODE_OPTIONS` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `tasks.<name>.steps` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `NODE_OPTIONS` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `tasks.<name>.steps` section the deploy process injects `--require /path/to/evil` so any node step loads attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `NODE_OPTIONS` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `tasks.<name>.steps` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `tasks.<name>.steps` step inherits `NODE_OPTIONS` from Command#unbundled_env and injects `--require /path/to/evil` so any node step loads attacker code
- Invariant to test: The `tasks.<name>.steps` step inherits no fork-controllable key such as `NODE_OPTIONS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `tasks.<name>.steps` step, inject `NODE_OPTIONS` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
