# Q2341: [allow_with_label] `NODE_OPTIONS` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `fetch` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `NODE_OPTIONS` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `fetch` section the deploy process injects `--require /path/to/evil` so any node step loads attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `NODE_OPTIONS` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `fetch` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `fetch` step inherits `NODE_OPTIONS` from Command#unbundled_env and injects `--require /path/to/evil` so any node step loads attacker code
- Invariant to test: The `fetch` step inherits no fork-controllable key such as `NODE_OPTIONS`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `fetch` step, inject `NODE_OPTIONS` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
