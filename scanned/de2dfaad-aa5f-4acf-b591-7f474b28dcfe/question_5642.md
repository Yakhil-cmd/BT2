# Q5642: [prevent_with_label] `RUBYLIB` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `deploy.variables` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `RUBYLIB` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `deploy.variables` section the deploy process prepends an attacker load path so `require` in a ruby step loads attacker code?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `RUBYLIB` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `deploy.variables` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `deploy.variables` step inherits `RUBYLIB` from Command#unbundled_env and prepends an attacker load path so `require` in a ruby step loads attacker code
- Invariant to test: The `deploy.variables` step inherits no fork-controllable key such as `RUBYLIB`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `deploy.variables` step, inject `RUBYLIB` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
