# Q0453: [prevent_with_label] `PYTHONSTARTUP` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `review.checklist` phase

## Question
On a repo with provisioning_behavior=`prevent_with_label`, can an unprivileged fork PR inject `PYTHONSTARTUP` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `review.checklist` section the deploy process names a python file executed at interpreter start?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `PYTHONSTARTUP` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `review.checklist` section of the fork shipit.yml under `prevent_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `review.checklist` step inherits `PYTHONSTARTUP` from Command#unbundled_env and names a python file executed at interpreter start
- Invariant to test: The `review.checklist` step inherits no fork-controllable key such as `PYTHONSTARTUP`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[prevent_with_label]: build the review-stack `review.checklist` step, inject `PYTHONSTARTUP` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
