# Q5257: [allow_with_label] `BUNDLE_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `fetch` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `BUNDLE_PATH` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `fetch` section the deploy process redirects bundler to an attacker-populated vendored gem tree that runs on load?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `BUNDLE_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `fetch` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `fetch` step inherits `BUNDLE_PATH` from Command#unbundled_env and redirects bundler to an attacker-populated vendored gem tree that runs on load
- Invariant to test: The `fetch` step inherits no fork-controllable key such as `BUNDLE_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `fetch` step, inject `BUNDLE_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
