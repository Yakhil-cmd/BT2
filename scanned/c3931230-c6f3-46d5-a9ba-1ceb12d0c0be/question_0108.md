# Q0108: [allow_all] `BUNDLE_GEMFILE` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `ci.require` phase

## Question
On a repo with provisioning_behavior=`allow_all`, can an unprivileged fork PR inject `BUNDLE_GEMFILE` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `ci.require` section the deploy process points bundler at an attacker Gemfile whose evaluated code runs?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `BUNDLE_GEMFILE` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `ci.require` section of the fork shipit.yml under `allow_all`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `ci.require` step inherits `BUNDLE_GEMFILE` from Command#unbundled_env and points bundler at an attacker Gemfile whose evaluated code runs
- Invariant to test: The `ci.require` step inherits no fork-controllable key such as `BUNDLE_GEMFILE`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_all]: build the review-stack `ci.require` step, inject `BUNDLE_GEMFILE` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
