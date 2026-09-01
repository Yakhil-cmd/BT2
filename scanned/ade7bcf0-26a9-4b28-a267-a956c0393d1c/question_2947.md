# Q2947: [allow_with_label] `PERL5LIB` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `deploy.override` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `PERL5LIB` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `deploy.override` section the deploy process adds an attacker perl include path?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `PERL5LIB` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `deploy.override` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `deploy.override` step inherits `PERL5LIB` from Command#unbundled_env and adds an attacker perl include path
- Invariant to test: The `deploy.override` step inherits no fork-controllable key such as `PERL5LIB`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `deploy.override` step, inject `PERL5LIB` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
