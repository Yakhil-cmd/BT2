# Q0650: [allow_with_label] `RUBYOPT` via a `machine.environment` entry in the fork branch's `shipit.yml` affecting the `rollback.override` phase

## Question
On a repo with provisioning_behavior=`allow_with_label`, can an unprivileged fork PR inject `RUBYOPT` through a `machine.environment` entry in the fork branch's `shipit.yml` so that when the review stack runs its `rollback.override` section the deploy process injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup?

## Target
- File/function: app/models/shipit/review_stack.rb + app/models/shipit/deploy_spec.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> DeploySpec -> Command#start
- Attacker controls: `RUBYOPT` via a `machine.environment` entry in the fork branch's `shipit.yml`; the `rollback.override` section of the fork shipit.yml under `allow_with_label`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; the `rollback.override` step inherits `RUBYOPT` from Command#unbundled_env and injects `-r/path/to/evil` so any `ruby`/`rake`/`bundle` step requires attacker code at startup
- Invariant to test: The `rollback.override` step inherits no fork-controllable key such as `RUBYOPT`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest[allow_with_label]: build the review-stack `rollback.override` step, inject `RUBYOPT` via a `machine.environment` entry in the fork branch's `shipit.yml`, assert the env reaches the spawned process.
