# Q1293: `BUNDLE_PATH` hijacks `bundle install` (ruby/bundler) via a `machine.environment` entry in the fork branch's `shipit.yml`

## Question
When a review stack's deploy runs the `bundle install` step, can an unprivileged fork PR author set `BUNDLE_PATH` through a `machine.environment` entry in the fork branch's `shipit.yml` so the ruby/bundler process redirects bundler to an attacker-populated vendored gem tree that runs on load?

## Target
- File/function: app/models/shipit/review_stack.rb + lib/shipit/task_commands.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack -> PerformTaskJob -> Command#start (PTY.spawn)
- Attacker controls: env key `BUNDLE_PATH` via a `machine.environment` entry in the fork branch's `shipit.yml`, with the deploy spec step `bundle install`
- Exploit idea: `DeploySpec#machine_env` returns `config('machine','environment')` verbatim and `TaskCommands#env` merges it into the hash passed to `PTY.spawn`, and the fork PR author controls that file on the review-stack branch; `Command#unbundled_env` carries `BUNDLE_PATH` unfiltered into the `bundle install` subprocess, which redirects bundler to an attacker-populated vendored gem tree that runs on load
- Invariant to test: The `bundle install` subprocess inherits no fork-controllable environment key such as `BUNDLE_PATH`.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build the review-stack task with step `bundle install` and injected `BUNDLE_PATH`, assert Command#unbundled_env passes `BUNDLE_PATH` to the spawned process.
