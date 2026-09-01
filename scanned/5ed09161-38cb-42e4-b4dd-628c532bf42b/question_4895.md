# Q4895: shell metacharacters in a step string in shipit.yml `deploy.override`

## Question
Can an unprivileged fork PR author abuse the `deploy.override` section of the review-stack `shipit.yml` so that the fork's `shipit.yml` `deploy.override`/`dependencies.override` step contains `;`, `$(...)`, backticks or `&&`, defeating the assumption that `Command#parse_arguments` keeps the step as a single string and `PTY.spawn(env?

## Target
- File/function: app/models/shipit/deploy_spec.rb + app/models/shipit/deploy_spec/file_system.rb + lib/shipit/command.rb
- Entrypoint: Unprivileged PR -> ReviewStack shipit.yml -> TaskCommands -> Command#start
- Attacker controls: the `deploy.override` content on the fork branch (the fork's `shipit.yml` `deploy.override`/`dependencies.override` step contains `;`, `$(...)`, backticks or `&&`)
- Exploit idea: `DeploySpec` reads `deploy.override` from the fork-authored shipit.yml and feeds it into command building where `Command#parse_arguments` keeps the step as a single string and `PTY.spawn(env, *interpolated_arguments)` runs it through a shell, so metacharacters execute
- Invariant to test: Every value read from a fork-authored shipit.yml is treated as untrusted and cannot alter the executed argv or leak Shipit secrets.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: build a DeploySpec whose `deploy.override` carries the payload, run through Command building, assert the argv/leak.
