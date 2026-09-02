### Title
Arbitrary env-var injection via PR labels bypasses reserved-key overrides and reaches `Command#start` unfiltered - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every GitHub label on a pull request directly into the deploy environment, keyed by `label_name.upcase => "true"`, with no allow-list or collision check. Because `TaskCommands#env` merges `@stack.env` before the hardcoded safety keys, `deploy_spec.machine_env`, and `@task.env`, any label whose upcased name is not one of those keys (e.g. `rubylib`) survives untouched into the environment passed to `Command#start`/`PTY.spawn`.

### Finding Description
Binding claimed to hold: `TaskCommands#env` keys == `Shipit.env` keys ∪ `deploy_spec.machine_env` keys ∪ {`SHIPIT_USER`, `EMAIL`, `BUNDLE_PATH`, `SHIPIT_LINK`, `TASK_ID`, `IGNORED_SAFETIES`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`} ∪ `@task.env` keys, and must NOT include arbitrary keys derived from `pull_request.labels`.

Tracing the code shows this binding is broken:
- `ReviewStack#env` ( [1](#0-0) ) merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into the stack's base env, with the label text fully attacker-controlled and no filtering against reserved names.
- `TaskCommands#env` ( [2](#0-1) ) builds the final env by merging `super` (Shipit-level env), then `@stack.env` (which for a `ReviewStack` includes the label-derived keys), then the fixed literal keys, then `deploy_spec.machine_env`, then `@task.env`. Later `merge` calls only overwrite keys that literally match; any label key not in that fixed set (e.g. `RUBYLIB`, `LD_PRELOAD`, `RUBYOPT`, `GEM_HOME`, `PATH`, etc.) passes through unchanged into the final hash.
- The label itself reaches `pull_request.labels` via the webhook handler `LabelCapturingHandler#capture_labels`, which persists `params.pull_request.labels.map(&:name)` verbatim from the GitHub webhook payload ( [3](#0-2) ). Labels are attacker-controlled: any user who can label their own PR (including on their own repository/fork configured with Shipit) controls this string, and there is no `ExplicitParameters` schema restriction on label name content beyond being a `String`.
- The resulting env is used directly to build `Command`s for install/deploy steps (`install_dependencies`, `perform` in `lib/shipit/task_commands.rb`), which are ultimately executed via `Command#start`/`PTY.spawn` on the deploy host.

None of the existing guards prevent this: `verify_signature`/webhook signature validation only proves the payload came from GitHub for that repo, not that the label content is safe; `ExplicitParameters` only validates types/shape, not content; there is no `EnvironmentVariables#permit`-style allow-list applied to `ReviewStack#env`.

### Impact Explanation
An attacker who can open/label a pull request on a repository that has Shipit review stacks enabled can inject arbitrary environment variables (e.g. `RUBYLIB`, `RUBYOPT`, `LD_PRELOAD`, `BUNDLE_GEMFILE`) into the environment of every shell command Shipit runs for that review stack's deploy/build/test steps. Depending on what those commands are (bundler, ruby, rake, git, etc.), this can escalate to arbitrary code execution on the deploy host — matching the Critical impact category (RCE via `Command`/`PTY.spawn`). The blast radius is scoped to the repository/stack the attacker controls (their own PR's review stack), but any repository onboarded to Shipit with review-stack support is equally exposed, and the technique is repeatable on every relabel event.

### Likelihood Explanation
Preconditions: the target repository must have Shipit review stacks enabled (`has_one :pull_request` / `ReviewStack` flow active) and the PR must reach an active, non-archived stack. The attacker needs no Shipit credentials — only the ability to open a PR and apply a label to it (trivial on a repo they own, or any repo where they can label PRs, e.g. via fork + PR if labeling is permitted by GitHub for their role, or on any repo where they are a collaborator). Cost is essentially one webhook-triggering GitHub action (label a PR). This is fully repeatable and does not require secrets.

### Recommendation
Do not let PR label names populate arbitrary environment variable keys. Either: (1) drop `ReviewStack#env`'s label-to-env mapping entirely, or (2) restrict it to a fixed, non-reserved prefix (e.g. always prefix with `SHIPIT_LABEL_` before upcasing) and validate label names against a strict allow-listed character set, and (3) ensure the label-derived keys are merged before/never override anything, and are excluded from ever matching well-known interpreter/loader environment variable names (`RUBYLIB`, `RUBYOPT`, `LD_PRELOAD`, `PATH`, `BUNDLE_*`, `GEM_*`, etc.) via an explicit denylist or allow-list check in `TaskCommands#env`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_env_test.rb (proof sketch)
require "test_helper"

module Shipit
  class ReviewStackLabelEnvInjectionTest < ActiveSupport::TestCase
    test "PR label cannot inject arbitrary env keys like RUBYLIB into TaskCommands#env" do
      stack = shipit_fixtures(:shipit) # a ReviewStack fixture with an associated pull_request
      stack.pull_request.update!(labels: ['rubylib'])

      task = stack.tasks.build(definition: TaskDefinition.new({}, 'deploy'))
      env = TaskCommands.new(task).env

      # Binding under test: 'RUBYLIB' must NOT be present, since it is not one of
      # Shipit.env keys, deploy_spec.machine_env keys, the fixed literal keys, or @task.env keys.
      refute_includes env.keys, 'RUBYLIB',
        "Attacker-controlled PR label leaked into task environment as RUBYLIB"
    end
  end
end
```
Expected current behavior: the assertion fails, because `env['RUBYLIB'] == "true"` after the merge chain in `TaskCommands#env`, demonstrating the broken binding.

### Citations

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
    end
```

**File:** lib/shipit/task_commands.rb (L33-48)
```ruby
    def env
      super
        .merge(@stack.env)
        .merge(
          'SHIPIT_USER' => "#{@task.author.login} (#{normalized_author_name}) via Shipit",
          'EMAIL' => @task.author.email,
          'BUNDLE_PATH' => Rails.root.join('data', 'bundler').to_s,
          'SHIPIT_LINK' => @task.permalink,
          'TASK_ID' => @task.id.to_s,
          'IGNORED_SAFETIES' => @task.ignored_safeties? ? '1' : '0',
          'GIT_COMMITTER_NAME' => @task.user&.name || Shipit.committer_name,
          'GIT_COMMITTER_EMAIL' => @task.user&.email || Shipit.committer_email
        )
        .merge(deploy_spec.machine_env)
        .merge(@task.env)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```
