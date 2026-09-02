### Title
`ReviewStack#env` label merge silently overrides operator-configured `Stack#env` keys (e.g. `ENVIRONMENT`, `DEPLOY_URL`) - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges PR labels (upcased, value `"true"`) on top of `Stack#env`'s operator-defined keys, so any PR label whose upcased name matches a reserved key (`ENVIRONMENT`, `DEPLOY_URL`, `BRANCH`, `LAST_DEPLOYED_SHA`, `GITHUB_REPO_OWNER`, `GITHUB_REPO_NAME`) overwrites that value before it reaches `Command#start`/`PTY.spawn`. The PR author, who is unprivileged relative to the repository's `shipit.yml` configuration, controls this collision simply by applying a label to their own PR.

### Finding Description
The claimed binding is: `Stack#env['ENVIRONMENT'] == ReviewStack#env['ENVIRONMENT']` (and similarly for `DEPLOY_URL`) — i.e., the value written by the operator via `Stack#env` should be the same value read by `Command#unbundled_env` / `PTY.spawn`.

`Stack#env` computes fixed operator/system-controlled values: [1](#0-0) 

`ReviewStack#env` overrides `Stack#env` and merges a hash built from `pull_request.labels`, with **labels as the second argument to `Hash#merge`, i.e., the labels win on key collision**: [2](#0-1) 

`pull_request.labels` is populated straight from the webhook payload with no restriction against reserved names: [3](#0-2) 

The resulting env hash is eventually passed into `Command.new(..., env: ...)`, stored in `@env`, and merged into the process environment right before `PTY.spawn`: [4](#0-3) [5](#0-4) 

**Exploit flow**: An attacker who owns/controls a fork PR against a repository that has ReviewStacks enabled adds a label named `environment` (or `deploy_url`, `branch`, etc.) to their own PR. GitHub emits a `pull_request` `labeled` webhook, handled by `LabelCapturingHandler`, which persists `pull_request.labels` verbatim (only requiring `name: String` in the `ExplicitParameters` schema — no allow-list, no case restriction). When any deploy/task command is built with `ReviewStack#env`, the merge causes `labels['ENVIRONMENT'] = 'true'` to overwrite `super['ENVIRONMENT']` (the operator's actual environment name computed from `environment` attribute), or `labels['DEPLOY_URL'] = 'true'` to overwrite the operator's real `deploy_url`. This corrupted hash is what `Command` interpolates into arguments (`interpolate_environment_variables`) and injects into `PTY.spawn`'s environment.

**Why existing guards don't stop this**: `verify_signature`/`GitHubApp#verify_webhook_signature` only authenticate that the webhook came from GitHub for that repo — they do not constrain label content. `ExplicitParameters` only validates label `name` is a `String`, not that it avoids reserved keys. There is no `EnvironmentVariables#permit`/allow-list applied at the `ReviewStack#env` merge site, and no re-validation that reserved keys aren't clobbered after the merge.

### Impact Explanation
The attacker (any user able to open/label a PR on a repository with ReviewStacks) can force the effective `ENVIRONMENT`/`DEPLOY_URL`/`BRANCH` seen by every shell command run for that review stack (via `Command`/`PTY.spawn`) to the fixed literal `"true"` instead of the operator-configured value. Any `shipit.yml` step whose behavior branches on `$ENVIRONMENT` or `$DEPLOY_URL` (e.g., selecting a deploy target, gating a promotion, choosing a webhook/notification URL) will observe the wrong value. This is limited to the attacker's own repository/review stack (no cross-tenant mutation is demonstrated), and the injected value is fixed to the literal string `"true"` rather than attacker-chosen content, so it does not by itself grant arbitrary command injection or credential exfiltration. The realistic impact is corruption of environment-dependent deploy logic within the attacker's own repo's review stack — this is a real but repo-scoped integrity break rather than a cross-tenant RCE or secret-exfiltration primitive.

### Likelihood Explanation
Preconditions: the target repository must have ReviewStacks enabled and a `shipit.yml`/commands relying on `ENVIRONMENT`, `DEPLOY_URL`, `BRANCH`, or the other `Stack#env` keys. Attacker cost is trivial — labeling one's own PR requires no special privilege beyond opening a PR on a repo they control (or any repo where they can apply labels). It is fully repeatable and deterministic (any label name that upcases to a reserved key always wins the merge).

### Recommendation
In `ReviewStack#env`, reverse the merge precedence so operator-defined keys always win, and/or filter out label-derived keys that collide with `Stack::ENV`-reserved names before merging, e.g.:
```ruby
def env
  return super unless pull_request.present?

  label_env = pull_request.labels.each_with_object({}) { |l, h| h[l.upcase] = "true" }
  label_env.merge(super) # operator config takes precedence
end
```
Alternatively, explicitly reject/strip labels whose upcased name matches any key already defined by `Stack#env`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_env_test.rb
require 'test_helper'

module Shipit
  class ReviewStackEnvTest < ActiveSupport::TestCase
    test "PR label 'ENVIRONMENT' overwrites Stack#env's operator-configured value" do
      stack = shipit_stacks(:shipit) # or any ReviewStack fixture
      review_stack = ReviewStack.new(stack.attributes.except('id'))
      review_stack.pull_request = PullRequest.new(labels: ['ENVIRONMENT'])

      base_env_value = Stack.instance_method(:env).bind(review_stack).call['ENVIRONMENT']
      merged_env_value = review_stack.env['ENVIRONMENT']

      assert_equal stack.environment, base_env_value
      refute_equal base_env_value, merged_env_value
      assert_equal 'true', merged_env_value

      # Feed into Command to show it reaches unbundled_env / PTY.spawn input
      command = Shipit::Command.new('env', chdir: Dir.tmpdir, env: review_stack.env)
      assert_equal 'true', command.unbundled_env['ENVIRONMENT']
    end
  end
end
```
This asserts the exact broken binding: `Stack#env['ENVIRONMENT'] == stack.environment` on one side, but `ReviewStack#env['ENVIRONMENT'] == 'true'` (label-controlled) on the other, and shows the corrupted value flows into `Command#unbundled_env`, the hash passed to `PTY.spawn`.

### Citations

**File:** app/models/shipit/stack.rb (L54-63)
```ruby
    def env
      {
        'ENVIRONMENT' => environment,
        'LAST_DEPLOYED_SHA' => last_deployed_commit.sha,
        'GITHUB_REPO_OWNER' => repository.owner,
        'GITHUB_REPO_NAME' => repository.name,
        'DEPLOY_URL' => deploy_url,
        'BRANCH' => branch
      }
    end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** lib/shipit/command.rb (L85-98)
```ruby
    def start(&block)
      return if @started

      @control_block = block
      @out = @pid = nil
      FileUtils.mkdir_p(@chdir)
      begin
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
        child_in.close
      rescue Errno::ENOENT
        raise NotFound, "#{Shellwords.split(interpolated_arguments.first).first}: command not found"
      rescue Errno::EACCES
        raise Denied, "#{Shellwords.split(interpolated_arguments.first).first}: Permission denied"
      end
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```
