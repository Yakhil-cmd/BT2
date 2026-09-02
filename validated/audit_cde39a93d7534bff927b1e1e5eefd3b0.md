### Title
`deploy_spec.machine_env` from `shipit.yml` can override Bundler-stripped env vars in `Command#unbundled_env` - ([File: lib/shipit/command.rb])

### Summary
`Command::BASE_ENV` deliberately nils out any key that `Bundler.unbundled_env`/`clean_env` strips (e.g. `BUNDLE_GEMFILE`, `RUBYLIB`, `RUBYOPT`), but `TaskCommands#env` merges `deploy_spec.machine_env` — a value read verbatim from the repository's `shipit.yml`/`.shipit/shipit.yml` — on top of that base with no key filtering, and `Command#unbundled_env` merges `@env` last. Any repository that can get a `shipit.yml` change into the branch that Shipit checks out for deploy can therefore reinject one of these stripped variables into the process passed to `PTY.spawn`.

### Finding Description
The broken binding: `Command::BASE_ENV[key] == nil` for every `key` that `Bundler.unbundled_env`/`clean_env` removed [1](#0-0)  is expected to remain `nil` in the value handed to `PTY.spawn` via `unbundled_env`, but that binding is not enforced anywhere downstream — `unbundled_env` merges `@env.stringify_keys` unconditionally last [2](#0-1) .

`@env` for deploy/rollback/task commands is built by `TaskCommands#env`, which merges, in order: stack env, hard-coded vars, then `deploy_spec.machine_env`, then `@task.env` [3](#0-2) . `deploy_spec.machine_env` is `config('machine', 'environment') || {}` [4](#0-3) , i.e. read directly and unfiltered from the `machine.environment` section of the checked-out `shipit.yml`, via `DeploySpec::FileSystem#load_config`/`config_file_path` [5](#0-4) . Unlike `deploy_variables`/`rollback_variables`, which are explicitly whitelisted with `filter_deploy_envs`/`filter_rollback_envs` via `EnvironmentVariables#permit` [6](#0-5) , `machine_env` has no such filtering — any key/value pair a repository declares under `machine.environment` is trusted as-is.

Root cause: `Command::BASE_ENV`'s "strip Bundler vars" invariant is only established once at class-load time and is never re-applied or protected against later merges; `unbundled_env` naively layers `@env` on top without excluding the Bundler-managed keys.

Exploit path: a repository's `shipit.yml` sets
```yaml
machine:
  environment:
    RUBYLIB: /path/attacker/controls
```
When this configuration reaches Shipit for a deploy/rollback/task on that stack, `TaskCommands#env` merges this value, and `Command#unbundled_env` returns `RUBYLIB` set to the attacker value rather than `nil`, so any subsequent `ruby`/`bundle exec` step's require path is attacker-controlled, achieving RCE on the deploy host.

Where existing guards fail: `EnvironmentVariables#permit`/`filter_deploy_envs`/`filter_rollback_envs` only apply to `deploy.variables`/`rollback.variables`, not to `machine.environment`. Nothing in `DeploySpec`, `DeploySpec::FileSystem`, `TaskCommands`, or `Command` denies-lists Bundler-managed keys before or during the merges.

### Impact Explanation
If reachable, this is Critical: reintroducing `RUBYLIB`/`BUNDLE_GEMFILE`/`RUBYOPT` lets a party who controls `shipit.yml` content in the deployed tree run arbitrary Ruby code inside any later Ruby/Bundler invocation on the deploy host, i.e. RCE via `Command`/`PTY.spawn`. However, this is gated entirely on whether `shipit.yml` content from an *unprivileged* PR ever becomes the `shipit.yml` actually used for a deploy — that depends on whether the PR is merged, and merging (`MergeRequest#merge!`) is only performed by `ProcessMergeRequestsJob` after CI/status checks pass and the merge queue is enabled by the repository owner [7](#0-6) [8](#0-7) . Whether CI/status requirements can be satisfied entirely under attacker control (self-hosted CI reporting success on their own fork/PR) is a separate question about GitHub Status/webhook trust that is out of scope for `Command`/`status_controller.rb` itself and was not verified here.

### Likelihood Explanation
Preconditions are non-trivial: the attacker's `machine.environment.RUBYLIB`/`BUNDLE_GEMFILE` change must land in the commit that is actually checked out and deployed for the stack — this requires either (a) the change being merged normally by a maintainer/CI process (not attacker-controlled), or (b) the repository operating an auto-merge queue with status checks the attacker can force to pass. The engine code itself (`Command`, `TaskCommands`, `DeploySpec`) applies no defense once such a commit is checked out and deployed, so once the config lands, the exploit is deterministic and repeatable on every subsequent task using that `Command` instance.

### Recommendation
In `Command#unbundled_env` (or in `TaskCommands#env`/`DeploySpec#machine_env`), explicitly strip or deny-list Bundler-managed keys (`BUNDLE_GEMFILE`, `RUBYLIB`, `RUBYOPT`, `BUNDLE_BIN_PATH`, `BUNDLE_ORIG_*`, `GEM_HOME`, `GEM_PATH`) from `@env`/`machine_env` before merging, e.g.:
```ruby
def unbundled_env
  BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys.except(*STRIPPED_KEYS))
end
```
where `STRIPPED_KEYS` is derived from `ENV.keys - Bundler.unbundled_env.keys` (the same set computed for `BASE_ENV`), so no later merge can resurrect them.

### Proof of Concept
```ruby
# test/unit/command_test.rb
test "#unbundled_env cannot be used to reintroduce bundler-stripped variables" do
  stripped_key = (ENV.keys - Bundler.unbundled_env.keys).first
  skip "no bundler-stripped keys present in this environment" unless stripped_key
  assert_nil Shipit::Command::BASE_ENV[stripped_key]

  command = Shipit::Command.new('true', chdir: '.', env: { stripped_key => '/tmp/evil' })
  assert_nil command.unbundled_env[stripped_key],
    "#{stripped_key} should remain stripped, but machine_env-style @env merge reintroduced it"
end
```
This directly demonstrates the binding stated in the question is violated: `BASE_ENV[stripped_key]` is `nil`, but `Command#unbundled_env[stripped_key]` becomes the attacker-supplied value once `@env` contains it — confirming the merge-order defect in `lib/shipit/command.rb:103-105`. The remaining, unverified piece is whether an unprivileged attacker can get such a key into `deploy_spec.machine_env` for a real deploy without maintainer/CI cooperation; that would require a separate PoC against `MergeRequest`/`ProcessMergeRequestsJob`/status-check trust, which was not confirmed in this investigation.

### Citations

**File:** lib/shipit/command.rb (L17-18)
```ruby
    unbundled_env = Bundler.respond_to?(:unbundled_env) ? Bundler.unbundled_env : Bundler.clean_env
    BASE_ENV = unbundled_env.merge((ENV.keys - unbundled_env.keys).map { |k| [k, nil] }.to_h)
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
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

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
    end
```

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L98-142)
```ruby
      def load_config
        return if config_file_path.nil?

        if !Shipit.respect_bare_shipit_file? && config_file_path.to_s.end_with?(*bare_shipit_filenames)
          return { 'deploy' => { 'pre' => [shipit_not_obeying_bare_file_echo_command, 'exit 1'] } }
        end

        config_obj = read_config(config_file_path)
        build_config(config_file_path, config_obj)
      end

      YAML_EXTENSIONS = ["yml", "yaml"].freeze

      def shipit_file_names_in_priority_order
        YAML_EXTENSIONS.flat_map do |ext|
          [
            "#{app_name}.#{@env}.#{ext}",
            ".shipit/#{app_name}.#{@env}.#{ext}",

            "#{app_name}.#{ext}",
            ".shipit/#{app_name}.#{ext}",

            "shipit.#{@env}.#{ext}",
            ".shipit/#{@env}.#{ext}",

            "shipit.#{ext}",
            ".shipit/shipit.#{ext}"
          ]
        end.uniq
      end

      def bare_shipit_filenames
        YAML_EXTENSIONS.flat_map do |ext|
          ["#{app_name}.#{ext}", "shipit.#{ext}", ".shipit/#{app_name}.#{ext}", ".shipit/shipit.#{ext}"]
        end.uniq
      end

      def config_file_path
        shipit_file_names_in_priority_order.each do |filename|
          path = file(filename, root: true)
          return path if path.exist?
        end

        nil
      end
```

**File:** app/models/shipit/merge_request.rb (L164-191)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-32)
```ruby
    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end

      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
      end
    end
```
