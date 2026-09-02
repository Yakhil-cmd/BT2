This confirms `DeployCommands#steps` reads `deploy_spec.deploy_steps!`, where `deploy_spec` (defined in `TaskCommands#deploy_spec`, `app/models/shipit/deploy_spec/file_system.rb`) is built from the task's own `working_directory`, which is checked out to the actual commit being deployed via `checkout(commit)` in `lib/shipit/task_commands.rb`. This means the actually-executed `deploy.override` steps are read live from the target commit's `shipit.yml`, not from `cached_deploy_spec`. The `cached_deploy_spec` (HEAD-derived, via `CacheDeploySpecJob`) is only used for things like `find_task_definition`, `variables`/env whitelisting, and UI metadata — not for the deploy/rollback step commands themselves. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

This rules out the "ref approved vs ref whose shipit.yml executes" analog for deploy/rollback: the actual steps executed do come from the target commit's own file, so there's no signature/binding mismatch there for the core deploy path. I did not find a concrete, in-scope binding break matching the BitArray bug class (a field acted on but never covered by verification, or an authenticated identity diverging from an executed identity) that meets the required Critical/High impact bar (RCE, auth bypass, credential exfiltration, cross-repo writes, unauthorized ship/rollback/merge, or SSRF with GitHub credentials):

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) selects the webhook secret based on `repository_owner`, itself parsed from the raw JSON body — but since GitHub's HMAC signature covers the entire raw body including that field, an attacker cannot forge a mismatch without already knowing the correct secret. [5](#0-4) 
- `EnvironmentVariables#permit` (`lib/shipit/environment_variables.rb:13-44`) strictly whitelists env keys against `variable_definitions`, and `Stack#trigger_task`/`build_deploy` (`app/models/shipit/stack.rb:139-172`) apply this filter before task/deploy creation — env key permitted matches env key spawned. [6](#0-5) 
- `User#authorized?` (`app/models/shipit/user.rb:80-82`) and `Authentication#force_github_authentication` (`app/controllers/concerns/shipit/authentication.rb:20-34`) bind the session's `User` to `Shipit.github_teams` membership consistently, with no divergence found between the GitHub identity and the session's bound `User`. [7](#0-6) 

#No vulnerability found for this question.

### Citations

**File:** lib/shipit/deploy_commands.rb (L1-8)
```ruby
# frozen_string_literal: true

module Shipit
  class DeployCommands < TaskCommands
    def steps
      deploy_spec.deploy_steps!
    end

```

**File:** lib/shipit/task_commands.rb (L13-15)
```ruby
    def deploy_spec
      @deploy_spec ||= DeploySpec::FileSystem.new(@task.working_directory, @stack)
    end
```

**File:** lib/shipit/task_commands.rb (L50-59)
```ruby
    def checkout(commit)
      git(
        '-c',
        'advice.detachedHead=false',
        'checkout',
        '--quiet',
        commit.sha,
        chdir: @task.working_directory
      )
    end
```

**File:** app/jobs/shipit/cache_deploy_spec_job.rb (L16-23)
```ruby
    def perform(stack)
      return if stack.inaccessible?

      commit = stack.commits.reachable.last
      commands = Commands.for(stack)
      commands.with_temporary_working_directory(commit:, recursive: false) do |path|
        stack.update!(cached_deploy_spec: DeploySpec::FileSystem.new(path, stack))
      end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** lib/shipit/environment_variables.rb (L13-44)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end

    def interpolate(argument)
      return argument unless @env

      argument.gsub(/(\$\w+)/) do |variable|
        variable.sub!('$', '')
        Shellwords.escape(@env.fetch(variable) { ENV[variable] })
      end
    end

    private

    def initialize(env)
      @env = env
    end

    def sanitize_env_vars(variable_definitions)
      allowed_variables = variable_definitions.map(&:name)

      allowed, disallowed = @env.partition { |k, _| allowed_variables.include?(k) }.map(&:to_h)

      error_message = "Variables #{disallowed.keys.to_sentence} have not been whitelisted"
      raise NotPermitted, error_message unless disallowed.empty?

      allowed
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
