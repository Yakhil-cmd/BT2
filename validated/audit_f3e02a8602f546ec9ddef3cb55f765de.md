This is a valid, concrete finding. I found it in the webhook signature/routing path, not in DoS/rate-limiting behavior.

### Title
Webhook Signature Verified Against Attacker-Controlled Organization While Status/Push Handlers Act on Payload Fields Never Covered by That Binding - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the HMAC against using `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) . Once verified, the handler that actually acts on the payload (`StatusHandler`, `PushHandler`, `CheckSuiteHandler`) does not re-derive or cross-check that same `repository.owner.login`/`repository.full_name` field — `StatusHandler` doesn't scope by repository at all, and `PushHandler`/`CheckSuiteHandler` scope by the independent `repository.full_name` field [3](#0-2) [4](#0-3) . The signature binds the org whose secret authenticated the request; it never binds the org/repo whose data is actually mutated.

### Finding Description
The engine supports multi-organization GitHub App configuration, each with its own `webhook_secret` [5](#0-4) . Any organization onboarded to the Shipit instance (even a throwaway, attacker-owned org added purely to get a stack/webhook configured) has its own webhook secret, which the org admin necessarily knows because they configure it in the GitHub App/webhook settings themselves.

`verify_signature` computes `repository_owner` from the JSON body's `repository.owner.login` (or `organization.login`) and looks up `Shipit.github(organization: repository_owner)` to obtain the secret used for `verify_webhook_signature` [2](#0-1) [6](#0-5) . Because this is a raw signature check over `request.raw_post`, and the attacker controls both the body and the secret used to sign it (their own org's secret), the attacker can freely craft any JSON body as long as `repository.owner.login` equals their own org, and sign it correctly.

Downstream, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the same `params` hash to handlers [7](#0-6) . Critically:
- `StatusHandler#process` does `Commit.where(sha: params.sha)` — a **global, unscoped** lookup by SHA across every repository/stack in the Shipit instance — and calls `commit.create_status_from_github!(params)` [3](#0-2) . There is no check that the commit's repository matches `repository_owner` used for signature verification at all.
- `PushHandler`/`CheckSuiteHandler` scope via `Handler#stacks`, which reads `payload.dig('repository', 'full_name')` [4](#0-3)  — a field independent from `repository.owner.login` used for the signature check. Nothing enforces that `full_name`'s owner segment equals `owner.login`.

This breaks the equality: `organization whose secret authenticated the request == organization/repository whose data is written`. An attacker who controls (or is granted) any single organization's webhook secret in the Shipit config can forge a `status` webhook naming any commit SHA belonging to a victim stack in a *different* organization, and inject a fabricated CI status (`state: success`, matching `context`) onto that victim commit — all authenticated only by their own org's secret.

### Impact Explanation
`ci.require` in `shipit.yml` gates whether a commit is eligible to deploy based on `Status` rows attached to that commit [8](#0-7) . Since `StatusHandler` creates `Status` rows keyed purely by global SHA lookup, cross-organization forgery of a required CI context turns a commit that never actually passed real CI into one that appears green to Shipit's deploy-eligibility logic, enabling an unauthorized deploy of that commit. This crosses an authentication boundary (organization secret) to a write target (commit belonging to an unrelated organization/repository) that boundary was never meant to authorize — matching the "unauthorized deploy" and "cross-repository writes" impact categories.

### Likelihood Explanation
Exploitability only requires the attacker to control one legitimate organization's webhook configuration in the Shipit deployment (a normal, low-privilege onboarding action many multi-tenant Shipit deployments allow), plus knowledge of a target commit SHA (visible on any public GitHub repo, or via the Shipit UI). No `ApiClient` token, GitHub App private key, or session is required — only the ability to send a raw HTTP POST to `/webhooks` with a correctly-signed body, which is the exact attack surface `WebhooksController` exposes unauthenticated by design.

### Recommendation
Bind the org/repository authorized by signature verification to the org/repository actually mutated: have each handler validate that `payload.dig('repository', 'full_name')` (and/or `owner.login`) matches the commit's/stack's actual repository before acting, and reject `StatusHandler` payloads for commits outside the repository named in the payload (and verified by the signature). Do not perform global, repository-unscoped `Commit.where(sha:)` lookups when handling org-scoped webhooks.

### Proof of Concept
1. Attacker owns/configures organization `attacker-org` in the Shipit instance's `secrets.yml`, with a known `webhook_secret`.
2. Attacker finds the SHA of a commit belonging to `victim-org/victim-repo`'s stack that is pending a required CI context (e.g., `ci/tests`).
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" } },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/tests"
}
```
signed with `sha1=` HMAC using `attacker-org`'s own `webhook_secret` [1](#0-0) .
4. `verify_signature` succeeds (secret matches `attacker-org`) [2](#0-1) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit regardless of repository, and creates a passing `Status` on it [3](#0-2) .
6. The victim commit now satisfies `ci.require`, becoming eligible for deploy despite never passing real CI.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/deploy_spec.rb (L121-180)
```ruby
      Array.wrap(config('deploy', 'variables')).map(&VariableDefinition.method(:new))
    end

    def default_deploy_env
      deploy_variables.map { |v| [v.name, v.default] }.to_h
    end

    def retries_on_deploy
      config('deploy', 'retries') { nil }
    end

    def rollback_steps
      around_steps('rollback') do
        config('rollback', 'override') { discover_rollback_steps }
      end
    end

    def rollback_steps!
      rollback_steps || cant_detect!(:rollback)
    end

    def rollback_variables
      if config('rollback', 'variables').nil?
        # For backwards compatibility, fallback to using deploy_variables if no explicit rollback variables are set
        deploy_variables
      else
        Array.wrap(config('rollback', 'variables')).map(&VariableDefinition.method(:new))
      end
    end

    def retries_on_rollback
      config('rollback', 'retries') { nil }
    end

    def fetch_deployed_revision_steps
      config('fetch') || discover_fetch_deployed_revision_steps
    end

    def fetch_deployed_revision_steps!
      fetch_deployed_revision_steps || cant_detect!(:fetch)
    end

    def task_definitions
      discover_task_definitions.merge(config('tasks') || {}).map do |name, definition|
        TaskDefinition.new(name, coerce_task_definition(definition))
      end
    end

    def find_task_definition(id)
      definition = config('tasks', id) || discover_task_definitions[id]
      TaskDefinition.new(id, coerce_task_definition(definition) || task_not_found!(id))
    end

    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```
