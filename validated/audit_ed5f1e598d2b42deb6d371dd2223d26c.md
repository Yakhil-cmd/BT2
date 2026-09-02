### Title
Signature-verifying organization and label-mutated organization are independently attacker-controlled fields, letting one org's (no-secret) webhook forge a `pull_request:labeled` event that mutates a different, unrelated production `ReviewStack` - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which org's `webhook_secret` to validate against using `repository_owner`, which is read straight out of the untrusted JSON body (`params.dig('repository','owner','login')`) [1](#0-0) . `LabelCapturingHandler`, invoked on the same body, independently resolves the target `Repository`/`Stack` via `params.repository.full_name` [2](#0-1) . Nothing enforces that these two attacker-controlled fields refer to the same repository, so a webhook whose `repository.owner.login` names an org with no configured `webhook_secret` (a documented, supported configuration for multi-org setups) is accepted unconditionally by `verify_webhook_signature` [3](#0-2)  while its `repository.full_name` can point at a totally different, secured, production stack.

### Finding Description
The broken binding, stated as an equality that should hold but does not:

`org_that_authenticated_the_request (Shipit.github(organization: params.dig('repository','owner','login')))` **must equal** `org_whose_stack_is_mutated (Repository.from_github_repo_name(params.repository.full_name).owner)`.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` purely from the JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [4](#0-3) . It then does `github_app = Shipit.github(organization: repository_owner)` and checks the signature against **that org's** `webhook_secret` [1](#0-0) .
2. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `@webhook_secret` is blank for that org: `return true unless webhook_secret` [3](#0-2) . Multi-org configuration where individual orgs omit `webhook_secret` is explicitly documented and supported (`docs/setup.md` "Using Multiple Github Applications", and the sample `secrets_double_github_app.yml` fixture literally sets `webhook_secret: # nil` per org) [5](#0-4) [6](#0-5) .
3. Once past `verify_signature`, `WebhooksController#create` parses the raw body again and dispatches it unmodified to all `pull_request` handlers, including `LabelCapturingHandler` [7](#0-6) .
4. `LabelCapturingHandler` resolves the target `Repository` via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a completely separate JSON field from the one used for signature scoping — and then the associated `stack` (`review_stack.stack`) [8](#0-7) . `Repository.from_github_repo_name` performs a plain DB lookup with no cross-check against the authenticating org: `find_by(owner: repo_owner, name: repo_name)` [9](#0-8) .
5. For `action == "labeled"` against a non-archived stack, `capture_labels` persists `params.pull_request.labels.map(&:name)` onto `stack.pull_request` [10](#0-9) .
6. `ReviewStack#env` upcases every persisted label name into an environment variable set to `"true"`, merged into the stack's environment used by deploy/task commands: `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` [11](#0-10) , which is confirmed reachable into `TaskCommands#env`/`DeployCommands#env` and ultimately the process environment used for git/deploy commands [12](#0-11) .

Exploit flow: attacker (who need not know any Shipit or GitHub secret) sends `POST /webhooks` with `X-Github-Event: pull_request`, `X-Hub-Signature: sha1=anything` (or even a malformed one—irrelevant once bypassed), and a body where `repository.owner.login = "no-secret-org"` (some org configured in `Shipit` multi-org config without a `webhook_secret`) but `repository.full_name = "victim-org/production-repo"`. `verify_signature` authenticates against `no-secret-org` and passes unconditionally; `LabelCapturingHandler` then mutates `victim-org/production-repo`'s review stack using attacker-chosen label names, injecting attacker-controlled environment variables (e.g. names matching flags interpreted by the victim's deploy scripts) into the production stack's env.

No existing guard closes this: `verify_signature` never compares `repository_owner` to `repository.full_name`; `ExplicitParameters` in `LabelCapturingHandler` only validates types/shape, not cross-consistency with the authenticated org [13](#0-12) ; `Repository.from_github_repo_name` has no owner/org binding to the request's authenticated org [9](#0-8) .

### Impact Explanation
An unprivileged internet attacker can, per request, write arbitrary attacker-chosen label strings onto the `PullRequest` of *any* review stack belonging to *any* repository tracked by Shipit — including a production-environment stack that belongs to a completely different organization than the one whose (secret-less) org name the attacker used to pass signature verification. Those labels become uppercase environment variables merged into the stack's deploy/task `env`, which flows into `Command`/`PTY.spawn` execution for that production stack's tasks. This is a cross-tenant "payload for one repository mutating another's stack" scenario, matching the Critical impact category (unauthorized manipulation of a production deploy environment via injected env vars, potentially enabling command/flag injection depending on the victim's `shipit.yml`/deploy scripts). The attack is repeatable against any tracked repository as long as one org in the Shipit deployment's multi-org config lacks a `webhook_secret`.

### Likelihood Explanation
Preconditions: (1) Shipit configured with the documented multi-org github config (`docs/setup.md`, "Using Multiple Github Applications"); (2) at least one configured org has no `webhook_secret` set — a state the codebase explicitly treats as valid/optional, not an error condition; (3) `review_stacks_enabled` and a non-archived review stack exist for the target repository. None of these require possession of any actual Shipit/GitHub secret. The attacker cost is a single crafted HTTP POST with a guessed or discovered no-secret org name (which may be discoverable via error responses distinguishing "unknown organization" 422 vs. accepted requests, or via reconnaissance of the operator's public org list). This is fully repeatable and scriptable.

### Recommendation
Bind the org used for signature verification to the org actually being mutated: in `WebhooksController#verify_signature`/`create`, after resolving the target `Repository`/`Stack` from the payload's `repository.full_name`, require that its `owner` match the `repository_owner` used to select the `GitHubApp`/secret, and reject (422) on mismatch. Additionally, treat a missing `webhook_secret` for a configured org as a hard misconfiguration (fail closed) rather than "signature always valid," or at minimum log/alert loudly and restrict such orgs from being able to author events targeting other orgs' repositories.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` style):
```ruby
test "pull_request labeled event authenticated by a no-secret org mutates a different org's production stack" do
  # Arrange: two orgs configured; "no-secret-org" has no webhook_secret,
  # "victim-org" is unrelated and has a tracked production review stack.
  victim_repo = shipit_repositories(:shipit) # owner: victim-org
  victim_repo.update!(review_stacks_enabled: true, provisioning_behavior: :allow_all)
  stack = create_review_stack_for(victim_repo, environment: "production")

  payload = payload_parsed(:pull_request_labeled)
  payload["repository"]["owner"] = { "login" => "no-secret-org" }   # used for signature scoping
  payload["repository"]["full_name"] = victim_repo.github_repo_name # used for target resolution -- MISMATCH
  payload["pull_request"]["labels"] = [{ "name" => "malicious-flag" }]

  @request.headers["X-Github-Event"] = "pull_request"
  @request.headers["X-Hub-Signature"] = "sha1=deadbeef" # attacker doesn't know any real secret

  # Binding under test, stated explicitly BEFORE tracing:
  authenticating_org = "no-secret-org"
  mutated_org = victim_repo.owner
  assert_not_equal authenticating_org, mutated_org # divergence exists pre-request

  post :create, body: payload.to_json, as: :json

  assert_response :ok # signature verification passed unconditionally for no-secret-org
  assert_includes stack.reload.pull_request.labels, "malicious-flag"
  assert_equal "true", stack.env["MALICIOUS-FLAG".upcase] # env var injected into production stack
end
```
This demonstrates the equality `authenticating_org == mutated_org` is violated: the request is authenticated as `no-secret-org` yet mutates `victim-org`'s production `ReviewStack`, contradicting the stated invariant.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L62-102)
```ruby
          def labeled_active_stack?
            labeled? && stack.present? && !stack.archived?
          end

          def unlabeled_active_stack?
            unlabeled? && stack.present? && !stack.archived?
          end

          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
          end

          def opened?
            action == "opened"
          end

          def labeled?
            action == "labeled"
          end

          def unlabeled?
            action == "unlabeled"
          end

          def reopened?
            action == "reopened"
          end

          def action
            params.action
          end

          def pull_request
            params.pull_request
          end

          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L104-118)
```ruby
          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
