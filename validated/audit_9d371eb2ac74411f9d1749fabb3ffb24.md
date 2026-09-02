### Title
Signature-verification org (`repository.owner.login`) diverges from mutated-repo org (`repository.full_name`), allowing forged `pull_request`/`reopened` webhooks against any org without `webhook_secret` to write attacker-controlled labels into another org's `ReviewStack#env` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` used to authenticate a webhook using `repository_owner` (`params.dig('repository','owner','login')`), while `LabelCapturingHandler` (and the other `pull_request` handlers) resolves the actual `Repository`/`Stack` to mutate using a completely different, independently attacker-controlled field, `params.repository.full_name`. Because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected org has no `webhook_secret` configured, an attacker can pick any no-secret org for `repository.owner.login` to pass verification, while pointing `repository.full_name` at a different, secret-protected org's repo whose `ReviewStack` actually gets mutated.

### Finding Description
The broken binding, as an equality that the code implicitly assumes but never enforces:

`repository.owner.login used to select GitHub App/secret in verify_signature == owner of repository.full_name used by the handler to resolve Repository/Stack`

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner)` to select a `GitHubApp` config [1](#0-0) , then `Shipit.github(organization: repository_owner)` looks up per-org config by that org name [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever that specific org's `@webhook_secret` is blank: `return true unless webhook_secret` [3](#0-2) .
3. `WebhooksController#repository_owner` is read purely from `params.dig('repository', 'owner', 'login')` [4](#0-3) , a JSON field fully controlled by whoever POSTs the payload — it has no cryptographic relationship to `repository.full_name`.
4. Once verification passes, `WebhooksController#create` dispatches to all registered handlers for the event with the raw, unverified-per-repo `params` [5](#0-4) .
5. `LabelCapturingHandler` resolves the target `Repository` via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, a field independent from `repository.owner.login` [6](#0-5) , and for `action == "reopened"` on a present, non-archived stack calls `capture_labels`, persisting `params.pull_request.labels.map(&:name)` onto the resolved stack's `PullRequest` [7](#0-6) .
6. Those persisted label names are later merged into `ReviewStack#env`, each becoming `LABEL_NAME => "true"` in the environment passed downstream to deploy/task commands [8](#0-7) .

Exploit flow: attacker sends `POST /webhooks` with header `X-Github-Event: pull_request`, body `action=reopened`, `repository.owner.login = "no-secret-org"` (an org configured in `secrets.github` with `webhook_secret` unset/nil — per the documented multi-org schema at `docs/setup.md:182-209` and the example config `config/secrets.development.example.yml:20-29`), but `repository.full_name = "victim-org/victim-repo"` pointing at a *different*, secret-protected org's repository that actually has a matching `Repository`/`ReviewStack` in this Shipit instance. `verify_signature` resolves `Shipit.github(organization: "no-secret-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (even absent or garbage) `X-Hub-Signature` header. The request is accepted, and `LabelCapturingHandler` mutates the victim org's review stack's `PullRequest#labels`, which subsequently become environment variables in `ReviewStack#env` for that victim stack.

Existing guards do not catch this: `drop_unhandled_event` only checks the event type is handled, not repo ownership [9](#0-8) ; `ExplicitParameters` schema in the handler only validates types/presence of `repository.full_name`, not that it matches the org used for signing [10](#0-9) ; and `GithubOrganizationUnknown` rescue only triggers if the named org isn't configured at all, not when it's configured with a blank secret [11](#0-10) . Nothing anywhere cross-checks that the org that authenticated the request is the org that owns `repository.full_name`.

### Impact Explanation
An attacker who owns or controls any GitHub organization/repo configured in this Shipit instance with no `webhook_secret` (a supported, documented configuration — multiple orgs per `docs/setup.md:182-209`) can forge webhooks that are accepted unconditionally for that org, then use `repository.full_name` to redirect the effect onto a *different* org's `Stack`/`ReviewStack`/`PullRequest`. This is a cross-tenant "payload for one repository mutates another's stack" scenario matching the Critical impact category: unprivileged data written to a repository/stack that never authenticated the request, and that data (labels) becomes environment variables merged into deploy/task command environments for the victim's `ReviewStack`. This is repeatable per victim `full_name` value and per PR number as long as a matching `PullRequest`/non-archived `ReviewStack` exists, and it generalizes to any handler that reads `params.repository.full_name` while trusting `verify_signature`'s org selection (e.g., `OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `AssignedHandler`, `EditedHandler`), since all of them share the same `Handler`/`from_github_repo_name` pattern.

### Likelihood Explanation
Preconditions: the Shipit instance must have at least one configured GitHub org with `webhook_secret` unset/blank (this is a documented, supported configuration, not a misconfiguration unique to a hypothetical setup), and a victim org/stack with a real `Repository` and active `ReviewStack`/`PullRequest`. The attacker needs no Shipit session, API token, or GitHub credentials for the victim org — only knowledge of the victim's `owner/repo` full name (public information) and the existence of a no-secret org anywhere in the same Shipit deployment. Feasibility is high: a single crafted HTTP POST, no signature computation needed since `verify_webhook_signature` short-circuits to `true`, fully repeatable.

### Recommendation
In `WebhooksController#verify_signature`, derive the verifying org strictly from the same field the handlers use to resolve the target repository (`repository.full_name`'s owner segment) rather than the separate `repository.owner.login`/`organization.login` field, or explicitly assert equality between them and reject on mismatch. Additionally, `GitHubApp#verify_webhook_signature` should not silently return `true` when `webhook_secret` is blank for organizations that are explicitly configured (multi-org schema) — require an explicit secret for every configured org, or reject signature-less webhooks by default. Handlers should also independently verify that the resolved `Repository`'s owning organization matches the org that authenticated the webhook.

### Proof of Concept
minitest plan (functional test on `Shipit::WebhooksController`, no live GitHub):
1. Configure `Shipit.secrets.github` with two orgs: `"attacker-org"` (no `webhook_secret`) and `"victim-org"` (with `webhook_secret` set), mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. Create fixtures: a `Shipit::Repository` for `"victim-org/victim-repo"` with an active `ReviewStack` and an associated `PullRequest` (e.g. `labels: []`).
3. Assert-before: `pull_request.labels == []` and `Shipit.github(organization: "attacker-org").verify_webhook_signature(anything, anything) == true` (blank secret).
4. POST `/webhooks` with header `X-Github-Event: pull_request`, no/garbage `X-Hub-Signature`, JSON body: `{"action": "reopened", "number": <pr_number>, "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, "pull_request": {...valid schema..., "labels": [{"name": "malicious_flag"}]}, "sender": {"login": "attacker"}}`.
5. Assert response is `200 OK` (not `422`), proving the forged webhook for `attacker-org` was accepted.
6. Assert-after: reload the victim `PullRequest`, assert `pull_request.labels == ["malicious_flag"]`, and assert `review_stack.env["MALICIOUS_FLAG"] == "true"`, proving a payload authenticated as `attacker-org` mutated `victim-org`'s stack state and environment.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/controllers/shipit/webhooks_controller.rb (L39-49)
```ruby
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L70-102)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-118)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
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
