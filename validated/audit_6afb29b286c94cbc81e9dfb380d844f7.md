### Title
Cross-tenant webhook forgery via organization/repository binding mismatch in `verify_signature` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/secret to validate a webhook against using `params.dig('repository','owner','login')`, but every event handler (including `LabelCapturingHandler`) resolves the actual target `Repository`/`Stack` using the independent field `params.repository.full_name`. Because nothing enforces `full_name`'s owner segment equals `owner.login`, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the selected organization has no `webhook_secret` configured, an attacker can pick any configured-but-secretless organization to satisfy signature verification while forging a `pull_request` payload whose `repository.full_name` names a completely different (potentially secret-protected) victim stack.

### Finding Description
The invariant that should hold is: `authenticating_org(payload) == target_repository_owner(payload)`, where `authenticating_org` is the org whose secret validated the request and `target_repository_owner` is the org/repo whose records get mutated. This binding is broken:

- `verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and fetches `Shipit.github(organization: repository_owner)` [1](#0-0) , then calls `github_app.verify_webhook_signature`.
- `verify_webhook_signature` short-circuits to `true` whenever the resolved `GitHubApp` has no `webhook_secret` configured, and even when a secret exists, only accepts the legacy `sha1` algorithm: [2](#0-1) .
- `LabelCapturingHandler#repository` (and every other `pull_request` handler) independently resolves the target repository via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, a field completely separate from `owner.login` used above: [3](#0-2) , and `Repository.from_github_repo_name` simply splits and looks up by owner/name derived from `full_name`: [4](#0-3) .
- Multi-org Shipit deployments are explicitly supported, keyed by organization name, with `webhook_secret` as an optional per-org field (nothing enforces it must be non-blank) [5](#0-4) .

Exploit: attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, `X-Hub-Signature: sha1=<anything>` (or no header at all works too, since the org lookup itself decides the outcome), and a JSON body where `repository.owner.login` = `"attacker-configured-org"` (an org present in Shipit's config with a blank/unset `webhook_secret`) but `repository.full_name` = `"victim-org/victim-repo"` (the real target, potentially guarded by its own secret). `verify_signature` resolves `Shipit.github(organization: "attacker-configured-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — no HMAC of any kind is checked. The request proceeds to `LabelCapturingHandler`, which uses `full_name` to locate `victim-org/victim-repo`'s `Repository`, finds the matching `ReviewStack`/`PullRequest`, and persists `params.pull_request.labels.map(&:name)` onto it: [6](#0-5) . These stored labels are later surfaced as uppercased environment variables via `ReviewStack#env`, and other status/label handlers on the same stack can similarly write records that affect `blocked?` gating for a `blocking_statuses`-configured stack — none of which the attacker's identity should have been able to touch.

Existing guards do not prevent this: `drop_unhandled_event` only filters unsupported event types [7](#0-6) ; `GithubOrganizationUnknown` only fires if `repository_owner` names an org absent from config entirely [8](#0-7) , which does not stop an attacker from choosing a real, configured, secretless org. Handler-level `ExplicitParameters` schemas only validate types/presence of fields, not cross-field consistency between `repository.owner.login` and `repository.full_name` [9](#0-8) .

### Impact Explanation
An unauthenticated attacker can write arbitrary `PullRequest`/label state onto any stack belonging to any repository in the Shipit instance, as long as at least one other configured organization in the same instance has no (or a blank) `webhook_secret`. This is a payload authenticated under one tenant's identity mutating another tenant's stack records — the Critical category "a payload for one repository mutating another's stack, commit, task or team." Labels are surfaced as environment variables via `ReviewStack#env` and can influence deploy behavior; combined with other forgeable events (e.g., `status`) against the same victim stack, this can also flip `blocked?` state and gate/unblock deploys, amplifying the blast radius across the whole multi-tenant Shipit deployment.

### Likelihood Explanation
Preconditions: the Shipit instance must use the multi-organization GitHub App config format (documented, supported) and at least one configured organization must have a blank/unset `webhook_secret` — plausible in real deployments where an org's app was set up without a secret, or during migration between single-org and multi-org config. No secrets, tokens, or GitHub credentials are required by the attacker; only knowledge that such an org exists (which can be brute-forced or guessed from public organization installs). The attack is trivially repeatable against any victim repository/stack by simply changing `repository.full_name` in the forged payload.

### Recommendation
Bind signature verification to the same repository the handler will act on: derive the authenticating organization strictly from `repository.full_name`'s owner segment (not the separate `owner.login` field), or explicitly validate that `repository.owner.login` matches the owner segment of `repository.full_name` before dispatching to handlers. Additionally, remove the `return true unless webhook_secret` bypass in `GitHubApp#verify_webhook_signature` (require a configured secret for every organization, or explicitly document/enforce that secretless orgs cannot process any stack-mutating webhook), and support/require `X-Hub-Signature-256` (`sha256`) rather than only legacy `sha1`.

### Proof of Concept
Minitest plan under `test/controllers/webhooks_controller_test.rb`:
1. Configure `Shipit.stubs(:secrets)` (or use `test/dummy/config/secrets_double_github_app.yml`-style fixture) so org `"secretless-org"` exists with `webhook_secret` blank/nil, and org `"victim-org"` exists with a real `webhook_secret`.
2. Create a `victim-org/victim-repo` `Stack`/`ReviewStack` fixture with a `PullRequest` record and `blocking_statuses` configured.
3. Build a `pull_request` `action=opened` JSON payload where `repository.owner.login = "secretless-org"` and `repository.full_name = "victim-org/victim-repo"`, including `pull_request.labels` with attacker-chosen names.
4. `POST :create` with `X-Github-Event: pull_request` and any `X-Hub-Signature: sha1=deadbeef` (or omit it).
5. Assert `response.status == 200` (bypassing the expected 422 for a mismatched/unauthenticated org), and assert `victim-org/victim-repo`'s `PullRequest#labels` was updated to the attacker-supplied label names — proving `authenticating_org("secretless-org") != target_repository_owner("victim-org")` yet the write succeeded, violating the stated invariant.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
