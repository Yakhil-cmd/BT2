### Title
Webhook signature verification authenticates the payload's `organization`/`repository.owner`, but every handler acts on the independent `repository.full_name` field — allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret and validates the request using `repository.owner.login` (falling back to `organization.login`), but the code that actually resolves *which* `Stack`/`Repository`/`Commit` gets mutated (`Handler#repository_name`, used by every webhook handler) reads a completely different, independently attacker-controlled JSON field: `repository.full_name`. On a Shipit instance configured with multiple GitHub organizations (as documented in `config/secrets.development.example.yml`), each organization has its own `webhook_secret`. An entity that legitimately controls one organization's webhook secret can craft a brand-new payload — not a tampered legitimate one — that sets `repository.owner.login`/`organization.login` to their own org (so signature verification passes with their own known secret) while setting `repository.full_name` to a *different* organization's repository that is also hosted on the same Shipit instance. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) and uses it to pick the correct `Shipit.github(organization:)` configuration/secret to validate `X-Hub-Signature`: [4](#0-3) 

This proves only that *the sender knows the webhook secret configured for that particular organization*. It does not prove anything about which repository is affected.

Every handler, however, resolves the target repository independently via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` and looks it up with `Repository.from_github_repo_name`: [3](#0-2) [5](#0-4) 

Because `owner.login`/`organization.login` and `repository.full_name` are two unrelated fields inside the same self-crafted (not intercepted) JSON body, an attacker who legitimately administers organization A's GitHub App integration (hence legitimately possesses org A's `webhook_secret`) can sign a payload with `repository.owner.login = "org-a"` (verification passes, using org A's secret) but `repository.full_name = "org-b/victim-repo"`. `PushHandler`, `StatusHandler`, and `CheckSuiteHandler` all resolve their target `Stack`/`Commit` via this unverified `full_name`: [6](#0-5) 

This breaks the equality that should hold: `organization_authenticated_by_signature == organization_owning_repository_acted_upon`. After the attacker's crafted request, the left side is org A (the org whose secret validated the HMAC) while the right side is org B (the org whose `Stack`/`Commit` records actually get mutated) — a direct violation of the "organization that authenticated versus the repository that is written" binding.

### Impact Explanation
Using the `status` event, an attacker who only controls their own organization's webhook secret can forge a `Status` (`commit.statuses`) on a commit belonging to a different organization's stack that they have no legitimate access to, as demonstrated by the existing test that creates a `Status` purely from `sha`/`state`/`branches` fields merged with `repository_params`: [7](#0-6) 

Commit statuses are used by Shipit's `ci.require`/CI safety checks that gate whether a commit is deployable. Forging a passing status on a victim organization's commit writes data into that organization's repository/stack records and can defeat CI-based deploy safety gating — a cross-repository write achieved purely through webhook forgery, without any Shipit session, API token, or GitHub write access to the victim repository. This matches the Critical-impact category of "cross-repository writes."

### Likelihood Explanation
Exploitation requires only that: (1) the deployment hosts multiple GitHub organizations behind a single Shipit instance (an explicitly supported and documented configuration), and (2) the attacker legitimately controls the webhook secret for at least one of those organizations (which any org admin who installs/configures the shared GitHub App naturally has). No compromise of the victim organization, no `ApiClient` token, and no GitHub repository access to the victim repo is required — only knowledge of one's own organization's webhook secret, which is by design available to that organization's administrators. This is a realistic likelihood for any multi-tenant Shipit deployment.

### Recommendation
Bind the signature-verifying organization to the organization actually acted upon. Concretely, `Handler#repository_name`/`Repository.from_github_repo_name` should require that the resolved repository's `owner` matches the `repository_owner`/`organization.login` value that was used to select the webhook secret in `WebhooksController#verify_signature`, rejecting the event otherwise. Alternatively, derive the target repository strictly from the same field(s) used for signature-org resolution, or pass the verified `repository_owner` down into every handler and assert equality with `repository.full_name`'s owner segment before performing any lookup or mutation.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `config/secrets.development.example.yml` multi-org schema).
2. As an admin of `org-a` (who legitimately knows `org-a`'s webhook secret), craft a `status` event payload:
```json
{
  "sha": "<victim-commit-sha-in-org-b-repo>",
  "state": "success",
  "target_url": "https://ci.example.com/fake",
  "description": "fake",
  "context": "ci/required",
  "repository": {
    "full_name": "org-b/victim-repo",
    "owner": { "login": "org-a" }
  }
}
```
3. Sign the raw JSON body with `org-a`'s `webhook_secret` (HMAC-SHA1) and send it to `POST /webhooks` with `X-Github-Event: status` and `X-Hub-Signature: sha1=<hmac>`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"org-a"`, fetches `org-a`'s secret, and the signature validates successfully.
5. `StatusHandler` (via `Handler#repository_name`) resolves the target repository from `repository.full_name` = `"org-b/victim-repo"`, and writes a forged `Status` onto the victim commit belonging to `org-b`, despite the request never having been authenticated for `org-b`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
