Found the confirmed binding break: the webhook signature is verified against the organization derived from `repository_owner`, but the actual repository/stack the payload acts on is resolved independently from `payload.dig('repository', 'full_name')` — a different field that is never checked against the organization used for verification.

### Title
Webhook signature verified against one organization while payload is applied to a repository from an unverified field, allowing cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate the HMAC signature using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). Once the signature check passes, the raw, attacker-controlled JSON body is handed unmodified to the event handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. Those handlers (`Handler#repository_name`, `Handler#stacks`) resolve the target `Repository`/`Stack` from a *different* JSON field: `payload.dig('repository', 'full_name')`. Nothing enforces that `repository.full_name` and `repository.owner.login` refer to the same repository.

### Finding Description
This mirrors the HedgeUnit bug class: a value used to authorize/compute a ratio (here, the signing organization) is decoupled from the value actually acted upon (here, the repository the handler writes state for). The binding that should hold is:
`organization verified via webhook_secret == repository/stack actually mutated by the handler`

but the code only checks:
1. `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  — used solely to select `Shipit.github(organization: repository_owner)` and verify the HMAC over the raw body [2](#0-1) .
2. `Handler#repository_name` independently reads `payload.dig('repository', 'full_name')` to look up the `Repository`/`Stack` scope that the event handler operates on [3](#0-2) .

Both values come from the same untrusted, attacker-crafted JSON payload (they are two different keys inside `repository`: `repository.owner.login` vs `repository.full_name`). The signature only proves that *some* organization's configured `webhook_secret` was used to sign the body — it does not prove that `repository.full_name`, which is what handlers actually key their side effects on (e.g. `Repository.from_github_repo_name(repository_name)&.stacks`), belongs to that same organization. If an attacker (or a compromised low-trust org owner) configures a Shipit-integrated GitHub App/organization "attacker-org" (with its own `webhook_secret` known to the attacker because they control that org's Shipit GitHub App settings), they can sign a webhook payload with `attacker-org`'s secret while setting `repository.full_name` to `victim-org/victim-repo` and `repository.owner.login` to `attacker-org` (satisfying `repository_owner` used only for secret selection). `verify_signature` succeeds because it validated against `attacker-org`'s legitimately-known secret, and the handler then mutates state for the `victim-org/victim-repo` stack using data entirely controlled by the attacker (e.g., `push` payloads driving `GithubSyncJob`, `status` payloads creating commit statuses, `pull_request` payloads that open merge-queue requests) — see the `status` handler test showing commit-status creation driven purely by the parsed payload [4](#0-3) .

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" binding explicitly called out in scope. Depending on which webhook event/handler is reached, this allows an attacker who legitimately controls one organization's Shipit App installation (and thus its `webhook_secret`) to inject fabricated GitHub events (push, status, pull_request, membership, check_suite) that are applied to any other organization's stacks tracked by the same Shipit instance — e.g., fabricating commit statuses, driving `GithubSyncJob` to ingest attacker-chosen commit SHAs/messages into a victim stack's commit history, or creating merge-queue-adjacent pull-request state for a victim repository. Because commit ingestion and status data feed directly into `deployable?`/CI-gating logic used before an actual deploy is triggered, this can be leveraged toward an unauthorized deploy on the victim's stack, satisfying the "unauthorized deploy" high/critical impact bar.

### Likelihood Explanation
Likelihood is high for any Shipit deployment that federates multiple GitHub organizations/apps behind one instance (a documented, supported configuration since `Shipit.github(organization:)` is keyed per-org). Any actor who can obtain or configure a `webhook_secret` for *any one* recognized organization — including one they legitimately administer — can exploit this without needing write access to the victim repository, a Shipit session, or an API token, since the entire cross-binding gap lives in unauthenticated code in `WebhooksController`.

### Recommendation
After signature verification, re-validate that the repository referenced by `repository.full_name` (or any other repository identifiers used later in `Handler#stacks`/`Handler#repository_name`) belongs to the same organization (`repository_owner`) that was used to select and validate the webhook secret, before dispatching to event handlers. Reject the webhook (422) if these two values disagree.

### Proof of Concept
```ruby
# Attacker legitimately controls "attacker-org" and knows its Shipit webhook_secret.
payload = {
  "repository" => {
    "full_name" => "victim-org/victim-repo",   # acted upon by Handler#repository_name / #stacks
    "owner" => { "login" => "attacker-org" }   # used only to select the org for signature verification
  },
  "sha" => "deadbeef",
  "state" => "success",
  "context" => "ci/fake",
  "target_url" => "https://example.com"
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", attacker_org_webhook_secret, payload)

post "/webhooks", body: payload, headers: {
  "X-Github-Event" => "status",
  "X-Hub-Signature" => signature
}
# verify_signature succeeds (uses Shipit.github(organization: "attacker-org"))
# StatusHandler resolves stacks via Repository.from_github_repo_name("victim-org/victim-repo")
# and creates a fabricated commit status on the victim's stack/commit.
``` [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-38)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
