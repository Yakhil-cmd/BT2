### Title
Webhook Signature Verified Against a Different Organization Than the Repository Whose Data Is Written - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a GitHub webhook using `repository_owner`, a value pulled straight out of the same untrusted, attacker-controlled JSON body (`params.dig('repository', 'owner', 'login')`), before that body has been authenticated [1](#0-0) . Downstream handlers, however, resolve the repository/stack to act on using a *different* field of the same payload — `repository.full_name` — via `Handler#repository_name` / `Handler#stacks` [2](#0-1)  and `Repository.from_github_repo_name` [3](#0-2) . Nothing ties `repository.owner.login` (the field that selects the signing key) to `repository.full_name` (the field that selects the record acted upon), so a payload can be legitimately signed by organization A's secret while claiming to originate from organization B's repository.

### Finding Description
This is the delegatecall-to-unverified-address bug class applied to Shipit's webhook trust model: the "call" (write to a `Stack`/`Commit`/`Status` record) is dispatched to a target (`repository.full_name`) that is never covered by the same check that authorizes the caller (`repository.owner.login`, used to select the HMAC secret).

Concretely:
- `verify_signature` builds `github_app = Shipit.github(organization: repository_owner)` from `params.dig('repository', 'owner', 'login')` (or `organization.login`) and uses that app's `webhook_secret` to validate `X-Hub-Signature` against `request.raw_post` [4](#0-3) .
- Once verified, `WebhooksController#create` dispatches the *entire raw payload* to registered handlers for the event type [5](#0-4) , e.g. `Handlers::PushHandler`, `Handlers::StatusHandler`, `Handlers::CheckSuiteHandler`.
- Those handlers determine the target `Repository`/`Stack` via `payload.dig('repository', 'full_name')` [6](#0-5) , which is looked up independently with `Repository.from_github_repo_name` [3](#0-2) .

Because the signing-key-selection field (`repository.owner.login`) and the target-selection field (`repository.full_name`) are two independent keys inside the same attacker-supplied JSON body, an attacker who legitimately administers one GitHub organization already configured in this Shipit instance (and therefore knows that organization's own `webhook_secret`, a credential they own, not stolen) can compute a valid HMAC signature over a forged body where:
- `repository.owner.login` = `"attacker-org"` (so `verify_signature` fetches attacker-org's `GitHubApp` and successfully validates the signature computed with attacker-org's own secret), while
- `repository.full_name` = `"victim-org/victim-repo"` (so the handler resolves and mutates a `Stack` belonging to a completely different, victim organization).

The binding that should hold is:
`organization_that_signed(payload) == organization_that_owns(repository_acted_on(payload))`

but no code path enforces this equality; `verify_signature` only proves "this payload was signed by *some* org's secret," not "the org that signed it matches the repository the payload claims to describe."

### Impact Explanation
This lets an attacker who controls the webhook secret of any single organization onboarded into a multi-tenant Shipit installation forge repository-scoped events (`push`, `status`, `check_suite`, `pull_request`) against *any other organization's* stacks known to that Shipit instance:
- `StatusHandler` writes forged CI `Status` records tied to arbitrary commits [7](#0-6) , which can be used to fabricate a green CI status and unlock the deploy button on a victim stack — an unauthorized deploy path.
- `PushHandler` enqueues `GithubSyncJob` for arbitrary stacks with an attacker-chosen `expected_head_sha` [8](#0-7) , forcing syncs against victim stacks.
- `CheckSuiteHandler` and PR handlers similarly act on victim repositories/stacks that the attacker's organization has no legitimate relationship to.

This is a cross-organization/cross-repository write achieved without a Shipit session, `ApiClient` token, or GitHub App private key — only knowledge of one legitimately-configured org's own webhook secret, which the rules explicitly treat as an unprivileged-attacker-reachable credential (it authenticates "an organization," not "the repository" being written).

### Likelihood Explanation
Any organization already onboarded to a shared/multi-tenant Shipit deployment (a documented, supported configuration — see `config/secrets.development.shopify.yml` listing multiple GitHub orgs) [9](#0-8)  can mount this attack against every other tenant organization's stacks, since the org-to-secret binding (`repository.owner.login`) is never cross-checked against the repo-to-act-on binding (`repository.full_name`). No GitHub-side validation occurs; the webhook endpoint accepts arbitrary POSTed JSON as long as the signature matches the secret for whatever organization the attacker names in `repository.owner.login`.

### Recommendation
After successfully verifying `X-Hub-Signature`, re-derive the acting repository strictly from data scoped to the organization that produced a valid signature, or explicitly assert that `repository.full_name`'s owner segment equals `repository_owner`/`organization.login` before any handler is invoked. Reject the webhook if these two org references diverge.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` (secret `S_A`, known to the attacker because they administer that org's GitHub App/webhook) and `victim-org` (secret `S_V`, unknown to attacker), each with stacks tracked by Shipit.
2. Attacker crafts a `push` webhook body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, body)` — a signature they can validly compute since `S_A` is their own secret.
4. `POST /webhooks` with `X-Github-Event: push`. `verify_signature` loads `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and successfully verifies the signature against `S_A` [1](#0-0) .
5. `Handlers::PushHandler#process` resolves stacks via `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"` [2](#0-1) , and enqueues `GithubSyncJob` against victim-org's real stack with an attacker-chosen `expected_head_sha` [8](#0-7) , despite the request never having been signed by `victim-org`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
