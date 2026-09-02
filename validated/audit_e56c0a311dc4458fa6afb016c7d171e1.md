### Title
Cross-organization signature confusion allows forging GitHub webhooks that mutate arbitrary victim `Stack`/`Repository`/`Commit` state - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization `webhook_secret` is used to authenticate an inbound webhook based on `repository.owner.login` read out of the *unverified* JSON body, but the handlers that actually act on the payload (`Shipit::Webhooks::Handlers::Handler#repository_name`) resolve the target `Repository`/`Stack` from a *different* field of the same unverified body: `repository.full_name`. These two fields are never checked for consistency, so the "organization whose secret authenticated the request" and "the repository that gets written to" can be made to diverge.

### Finding Description
`verify_signature` picks the signing secret using the attacker-supplied JSON body itself: [1](#0-0) [2](#0-1) 

`repository_owner` is derived purely from `params.dig('repository', 'owner', 'login')` (or `organization.login`) — a value fully controlled by whoever sends the POST, before any cryptographic check has occurred. Once the signature checks out for that org's `webhook_secret` (line 30, `head(422) unless verified`, is only a soft guard — note it does not `return` after calling `head`, but that's a secondary point), the same raw, unverified body is handed to `handler.call(params)`: [3](#0-2) 

Every handler resolves the target repository using a *different* field of that same body: [4](#0-3) 

`Repository.from_github_repo_name` splits `owner/name` straight out of `full_name`: [5](#0-4) 

Shipit supports (and its own config fixtures demonstrate) hosting **multiple independent GitHub organizations/Apps** in one deployment, each with its own `webhook_secret`: [6](#0-5) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the repository/stack being mutated) are independent, attacker-controlled strings in the same JSON object, an attacker who is a legitimate member/admin of **any one** organization onboarded to the Shipit instance (and therefore knows or can trigger deliveries signed with *that* org's `webhook_secret`) can craft a payload where:
- `repository.owner.login = "attacker-org"` → signature verifies against `attacker-org`'s known secret.
- `repository.full_name = "victim-org/victim-repo"` → the handler acts on the victim's `Stack`.

This breaks the intended binding **organization-that-authenticated == repository-that-is-written**.

### Impact Explanation
With a forged, validly-"signed" (from the perspective of `attacker-org`) payload, an attacker can drive any of the registered handlers against a victim repository they have no legitimate access to:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on the victim's branch/stack, forcing a spurious GitHub sync job for a repo the attacker doesn't own. [7](#0-6) 
- `StatusHandler#process` writes fabricated CI/commit statuses (`create_status_from_github!`) onto any existing `Commit` row matching an attacker-chosen `sha`, regardless of which repo it belongs to, since `Commit.where(sha: params.sha)` is not scoped to the "authenticated" org at all: [8](#0-7) 

Injected/forged commit statuses feed directly into Shipit's deployability checks (`commit_checks`, `Stack`/`MergeRequest` deployable logic), so forging a passing status on a victim's commit can influence whether that commit is treated as safe to deploy — i.e., this reaches into the "unauthorized deploy" impact category rather than being a pure denial-of-service, because it can flip a victim stack's commit-check state used to gate deploys.

### Likelihood Explanation
Exploitation requires the attacker to control (or have delivery access to) a GitHub organization/App that is *also* configured in the same Shipit instance's `github:` secrets map — i.e., a genuine multi-tenant Shipit deployment with more than one onboarded organization, which the project's own docs and fixtures show is a supported configuration (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`). No `ApiClient` token, session, or GitHub App private key of the *victim* org is needed — only knowledge of the attacker's own org's `webhook_secret`, which the attacker legitimately possesses.

### Recommendation
After the signature is verified for `repository_owner`, re-validate that the org used for the HMAC lookup matches the org embedded in `repository.full_name` (and any other org/owner fields consumed by handlers) before dispatching to handlers; reject the request (`head(422)`) on mismatch. Alternatively, always verify against a fixed/expected org context (e.g., derived once and reused consistently by both `verify_signature` and the handler lookups) rather than re-parsing the body twice for two different fields.

### Proof of Concept
1. Shipit is configured with two organizations, `attacker-org` and `victim-org`, each as a separate GitHub App entry under `github:` in secrets, per `config/secrets.development.shopify.yml`-style configuration.
2. Attacker knows `attacker-org`'s `webhook_secret` (they administer that org's GitHub App).
3. Attacker POSTs to `/github/webhooks` with `X-Github-Event: status` and body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "repository": {
    "owner": {"login": "attacker-org"},
    "full_name": "victim-org/victim-repo"
  }
}
```
signed with `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, raw_body)>`.
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the signature verifies successfully.
5. `StatusHandler#process` executes against `Commit.where(sha: params.sha)`, writing a forged "success" status on the victim commit — a repository the attacker never authenticated against.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
