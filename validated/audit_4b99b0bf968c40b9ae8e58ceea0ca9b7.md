Confirmed: `Handler#repository_name` reads `payload.dig('repository', 'full_name')` [1](#0-0)  while `WebhooksController#verify_signature` selects the GitHub App/secret used for HMAC verification from `params.dig('repository', 'owner', 'login')` [2](#0-1) ` [3](#0-2) . These are two different fields from the same untrusted body, and nothing cryptographically binds `repository.full_name` to `repository.owner.login`. That is exactly the "organization authenticated versus repository written" binding the task describes.### Title
Webhook signature verification keys off `repository.owner.login` while event handlers act on `repository.full_name`, allowing cross-organization webhook forgery in multi-org deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature against using `repository_owner`, derived from `payload.dig('repository', 'owner', 'login')` (or `organization.login`) [2](#0-1) [3](#0-2) . Once the signature is accepted, the full raw payload is handed to event handlers, which instead resolve the target `Repository`/`Stack` using a *different* field, `payload.dig('repository', 'full_name')` [1](#0-0) . Nothing in the code enforces that `repository.owner.login` and the owner portion of `repository.full_name` refer to the same organization. In Shipit's multi-org configuration mode (`config/secrets.yml` supports per-organization `webhook_secret`s, see `Shipit.github_app_config`) [4](#0-3) , this breaks the intended binding: `organization authenticated == organization that owns the repository written`.

### Finding Description
The signature check and the action-taking code consume two different, independently-attacker-controlled JSON fields from the same unauthenticated request body:

- Verification org: `params.dig('repository', 'owner', 'login')` → selects `Shipit.github(organization: ...)` → selects the `webhook_secret` used in `verify_webhook_signature` [2](#0-1) .
- Action-taking repo: `payload.dig('repository', 'full_name')` → `Repository.from_github_repo_name` → `stacks` acted on by handlers such as `PushHandler#process` [5](#0-4) [6](#0-5) .

An attacker who legitimately controls a GitHub App/organization "orgA" configured in this Shipit instance (and therefore knows or can derive orgA's `webhook_secret`, since GitHub lets an org admin see/set their own App's webhook secret) can craft a payload where:
- `repository.owner.login = "orgA"` (so `verify_signature` looks up orgA's app and validates the HMAC against orgA's secret using the attacker's own valid signature), while
- `repository.full_name = "orgB/victim-repo"` (a repository belonging to a different organization/tenant hosted on the same Shipit instance).

Because the HMAC is computed over the entire raw body (so it "covers" `full_name` cryptographically), but the *verifier selection* logic only trusts `owner.login` to pick the secret — and no code cross-checks that `full_name`'s owner segment matches `owner.login` — the attacker's genuinely-signed-with-orgA's-secret payload is accepted, and then dispatched to handlers that act on `orgB/victim-repo`'s stacks (e.g., queuing a `GithubSyncJob`/`sync_github` for arbitrary `expected_head_sha`, creating commit statuses on arbitrary shas, etc.) [7](#0-6) [8](#0-7) .

This is the direct analog of H-02: just as `LendingPair.liquidateAccount` used a stale/mismatched state (`cumulativeInterestRate`) instead of the freshly-accrued one expected by the rest of the system, `WebhooksController#verify_signature` authenticates against one identity (`repository.owner.login`) while the rest of the pipeline (`Handler#repository_name`) trusts a different, unverified identity field (`repository.full_name`) from the same payload — an equality (`verified_owner == acted_repository_owner`) that the code assumes but never enforces.

### Impact Explanation
This allows cross-repository/cross-organization writes: a legitimate-but-malicious tenant (an organization onboarded to a shared Shipit instance) can trigger `GithubSyncJob`, commit-status creation, membership/team mutation, and pull-request-driven review-stack provisioning for another tenant's repositories without ever possessing that tenant's webhook secret. This matches the "Critical: cross-repository writes" impact bucket, since it lets one authenticated organization act on another organization's stack state through the webhook ingestion path.

### Likelihood Explanation
Exploitability requires the Shipit instance to be configured for multiple GitHub organizations (the documented multi-org `secrets.yml` schema) and requires the attacker to control one of those onboarded organizations' GitHub Apps (so they know their own `webhook_secret`). This is a realistic "unprivileged-attacker-within-a-tenant" scenario for any shared/multi-tenant Shipit deployment, though it does not apply to the common single-organization deployment (where `github_default_organization` is `nil` and the single configured secret is always used regardless of payload content) [9](#0-8) .

### Recommendation
After successful signature verification, re-derive/validate that the organization embedded in `repository.full_name` (and any other repository identifiers subsequently trusted by handlers, e.g. `Handler#repository_name`) matches the same organization (`repository_owner`) that was used to select the verifying secret, rejecting the webhook (HTTP 422) on mismatch. Alternatively, bind webhook secrets per-repository (not per-organization) or verify the payload's `repository.owner.login` and `repository.full_name` owner segment for equality before dispatching to `Shipit::Webhooks.for_event`.

### Proof of Concept
1. Shipit is configured with multi-org secrets: `orgA` (attacker's own onboarded org, secret `S_A` known to the attacker) and `orgB` (victim org, secret `S_B`), per `lib/shipit.rb#github_app_config` / `docs/setup.md` multi-org schema.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef...attacker-chosen-sha",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_A, raw_body)` using their own known `S_A`.
4. `POST /webhooks` with `X-Github-Event: push`. `verify_signature` computes `repository_owner = "orgA"`, fetches `Shipit.github(organization: "orgA")`, and validates the signature successfully against `S_A` [2](#0-1) .
5. `create` re-parses the same body and dispatches to `PushHandler`, whose `Handler#repository_name` reads `"orgB/victim-repo"` and resolves `Repository.from_github_repo_name("orgB/victim-repo")`, queuing `sync_github(expected_head_sha: "deadbeef...")` against `orgB`'s stack [5](#0-4) [6](#0-5) .
6. Result: orgA has forced a sync/deploy-affecting job on orgB's stack despite never possessing `S_B`.

*Note: I was unable to execute or fully trace this proof of concept end-to-end (e.g. run the test suite or exercise `GithubSyncJob` behavior) since I only have read access to the indexed codebase; this analysis is based on static code review of the cited files.*

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L7-17)
```ruby
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
