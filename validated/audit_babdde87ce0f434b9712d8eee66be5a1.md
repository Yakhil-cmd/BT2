### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but the repository/stack actually mutated is looked up from the independent, attacker-controlled `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature against using `repository.owner.login` (or `organization.login`) taken directly from the unauthenticated JSON body. Every webhook handler (`Handler#stacks`, `Handler#repository_name`), however, resolves the target `Repository`/`Stack` using the completely independent `repository.full_name` field from the same body. Because signature verification and target-resolution read two different, uncorrelated fields out of the same attacker-supplied payload, an actor who only knows the webhook secret of Organization A can craft a validly-signed payload whose `full_name` points at a repository belonging to Organization B, causing Shipit to act on Organization B's stacks.

### Finding Description
`WebhooksController#verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

This picks the `GitHubApp`/`webhook_secret` config keyed on `repository.owner.login`, and verifies the *raw* request body's HMAC (`sha1=...`) against that specific org's secret via `GitHubApp#verify_webhook_signature` [2](#0-1) . Shipit explicitly supports per-organization webhook secrets/apps (`config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`) [3](#0-2) .

Once the signature check passes, `WebhooksController#create` dispatches the parsed body to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
end
``` [4](#0-3) 

`Handler#stacks`/`#repository_name` resolve the actual target repository using a **different** field, `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

`Repository.from_github_repo_name` splits `full_name` on `/` and looks the repo up purely by `owner/name`, with no cross-check against `repository.owner.login`:
```ruby
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [6](#0-5) 

The two fields, `repository.owner.login` (used to choose *which secret* validates the request) and `repository.full_name` (used to choose *what gets mutated*), are both plain, unauthenticated JSON keys inside the same body whose only integrity guarantee is the overall HMAC. GitHub itself always keeps these consistent, but nothing in Shipit's verification enforces that `full_name.split('/').first == owner.login`. This is exactly the class of binding break called out in the brief: *"an organization that authenticated versus the repository that is written."*

`StatusHandler` further amplifies this because it resolves commits globally by SHA with no repository/stack scoping at all:
```ruby
def process
  Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github! params }
end
``` [7](#0-6) 
so a forged `status` event validly signed with Org A's secret can inject/overwrite CI status on any commit sha across the whole installation, including stacks belonging to other organizations, potentially unblocking CI gating for deploys elsewhere.

### Impact Explanation
In a deployment configured with multiple GitHub Apps/organizations (an explicitly supported and documented configuration), possession of a single organization's `webhook_secret` is sufficient to forge validly-signed webhook events whose `repository.full_name` targets a *different* organization's repository/stack. Depending on the event/handler this enables:
- Forcing `GithubSyncJob` to run against another org's stack (`push` handler), influencing which commits Shipit believes are undeployed/deployable.
- Injecting or forging commit statuses (`status` handler) for any commit across the entire installation regardless of owning org, which can defeat `ci.require`/CI-gating checks that guard deploys.
- Creating/mutating teams and memberships cross-organization via the `membership` handler, since `MembershipHandler` trusts `params.organization.login` to create/find teams without verifying it matches the org whose secret validated the request.

This is a cross-repository write / authorization boundary crossing that meets the "High/Critical" bar of the brief (escalation across the intended organization/repository trust boundary using only a legitimately-obtained, narrower-scoped credential).

### Likelihood Explanation
Exploitability requires the attacker to already hold the `webhook_secret` for at least one organization configured in the multi-org Shipit deployment — this is a real but bounded pre-condition (e.g., a compromised/rotated-but-still-known secret for a lower-trust org, or an org admin who is not meant to have write access to other orgs' stacks). Given that requirement, forging the payload is trivial: compute HMAC-SHA1 of an attacker-chosen JSON body with the known secret and set `X-Hub-Signature`; no interaction with GitHub is needed. Likelihood is Medium: it is not reachable by a fully anonymous attacker, but it is a straightforward cross-tenant escalation for anyone who legitimately controls one org's webhook secret in a multi-org install.

### Recommendation
- After signature verification, revalidate that `repository.owner.login` (or `organization.login`) used to select the signing key equals the owner portion of `repository.full_name` (and any other repo identifiers used later in handlers) before processing the event; reject mismatches with `422`.
- In `Repository.from_github_repo_name`/`Handler#stacks`, cross-check the resolved repository's `owner` against the organization whose secret validated the signature (pass the verified org down to handlers) rather than trusting `full_name` in isolation.
- Scope `StatusHandler#process` (and other handlers that do global lookups, e.g. by `sha`) to the repository/stack associated with the verified organization, instead of matching commits by SHA across all stacks/orgs.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own GitHub App and `webhook_secret` (as supported by `config/secrets.development.shopify.yml` / `test/dummy/config/secrets_double_github_app.yml`).
2. As an attacker who knows only `orgA`'s `webhook_secret` (e.g., a shared CI operator with access to orgA's app settings), craft a `push` (or `status`) event JSON body where:
   - `repository.owner.login` = `"orgA"` (so `verify_signature` selects orgA's secret)
   - `repository.full_name` = `"orgB/some-target-repo"` (so `Handler#stacks` resolves orgB's stack)
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(orgA_webhook_secret, raw_body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` passes (signature matches orgA's secret over the exact raw body). `PushHandler#process` then runs `GithubSyncJob` against orgB's stack (resolved from `full_name`), even though the request was only authenticated as belonging to orgA.
5. For the `status` event variant, any `sha`/`state` combination is applied globally via `Commit.where(sha: params.sha)`, letting the orgA-secret holder forge CI status for commits under stacks owned by orgB.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
