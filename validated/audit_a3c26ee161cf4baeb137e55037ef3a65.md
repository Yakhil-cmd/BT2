### Title
Webhook signature verified against `repository.owner.login` while triggered stacks are selected from the unbound `repository.full_name` field, letting one tenant org's webhook trigger sync jobs against another org's stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), but `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name` — used by `PushHandler` and other handlers to decide which `Stack` records to act on — reads a *different* JSON field, `payload.dig('repository', 'full_name')`. Nothing in the code enforces that `full_name` is consistent with `owner.login`. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
Shipit supports multi-tenant GitHub App configuration, where distinct organizations each have their own `webhook_secret` (as shown in `config/secrets.development.shopify.yml`, e.g. `somegithuborg` / `someothergithuborg`, each with independent `webhook_secret`). [4](#0-3) 

For every inbound webhook, `verify_signature` computes `repository_owner` from the JSON body itself, fetches that organization's `github_app` config, and verifies the `X-Hub-Signature` HMAC using that organization's `webhook_secret`:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

Once verification passes, the raw JSON is handed unmodified to the event handler:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
end
``` [6](#0-5) 

`PushHandler` (and other handlers via the shared `Handler` base class) resolve the affected `Stack`s from a **different** field of the same body — `repository.full_name` — not `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [3](#0-2) 

The binding equality that should hold is:
`organization whose secret authenticated the HMAC == organization that owns the repository being acted on`

The code only checks:
`HMAC(secret_of(payload.repository.owner.login), raw_body) == X-Hub-Signature`

and separately, unconditionally trusts `payload.repository.full_name` (which the attacker also fully controls inside that same signed body) to pick the `Stack` to sync. Because the attacker who owns/administers a tenant organization ("attacker-org") legitimately knows that organization's `webhook_secret` (they configured GitHub's webhook delivery to Shipit themselves), they can sign an arbitrary JSON payload with `attacker-org`'s secret while setting `repository.owner.login: "attacker-org"` (to pass the signature check) and `repository.full_name: "victim-org/victim-repo"` (to select a victim organization's stack). `Repository.from_github_repo_name` parses `full_name` alone, and finds/acts on the victim `Repository`/`Stack` with no re-check against `repository.owner.login`:
```ruby
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [7](#0-6) 

This lets the attacker enqueue `stack.sync_github(expected_head_sha: <attacker-chosen sha>)` against a victim stack they have no authorization over:
```ruby
def perform(params)
  @stack = Stack.find(params[:stack_id])
  expected_head_sha = params[:expected_head_sha]
  ...
  new_commits, shared_parent = fetch_missing_commits { stack.github_commits }
  ...
``` [8](#0-7) 

### Impact Explanation
This is a cross-repository/cross-organization write: an attacker who is authorized only within their own tenant organization (and thus only knows their own org's webhook secret) can force Shipit to run `GithubSyncJob` against a victim organization's `Stack`, fetching commits from the victim's GitHub repo using the victim's GitHub App credentials and appending/creating `Commit` records, and can drive `CacheDeploySpecJob` to re-cache the victim stack's deploy spec. Because commit ingestion feeds directly into deployability/CI gating and the deploy pipeline (`stack.commits.create_from_github!`, `stack.lock_reverted_commits!`), an attacker can inject state changes into a victim's pipeline that they are not authorized to touch, which matches the "cross-repository writes" / unauthorized-deploy-adjacent High/Critical impact class: the trust binding between "which org's secret authenticated this delivery" and "which repository's stack gets mutated" is broken, exactly analogous to `VaultPoolLib::reserve()` attributing/tracking state (`Pa`) to the wrong bucket than the one actually acted upon later.

### Likelihood Explanation
Requires the deployment to be configured for more than one GitHub organization/tenant sharing one Shipit instance (explicitly supported and documented via multiple entries in `secrets.yml`), and requires the attacker to control at least one of those tenant organizations (which is an "unprivileged" position relative to the victim organization/stack — no GitHub write access to the victim repo, no Shipit `ApiClient` token, and no possession of the victim's `webhook_secret` is needed). Given that Shipit is explicitly designed to serve multiple orgs from one instance, this is a realistic misconfiguration-adjacent but in-scope condition, not one that depends on the host not mounting the engine as documented.

### Recommendation
After the HMAC signature check succeeds using the org selected by `repository_owner`, re-derive/validate that `payload.dig('repository', 'full_name')`'s owner segment matches the same `repository_owner` (or `organization.login`) used to select the verifying secret, and reject (422) the webhook if they diverge. Alternatively, resolve the target `Stack`/`Repository` strictly from the verified organization rather than trusting `full_name` independently.

### Proof of Concept
1. Configure Shipit with two tenant orgs in `secrets.yml`: `attacker-org` (secret `S_A`) and `victim-org` (secret `S_V`), each with stacks synced from their respective GitHub orgs.
2. Attacker crafts a push-event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_A, raw_body)>` using their own known secret `S_A`, and sets `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner == "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC matches — verification succeeds (`head(422)` is skipped).
5. `PushHandler#process` is invoked with the full payload; `Handler#repository_name` returns `"victim-org/victim-repo"`, `Repository.from_github_repo_name` resolves the victim's `Repository`, and `stack.sync_github(expected_head_sha: "deadbeef...")` is called on the victim's `Stack`, which the attacker had no authorization over — despite the delivery only ever being signed by the attacker's own organization secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-41)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
```
