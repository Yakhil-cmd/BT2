### Title
Webhook signature verification key is selected from an unauthenticated payload field that differs from the field handlers use to identify the target repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization secret to verify the `X-Hub-Signature` against by reading `repository.owner.login` (or `organization.login`) straight out of the still-unauthenticated JSON body. Every webhook handler, however, resolves the actual `Repository`/`Stack` to act on using a *different* field from the same body: `repository.full_name`. Nothing ties these two fields together, so the "organization whose secret authenticated the request" is never checked to equal "the repository the handler actually writes to."

### Finding Description
`WebhooksController#verify_signature` does:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

The secret used for HMAC verification is chosen using `repository.owner.login`, a value taken from the *body being verified itself* — i.e. the request is only checked to be "signed with whatever org's secret the payload itself claims to belong to."

Meanwhile, every `Shipit::Webhooks::Handlers::Handler` subclass locates the `Repository`/`Stack` to mutate using a completely separate field, `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`Repository.from_github_repo_name` splits `owner/name` and does a straight DB lookup, with no cross-check against the `owner.login` value that was used to select the verification secret:
```ruby
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [3](#0-2) 

`PushHandler` is a concrete example that turns this into a write: it finds stacks for `repository_name` (from `full_name`) and calls `stack.sync_github(expected_head_sha: params.after)` unconditionally, which enqueues `GithubSyncJob`:
```ruby
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [4](#0-3) 

**Binding that should hold:** `organization_whose_secret_verified_signature == owner(repository.full_name_acted_on)`.
**What the code actually enforces:** `organization_whose_secret_verified_signature == payload["repository"]["owner"]["login"]`, a value chosen by whoever crafted the JSON body, with **no equality check at all** against `payload["repository"]["full_name"]`.

This is the exact analog of M-18's root cause: a downstream consumer (`authMint`) trusts and acts on a quantity (`returned`/`swapped`) that was never actually reconciled against the value produced by the verified operation (`yield()`'s PT→iPT swap). Here, the downstream consumer (webhook handlers) trusts and acts on `repository.full_name`, a value never reconciled against what the "verified" operation (signature check) actually authenticated (`repository.owner.login`).

**Concrete exploit path (multi-tenant Shipit deployment):** Shipit natively supports configuring several GitHub organizations/Apps in one instance, each with its own `webhook_secret` (see `config/secrets.development.shopify.yml`, which configures `somegithuborg` and `someothergithuborg` side by side) [5](#0-4) . An attacker who legitimately administers GitHub App "OrgA" (one tenant on that shared instance, and thus knows OrgA's `webhook_secret`) can craft an arbitrary JSON payload where:
- `repository.owner.login = "OrgA"` (so `repository_owner` resolves to OrgA, and the signature computed with OrgA's own secret verifies successfully), while
- `repository.full_name = "OrgB/victim-repo"` (a completely unrelated stack belonging to a different tenant, OrgB, on the same shared Shipit instance).

The signature check passes because it only validates "is this HMAC correct for OrgA's secret," and the attacker computed that HMAC themselves over their own forged body. The handler then acts on `OrgB/victim-repo` because it reads `full_name`, not `owner.login`.

### Impact Explanation
This breaks a repository-ownership trust boundary and enables cross-tenant, cross-repository writes/deploy-triggers from an attacker who only controls one tenant's webhook secret: forged `push` events invoke `stack.sync_github(expected_head_sha:)` → `GithubSyncJob` for a victim stack the attacker has no legitimate relationship with, and other in-scope handlers (`status`, `check_suite`, `pull_request/*`, `membership`) are equally reachable through the same `full_name`-vs-`owner.login` mismatch, since they all inherit `Handler#repository_name`. This matches the "Critical: cross-repository writes / an unauthorized deploy" bucket in the assessment rules: the attacker did not need write access to the victim repository, the victim's own webhook secret, or a Shipit session — only knowledge of a different, unrelated tenant's webhook secret that this Shipit instance also happens to trust.

Note: the actual commit *content* fetched by `GithubSyncJob` still comes from GitHub via the victim repository's own correctly-resolved GitHub App credentials (`Repository#github_app` uses the DB-stored `owner`, not attacker input) [6](#0-5) , so the attacker cannot inject fabricated commits. However, they can still force unscheduled sync/deploy-triggering activity, cache invalidation, and repeated retries (`GithubSyncJob` retries up to `MAX_RETRY_ATTEMPTS`) [7](#0-6)  against a repository outside their authorization scope, and — depending on the specific handler triggered (e.g. `status`/`check_suite` handlers, or `pull_request` handlers which can `archive!`/`unarchive!` review stacks or call `ReviewStackAdapter#create!`) — can directly mutate victim-tenant state.

### Likelihood Explanation
Requires a multi-tenant Shipit deployment where more than one GitHub organization/App is configured (a supported, documented configuration per `config/secrets.development.shopify.yml` and `docs/setup.md`'s per-org `github:` block), and requires the attacker to be a legitimate administrator/webhook-secret holder for at least one of those configured tenants. No repository write access to the victim repo, no `ApiClient` token, no Shipit session, and no knowledge of the victim's own `webhook_secret` is needed. This is a realistic configuration for any shared/hosted Shipit instance serving multiple GitHub orgs.

### Recommendation
Bind the field used to select the verification key to the field the handlers actually act on: after selecting the signing org via `repository.owner.login`/`organization.login`, verify that `repository.full_name`'s owner segment (and/or the resolved `Repository#owner`) equals that same organization before dispatching to handlers, rejecting (422) any payload where they diverge. Alternatively, always verify against every configured org's secret and require a match on `owner.login == full_name.split('/').first` as a precondition, rather than trusting the payload to self-select its own verification key.

### Proof of Concept
1. Deploy Shipit configured with two GitHub orgs, `OrgA` and `OrgB`, each with its own `github_app`/`webhook_secret` (as in `config/secrets.development.shopify.yml`).
2. As an administrator of `OrgA`'s GitHub App, obtain `OrgA`'s `webhook_secret`.
3. Craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker_chosen_sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>`.
5. POST to `/github/webhooks` with header `X-Github-Event: push`.
6. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches OrgA's app, and successfully verifies the signature (attacker computed it correctly for OrgA's secret) — see `app/controllers/shipit/webhooks_controller.rb:24-49`.
7. `PushHandler#process` resolves `repository_name` from `repository.full_name` = `"OrgB/victim-repo"`, finds `OrgB`'s `Stack`, and calls `stack.sync_github(expected_head_sha: "<attacker_chosen_sha>")`, enqueuing `GithubSyncJob` against a stack the attacker (as an `OrgA` admin) has no authorization over — see `app/models/shipit/webhooks/handlers/push_handler.rb:12-17` and `app/models/shipit/webhooks/handlers/handler.rb:30-38`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
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

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
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
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end
```
