### Title
Status webhook writes are not scoped to the authenticating organization's repositories - cross-repository commit-status forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App/organization derived from the payload's `repository.owner.login` (or `organization.login`), but `StatusHandler#process` writes the resulting commit status to *any* `Commit` record in the entire database that matches the raw `sha` value, without checking that the commit's `stack`/`repository` belongs to the organization that was actually authenticated. This breaks the binding: `organization authenticated by signature == repository whose data is written`.

### Finding Description
`WebhooksController#verify_signature` resolves the org used for HMAC signature verification purely from payload fields: [1](#0-0) [2](#0-1) 

The signature secret used is `Shipit.github(organization: repository_owner).webhook_secret`, i.e. the webhook secret configured for whichever organization is *named in the untrusted JSON body*. Verification only proves the payload was signed by the secret belonging to that named organization - it says nothing about which `Commit`/`Stack` the handler is later allowed to mutate.

Once verification succeeds, `StatusHandler#process` looks up commits purely by SHA, with no scoping to the authenticated organization/repository at all: [3](#0-2) 

Compare this with `Handler#stacks`, used by other handlers (e.g. `PushHandler`), which properly scopes to the repository named in the payload: [4](#0-3) 

`StatusHandler` does not use this repository-scoped helper. It calls `Commit.where(sha: params.sha)` globally across every stack tracked by the Shipit instance, then calls `commit.create_status_from_github!(params)`: [5](#0-4) 

Because Git commit SHAs are content-addressed and identical across forks/mirrors of the same history (a very common situation - any repository sharing history with, or forked from, another tracked repository will contain byte-identical commits/SHAs), an attacker who controls the GitHub App/organization configuration for *any* one organization onboarded to this Shipit instance (multi-tenant Shipit deployments configure multiple `github:` entries, each with its own `webhook_secret`) can:

1. Sign an arbitrary JSON body with their own organization's `webhook_secret` (which they legitimately possess as the owner/admin of that org's Shipit-integrated GitHub App) so it passes `verify_signature`.
2. Set `X-Github-Event: status` and any `sha` value, including a SHA belonging to a commit in a *different* organization's/repository's stack (obtainable trivially if the target repo is public, forked, or shares history).
3. POST directly to the public `/webhooks` endpoint (`resources :webhooks, only: :create` in `config/routes.rb`) - no session, no `ApiClient` token, no repository write access is required, only knowledge of the secret for the attacker's own onboarded org.

The `StatusHandler` will then create/replace a `Status` on the victim commit in the victim's stack, because the lookup is by SHA alone, not filtered by `repository.full_name`/organization.

### Impact Explanation
This is a cross-repository, cross-organization write: an entity that is only authenticated for organization A is able to write commit-status data belonging to organization B's stacks. This directly maps to `Commit#deployable?`, which gates continuous delivery and deploy eligibility on commit status: [6](#0-5) 

and to `Commit#schedule_continuous_delivery`, which triggers `ContinuousDeliveryJob` once a commit is marked deployable: [7](#0-6) 

By forging a `success` status for a colliding-SHA commit in a victim stack that has continuous deployment enabled, an attacker who only controls a different, unrelated organization's webhook credentials can cause Shipit to consider a commit deployable and trigger an unauthorized deploy in a repository/stack they have no legitimate relationship to. This matches the "cross-repository writes" / "unauthorized deploy" impact category (Critical).

### Likelihood Explanation
Likelihood depends on:
- Shipit being configured multi-tenant (multiple organizations each with their own GitHub App/webhook secret) - a documented, supported configuration (`Shipit.github(organization:)` is looked up dynamically per payload).
- The attacker controlling one legitimately onboarded organization (a much lower bar than compromising the target organization or obtaining a Shipit session/API token).
- SHA collision across repositories, which is common for forks, mirrors, or any two repos sharing commit history - not a cryptographic break, just normal Git behavior.

Given no additional binding is enforced between the authenticated org and the mutated commit's repository, the likelihood is non-trivial in any Shipit instance serving more than one organization/tenant.

### Recommendation
In `StatusHandler` (and any other handler relying on bare SHA lookups, e.g. verify similarly for `check_suite`), scope the query to the repository identified in the same payload used for signature verification, mirroring `Handler#stacks`/`Handler#repository_name`, e.g. resolve the commit through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` -> stacks -> commits, rather than a global `Commit.where(sha:)`. Additionally, have `verify_signature` and the handler agree on and pass forward the same authenticated organization value, and reject webhook payloads whose declared repository does not belong to the organization that produced a valid signature.

### Proof of Concept
1. Configure Shipit with two organizations, `org-attacker` and `org-victim`, each with its own `github.webhook_secret` (multi-tenant setup).
2. As the owner of `org-attacker`'s GitHub App, compute `sha256_hmac(webhook_secret_attacker, body)` for a crafted JSON body:
```json
{
  "sha": "<sha of a commit that also exists in org-victim's tracked stack, e.g. via a fork>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "org-attacker" } }
}
```
3. `POST /webhooks` with headers `X-Github-Event: status` and `X-Hub-Signature: sha1=<computed>`.
4. `WebhooksController#verify_signature` succeeds because it only checks the signature against `org-attacker`'s secret (which was legitimately used).
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)` and finds the commit belonging to `org-victim`'s stack (matched by SHA only), and calls `create_status_from_github!`, writing a forged "success" status onto it.
6. If `org-victim`'s stack has `continuous_deployment` enabled and the forged status satisfies `ci.require`, `Commit#deployable?` returns true and `ContinuousDeliveryJob` is scheduled, resulting in an unauthorized deploy triggered by an entity with no relationship to `org-victim`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
