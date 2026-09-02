This confirms the finding. `StatusHandler#process` looks up commits purely `by sha` (`Commit.where(sha: params.sha)`) with **no repository/organization scoping at all**, and `PushHandler`/`Handler#repository_name` resolve the target `Stack` from `payload.dig('repository', 'full_name')` — a field that is never cross-checked against the organization whose secret authenticated the request. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Webhook signature verification authenticates the payload's claimed organization, not the repository/commit that handlers actually act on, allowing cross-organization status/commit forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/`webhook_secret` to validate the HMAC signature against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. This lets Shipit run in a "multi-org" configuration (`test/dummy/config/secrets_double_github_app.yml` shows `OrgOne`/`OrgTwo` each with distinct `webhook_secret`s). Once the signature check passes for *some* configured organization, the handlers (`PushHandler`, `StatusHandler`, pull-request handlers, etc.) process the rest of the JSON body without any further verification that the acted-upon `repository.full_name` / commit `sha` actually belongs to the organization whose secret was used. `StatusHandler` in particular resolves commits by SHA alone, with zero repository scoping.

### Finding Description
The equality that should hold is: `organization whose webhook_secret verified the HMAC == organization owning the repository/commit that the handler mutates`. It does not hold.

- `verify_signature` selects `github_app = Shipit.github(organization: repository_owner)` using only `repository.owner.login` (or `organization.login`), then calls `github_app.verify_webhook_signature(signature, raw_post)` [1](#0-0) [4](#0-3) .
- Because the attacker fully controls the raw JSON body they send (they need only a `webhook_secret` for *any* organization configured on the shared Shipit instance — a secret they legitimately possess because they administer that organization's own GitHub App/webhook, not a Shipit credential), they can set `repository.owner.login` to their own org (so the secret check passes) while every other field in the same payload — `repository.full_name`, `sha`, `ref`, `pull_request` — references a completely different organization's repository/commit.
- Handlers never re-validate this: `Handler#repository_name` blindly trusts `payload.dig('repository', 'full_name')` to resolve the `Stack`/`Repository` to mutate [3](#0-2) , and `StatusHandler#process` resolves target commits with a global, unscoped `Commit.where(sha: params.sha)` lookup [2](#0-1) , which can match a commit belonging to any stack in the whole installation, irrespective of which org's secret was used to authenticate.

This is structurally the same class of bug as the report: a value that is credited/acted upon (`roots`) is never actually tied back to the value that should govern it (`stalk`/ratio). Here, the repository/commit that is *written to* is never tied back to the organization that was *cryptographically verified*.

### Impact Explanation
An attacker who legitimately controls a GitHub App/webhook installation for one organization configured on a shared Shipit instance can forge `status` events for commits belonging to a *different* organization's stack. Since `Commit#create_status_from_github!` feeds directly into `deployable?` [5](#0-4)  and into merge-queue processing (`stack.schedule_merges` / `ProcessMergeRequestsJob` / `MergeRequest#merge!`), the attacker can mark an arbitrary victim commit as `success`, causing an unauthorized deploy or an unauthorized pull-request merge in an organization/repository they do not control. This matches the Critical bucket ("unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires the Shipit deployment to host more than one GitHub organization's App/webhook_secret (a documented, supported configuration — see `secrets.development.shopify.yml` and `secrets_double_github_app.yml`), and requires the attacker to be a legitimate admin/owner of at least one of those organizations (able to configure its GitHub App webhook secret) while not being a member of the victim organization. No Shipit session, `ApiClient` token, or GitHub App private key is needed — only knowledge of one org's `webhook_secret`, which that org's own admins possess by design.

### Recommendation
After signature verification, re-derive the organization strictly from the *verified* HMAC (i.e., only accept the payload under the org whose secret matched, and reject if that org's name doesn't match `repository.full_name`'s owner segment). Scope all handler lookups (`StatusHandler`, `PushHandler`, pull-request handlers) by the authenticated organization instead of trusting `repository.full_name`/`sha` unscoped.

### Proof of Concept
1. Configure two orgs, `OrgOne` (`webhook_secret: secretA`) and `OrgTwo` (`webhook_secret: secretB`), both pointing at the same Shipit instance (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an admin of `OrgOne`, craft a `status` webhook body: `{"repository": {"owner": {"login": "OrgOne"}}, "sha": "<victim-commit-sha-in-OrgTwo-repo>", "state": "success", ...}`.
3. Sign it with `secretA` (`X-Hub-Signature: sha1=<hmac>`), send it to `/webhooks`.
4. `verify_signature` resolves `repository_owner` = `"OrgOne"`, verifies successfully with `secretA`.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a `success` status on the victim commit belonging to `OrgTwo`'s stack, potentially triggering an unauthorized deploy/merge there.

### Citations

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```
