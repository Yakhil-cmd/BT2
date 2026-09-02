### Title
Cross-organization Commit Status forgery via unscoped `StatusHandler` webhook lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
The webhook signature check in `WebhooksController#verify_signature` authenticates *which organization* a webhook came from, but the actual data mutation performed by `StatusHandler#process` is never scoped back to that authenticated organization or its repositories. This breaks the binding "organization authenticated == repository/stack that is written," allowing a legitimately onboarded tenant organization to forge commit statuses belonging to a completely different organization's stacks in a multi-tenant Shipit deployment.

### Finding Description
`WebhooksController#verify_signature` derives the organization to check the HMAC signature against directly from attacker-controlled JSON body fields: [1](#0-0) [2](#0-1) 

This confirms only that *some* onboarded GitHub organization sent the request — using that organization's own `webhook_secret`, which is legitimately known to that organization's admins (Shipit supports multiple organizations sharing one webhook endpoint, per `docs/setup.md`'s "Using Multiple Github Applications" section).

Once the signature is accepted, `WebhooksController#create` dispatches the entire raw JSON body to the registered handler with no further binding to the verified organization: [3](#0-2) 

For `push` and `check_suite` events, the base `Handler` class correctly re-derives the target `Stack`s only from `repository.full_name` inside the payload and filters through `Repository.from_github_repo_name`: [4](#0-3) 

However, `StatusHandler#process` — used for the `status` event — never calls this scoping helper at all. It looks up commits **globally, across every repository/stack in the entire Shipit installation**, keyed only by the attacker-supplied `sha` string: [5](#0-4) 

Because the JSON body is entirely attacker-authored (this is a forged `X-Github-Event: status` request, not a real relay from GitHub), the attacker can set `sha` to any 40-hex string of their choosing — including the exact SHA of a commit that belongs to a completely different organization's stack that Shipit tracks. The HMAC signature only proves "this came from an onboarded org," never "this org owns the referenced commit/repository."

This is the direct structural analog of the report's root cause: just as `BunniHook`/`AmAmm` assumed `block.number` on Arbitrum always refers to the chain whose block-time constant `_K` was configured, `StatusHandler` assumes any accepted webhook signature implies authority over the specific commit named in the payload. Both are "trusted context A implies target B" assumptions that don't actually hold.

### Impact Explanation
A tenant organization "Org A" onboarded to a multi-tenant Shipit instance (with its own legitimate `webhook_secret`) can forge `Commit::Status` records for commits belonging to "Org B"'s stacks that Org A has no GitHub permissions over. This is an unauthorized cross-repository/cross-tenant write of deploy-relevant state (`Commit.create_status_from_github!`), matching the "cross-repository writes" impact category — statuses influence whether Shipit considers a commit deployable, so this can be used to manipulate another tenant's deploy pipeline decisions without any access to that tenant's GitHub organization or repositories.

### Likelihood Explanation
Requires only that the attacker control (as a legitimate app owner) one organization already onboarded to the shared multi-tenant Shipit instance — no privileged Shipit account, no stolen secret belonging to another tenant, and no access to the victim's GitHub org is needed, since `StatusHandler` performs a completely unscoped, global `Commit.where(sha: ...)` lookup.

### Recommendation
`StatusHandler#process` should scope its `Commit` lookup through the same `stacks`/`Repository.from_github_repo_name(repository_name)` helper used by `PushHandler` and `CheckSuiteHandler`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)`, so that a status update can only ever mutate commits belonging to the repository named — and implicitly authenticated — in that specific webhook payload.

### Proof of Concept
1. Org A is a legitimate tenant of a shared Shipit install with its own `webhook_secret_A` (per `docs/setup.md` multi-org config).
2. Attacker (an admin of Org A) crafts a `status` webhook body: `{"sha": "<known sha of a commit belonging to Org B's tracked stack>", "state": "success", "repository": {"owner": {"login": "OrgA"}, "full_name": "OrgA/some-repo"}}`.
3. Attacker signs the raw body with `webhook_secret_A` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` to `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)` globally, finds Org B's commit, and calls `create_status_from_github!`, mutating Org B's stack state despite Org A having no relationship to Org B's repository.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
