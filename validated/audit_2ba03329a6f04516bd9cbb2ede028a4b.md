### Title
Cross-tenant commit status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` only proves that a `status` webhook was signed with the GitHub App secret belonging to the organization named in `params.dig('repository','owner','login')`; it never checks that the `sha` in the payload actually belongs to a repository under that organization. `StatusHandler#process` then queries `Commit.where(sha: params.sha)` across the entire `commits` table with no scoping to the authenticated repository/org at all, so any org with its own valid GitHub App installation can push a status for a sha that happens to collide with a commit tracked by a completely unrelated stack/org.

### Finding Description
The intended binding is: `repository_owner` used in `Shipit.github(organization: repository_owner)` (`app/controllers/shipit/webhooks_controller.rb:25,59-62`) should equal the org that owns every `Commit` row mutated by the handler processing that payload. That equality is never enforced.

Trace:
- `WebhooksController#verify_signature` [1](#0-0)  derives `repository_owner` purely from the untrusted JSON body [2](#0-1)  and asks `Shipit.github(organization: repository_owner)` for that org's app, then verifies the HMAC signature against that org's own `webhook_secret`. This only proves "the sender knows attacker-org's secret" — it says nothing about which `sha` is inside the body.
- `WebhooksController#create` dispatches to handlers with the raw parsed body, unfiltered by repository [3](#0-2) .
- The base `Handler` class actually provides a `stacks`/`repository_name`-scoped helper for exactly this purpose [4](#0-3) , but `StatusHandler#process` does not use it:
```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 
This query has zero repository/stack/org scoping — it matches by `sha` alone across every `Commit` row in the database, regardless of which stack or repository owns it.

Exploit: attacker owns `attacker-org` with a legitimate GitHub App install (their own `webhook_secret`). They craft a `status` event whose `repository.owner.login` is `attacker-org` (so `verify_signature` passes using attacker-org's own secret) but whose `sha` is copied from a real commit belonging to `victim-org`'s stack (obtainable from any public commit history/CI). `verify_signature` succeeds because it only checks the signature, not sha ownership. `StatusHandler#process` then finds and mutates the victim's `Commit` row via `commit.create_status_from_github!(params)`, injecting an arbitrary status (`state`, `context`, `target_url`, `description`) into `victim-org`'s commit — which can flip `Commit#deployable?`/`blocked?` and trigger `stack.schedule_merges` or `ContinuousDeliveryJob`, i.e., influence deploy/merge decisions for a repository the attacker never authenticated against.

No other guard intervenes: `ExplicitParameters` only validates the shape of the `status` payload (`sha`, `state`, etc.), not repository ownership; there is no `force_github_authentication`/`User#authorized?`/`require_permission!` check on this unauthenticated webhook endpoint by design; and `Repository`/`Stack` validations don't apply because no repository/stack record is looked up before mutating the `Commit`.

### Impact Explanation
An attacker with only their own throwaway GitHub org/App can inject/forge CI status entries on arbitrary commits belonging to any other tenant's stack, as long as they know or can guess a colliding `sha` (trivial for public repos, since git SHAs are public commit identifiers, not secrets). This can flip a victim commit's deployability, unblock or block deploys, and trigger continuous-delivery jobs — a webhook authenticated for org A writing state for org B. This matches the "payload for one repository mutating another's stack/commit" Critical category and is repeatable against arbitrary victim stacks by anyone who can register a GitHub App for their own org.

### Likelihood Explanation
Preconditions are low-cost and fully attacker-controlled: register any GitHub org, install a GitHub App on it (standard, unprivileged action), and know a target sha (git SHAs of commits under CI are typically discoverable, e.g., from a public repo, PR, or prior status webhooks). No Shipit secrets, sessions, or team membership are required. The request is a normal signed POST to `/webhooks`, fully repeatable for any known sha.

### Recommendation
In `StatusHandler#process` (and any other handler operating on shas), scope the `Commit` lookup by the authenticated repository, e.g. via the base `Handler#stacks` helper: `stacks.flat_map { |s| s.commits.where(sha: params.sha) }` or equivalently join `Commit` through `Stack`/`Repository` matching `payload.dig('repository','full_name')`, rather than a bare `Commit.where(sha:)`. Additionally, `verify_signature` should cross-check that the resolved repository's owner matches the org whose secret validated the signature (defense in depth), though the primary fix belongs in the handler's query scope.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (existing signature-verification test infra):
1. Fixture setup: `victim_commit` belongs to `stacks(:shipit)` (or similar) under org `"victim-org"`; assert `victim_commit.statuses.count == 0` before the request.
2. Configure a second GitHub App/organization `"attacker-org"` with a known `webhook_secret` (as done for existing org-scoped tests), independent from `"victim-org"`'s app.
3. Build a `status` event JSON body: `{"sha" => victim_commit.sha, "state" => "success", "context" => "ci/attacker", "repository" => {"owner" => {"login" => "attacker-org"}, "full_name" => "attacker-org/some-repo"}}`.
4. Compute `X-Hub-Signature` using `"attacker-org"`'s own `webhook_secret` (a value the "attacker" legitimately controls in this scenario) and POST to `/webhooks` with `X-Github-Event: status`.
5. Assert response is `200 OK` (i.e., `verify_signature` passed using attacker-org's own secret — binding equality `repository_owner ("attacker-org") == owner of mutated Commit` does NOT hold, yet processing proceeds).
6. Assert `victim_commit.reload.statuses.count == 1` and the new status's `context == "ci/attacker"`, proving a payload signed for `attacker-org` mutated a commit belonging to `victim-org`'s stack.

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
