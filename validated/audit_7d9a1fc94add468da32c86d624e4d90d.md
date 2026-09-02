### Title
Webhook signature scope (org secret) is not bound to the repository/commit the handler writes to - cross-organization status/deploy forgery ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret used to authenticate an inbound webhook purely from an organization-derived field in the JSON body, while the handlers that actually mutate state key off a *different, unrelated field* of the same body (or, in the case of the `status` event, no repository scoping at all). Because HMAC verification only proves "this exact byte blob was signed with secret S", it does not constrain which repository/commit that blob claims to describe. An attacker who legitimately controls one onboarded GitHub organization's webhook secret (a normal, unprivileged capability in a multi-org Shipit deployment) can therefore forge a signed payload that is verified against their own org's secret but whose effects land on a completely different organization's stack.

### Finding Description
`WebhooksController#verify_signature` computes the signing organization like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), and `Shipit.github(organization: repository_owner)` is used only to pick which app's `webhook_secret` verifies `X-Hub-Signature` against `request.raw_post` (see `GitHubApp#verify_webhook_signature` in `lib/shipit/github_app.rb:76-83`). Multi-org deployments configure one distinct secret per organization, as documented in `docs/setup.md:182-209` and `config/secrets.development.shopify.yml`.

Once the signature is accepted, `create` dispatches the *entire raw payload* to event handlers: [3](#0-2) 

The base `Handler` class resolves the actual target repository/stack from a **separate** field, `repository.full_name`: [4](#0-3) 

`repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the target `Repository`/`Stack`) are independent JSON fields inside the same signed body. Nothing ties them together cryptographically or logically — the app never asserts that `full_name` starts with `owner.login`. For a genuine GitHub-originated webhook the two are always consistent, but an attacker crafting their own request body (using a secret they legitimately know for their own org) can set them independently.

The `status` handler is the most severe case: it does not consult `repository` at all and matches purely on commit SHA across the entire instance: [5](#0-4) 
This means *any* org's valid webhook secret can be used to create a `Status` on a `Commit` belonging to *any other org's stack*, as long as the attacker knows/guesses the target commit's SHA (trivially obtainable from a public repository's Git history or GitHub API).

`PushHandler` and `CheckSuiteHandler` are similarly scoped only by the attacker-supplied `repository.full_name`/`repository.owner.login` pairing, not by the organization that the signature actually authenticated: [6](#0-5) [7](#0-6) 

**The binding that should hold but doesn't:** `organization authenticated by signature == organization that owns the repository/commit being written`. Before the attacker's request, this equality always holds because GitHub itself populates and signs the payload atomically. After a forged request from an attacker who legitimately controls one org's secret, the two sides diverge: signature says "Org A", write target says "Org B / any commit in the system".

### Impact Explanation
This crosses the Critical bar for "unauthorized deploy, rollback or merge" and "cross-repository writes":
- Via `status`, an attacker can post a fabricated green/success `Status` on any commit in any other organization's stack, which is exactly the signal `Stack#required_statuses`/`blocking_statuses` and the merge queue rely on to gate merges and deploys — this can be used to push an otherwise-blocked commit through the merge queue or unblock a deploy validation gate, i.e., an unauthorized merge/deploy on a repository the attacker has no legitimate access to.
- Via `push`/`check_suite`, an attacker can trigger `GithubSyncJob`/check-run refresh cycles against another org's stack using attacker-chosen `after` SHAs, corrupting that stack's notion of HEAD/build state.
- The only prerequisite is being an admin of *any one* GitHub organization onboarded to the same multi-tenant Shipit instance — an unprivileged position with respect to every other organization hosted there.

### Likelihood Explanation
Requires a specific deployment shape (multiple GitHub organizations configured under one Shipit instance, per `docs/setup.md`'s "Using Multiple Github Applications" section) and knowledge of a target commit SHA for the `status` path. Both are realistic for any shared/multi-tenant Shipit install and for public target repositories. No GitHub App private key, Shipit session, or `ApiClient` token is needed — only a legitimately-owned webhook secret for one tenant org.

### Recommendation
After verifying the HMAC signature, re-derive the acting organization strictly from a field the handler will actually act on (e.g., require `repository.full_name`'s owner segment to equal the `organization`/`repository.owner.login` used for signature selection, and reject on mismatch). For `StatusHandler`, scope `Commit` lookups by the stack/repository identified in the verified payload instead of a global SHA match across all stacks. In general, ensure the same field used to select the verifying secret is the field the handler treats as authoritative for locating the target resource.

### Proof of Concept
1. Deploy Shipit with two orgs configured, e.g. `orgA` and `orgB` (each with its own `webhook_secret`), per `docs/setup.md:182-209`.
2. As the (unprivileged w.r.t. orgB) admin of `orgA`'s GitHub App, know `orgA`'s `webhook_secret`.
3. Find a commit SHA belonging to a private/protected stack under `orgB` (e.g., via a public mirror or leaked commit reference).
4. Craft a `status` webhook JSON body:
   ```json
   {"sha": "<orgB-target-sha>", "state": "success", "context": "ci/required-check"}
   ```
5. Compute `X-Hub-Signature: sha1=<hmac>` using `orgA`'s known `webhook_secret` over the exact raw body, per `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`).
6. POST to `/webhooks` with `X-Github-Event: status` and the computed signature. `verify_signature` resolves `repository_owner` from `params.dig('organization','login')` (absent here) — actually for `status` there's no `repository` object required either, only `sha`/`state`, so `repository_owner` can simply be set to `orgA` via `organization.login` while `sha` targets orgB's commit; the signature check in `app/controllers/shipit/webhooks_controller.rb:24-30` passes against `orgA`'s secret.
7. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) matches `Commit.where(sha: params.sha)` globally and creates the forged status on `orgB`'s commit, regardless of the fact that the signature only proved knowledge of `orgA`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
