### Title
Cross-tenant Status write via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits globally by `sha` with no scoping to the repository/organization that authenticated the webhook, unlike `PushHandler` and `CheckSuiteHandler`, which both resolve `stacks` from `payload.dig('repository', 'full_name')` via `Handler#stacks`/`#repository_name` before touching any records. This means any correctly-signed "status" webhook whose `sha` happens to match a commit belonging to a stack owned by a different organization will have a `Status` row written to that other organization's commit.

### Finding Description
The claimed broken binding is: `organization whose webhook_secret authenticated the payload == organization owning the Commit/Stack the status is attached to`.

Trace:
- `WebhooksController#verify_signature` resolves the signing org via `repository_owner`, which reads `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) , then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [2](#0-1) . This step only proves that whichever org's secret was used to sign the request matches the org named in the payload — it says nothing about which repository/stack the `sha` in the body belongs to.
- `Handlers::StatusHandler#process` then does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . This is a **global** lookup across every `Commit` row in the database, regardless of `stack`, `repository`, or organization.
- By contrast, `PushHandler#process` and `CheckSuiteHandler#process` both scope through `stacks`, which is derived from `payload.dig('repository', 'full_name')` in the base `Handler` class [4](#0-3)  — i.e., they only touch stacks belonging to the repository named in the payload. `StatusHandler` has no equivalent check.
- Root cause: git commit SHAs are content-addressed and are **not unique per organization** — the same SHA can legitimately exist in multiple repositories owned by different organizations/tenants (e.g., forks, mirrors, or repos that share history). `verify_signature` only proves "this payload was signed by org A's secret"; it does not — and cannot, by itself — prove "the `sha` in this payload belongs to a commit in a repository under org A." `StatusHandler` never re-derives or checks the repository/stack ownership of the matched `Commit` against the payload's `repository`/`organization`, so the two facts are silently conflated.
- Exploitable request: an attacker with legitimate (unprivileged) push/webhook-configuration rights on a repository under organization A that shares a commit SHA with a repository under victim organization B (e.g., A's repo is a fork of B's repo, or A pushes a commit that is a superset containing B's existing commit) causes GitHub to emit a real, correctly-signed `status` event for org A containing that shared `sha`. Because `verify_signature` only checks that the signature matches org A's `webhook_secret` (which it legitimately does, since GitHub itself computed it), the request passes verification. `StatusHandler` then finds and mutates **every** `Commit` row with that SHA, including the one under org B's stack, writing an attacker-controlled `Status` (state/description/target_url/context) onto a commit the attacker's organization never owned.
- Existing guards that fail to prevent this: `verify_signature`/`verify_webhook_signature` only validate the HMAC against the resolved org's secret [5](#0-4) ; they perform no cross-check against the commit's actual owning stack. `ExplicitParameters` params schema for `StatusHandler` only validates types/presence of `sha`, `state`, `branches`, etc. [6](#0-5)  — it has no repository-ownership constraint. No `Stack`/`Repository` scoping equivalent to `Handler#stacks` is applied in `StatusHandler#process`.

### Impact Explanation
An attacker who legitimately controls (or can trigger webhook delivery from) organization A's Shipit-integrated repository can write a forged `Status` (`state`, `description`, `target_url`, `context`, `created_at`) onto a `Commit` belonging to an unrelated organization B's `Stack`, as long as that commit's SHA is shared between A's and B's repositories (fork/mirror/shared-history scenario). `Status#after_create`/`after_commit` callbacks (`enable_ci_on_stack`, `schedule_continuous_delivery`, `broadcast_update`) then fire on victim B's stack/commit [7](#0-6) , which can influence continuous delivery decisions (e.g., marking a commit "success" to unblock/trigger a deploy) — this is a payload for one repository mutating another's commit/stack state, matching the Critical category ("a payload for one repository mutating another's stack, commit ... or an unauthorized deploy"). The attack is repeatable against any pair of orgs/stacks that share commit history (forks are extremely common), and blast radius spans all tenants configured in `TOP_LEVEL_GH_KEYS` multi-org mode.

### Likelihood Explanation
Requires Shipit configured in multi-org mode with at least two organizations (`TOP_LEVEL_GH_KEYS`), and requires the attacker's org/repo to share a commit SHA with a victim org's tracked repository — realistically achievable via GitHub forks (fork commits retain identical SHAs to upstream) or shared history. The attacker needs no Shipit secrets; they only need legitimate control of a repository/org that GitHub will deliver a correctly-signed `status` webhook for, which is a low-cost, common scenario (any public fork). This is fully repeatable and does not require guessing any secret.

### Recommendation
In `Handlers::StatusHandler#process`, scope the commit lookup to the stacks/repository resolved from the webhook's own `repository`/`organization` payload (mirroring `Handler#stacks`), e.g., restrict to `stacks.joins(:commits).where(commits: { sha: params.sha })` or explicitly filter `Commit.where(sha: params.sha)` down to commits whose `stack.repository` matches `repository_name`/`repository_owner` derived from the same payload used for signature verification, rejecting or ignoring matches outside that scope.

### Proof of Concept
Minitest plan (no live GitHub):
1. Create two orgs' worth of fixtures: `stack_a` under org `"org-a"` and `stack_b` under org `"org-b"`, each with its own `Repository`/`Stack`.
2. Create `commit_b` under `stack_b` with a fixed `sha` (e.g., `"deadbeef" * 5`).
3. Stub `Shipit.github(organization: "org-a")` (or whichever the payload resolves to) so `verify_webhook_signature` returns `true` (simulating a correctly-signed payload from org A), without granting org A any relation to `stack_b`.
4. POST `/webhooks` with `X-Github-Event: status`, body `{ "sha" => commit_b.sha, "state" => "success", "repository" => { "full_name" => "org-a/some-repo", "owner" => { "login" => "org-a" } } }`.
5. Assert: `assert_difference('commit_b.statuses.count', 1) { post :create, body:, as: :json }` — i.e., a `Status` is written on `commit_b` (owned by `stack_b`/org B) despite the request being authenticated solely with org A's webhook secret and org A's payload naming an unrelated repository.
6. Assert equality-before-after: before the request, `repository_owner_used_for_verification == "org-a"` and `commit_b.stack.repository.owner == "org-b"` (mismatched); after the request, the `Status` row still exists on `commit_b`, proving the binding is violated.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/status.rb (L16-21)
```ruby
    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
```
