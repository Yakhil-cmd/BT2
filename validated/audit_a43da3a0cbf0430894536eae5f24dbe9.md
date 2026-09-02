### Title
Cross-repository CI status forgery via unscoped `StatusHandler` breaks the organization-signed / repository-written binding - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub `status` webhook against the GitHub organization derived from the payload's `repository.owner.login` field, using that organization's configured `webhook_secret`. However, `StatusHandler#process` never checks the payload's `repository` field at all — it looks up commits purely by SHA across the *entire* Shipit installation and writes a CI status to every match. This breaks the equality that should hold: `organization that signed the payload == repository whose commit status is written`.

### Finding Description
`WebhooksController#verify_signature` resolves the signing organization exclusively from the payload: [1](#0-0) 
using `repository_owner`, which is `params.dig('repository', 'owner', 'login')` (or the `organization` sub-object as fallback): [2](#0-1) 

This only proves that the sender controls a valid webhook secret for *some* organization/repository — the one named in `repository.owner.login`. It says nothing about which commits should be affected.

The `status` event is then dispatched unmodified to `Shipit::Webhooks::Handlers::StatusHandler`: [3](#0-2) 

`process` does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this query is **global**, not scoped to the repository/stack that the signature check authenticated. Contrast this with other handlers such as `PushHandler`, which correctly scope to `stacks` derived from `repository.full_name`: [4](#0-3) 
and the base `Handler#stacks`/`repository_name` helper that other handlers use to bind actions to the authenticated repository: [5](#0-4) 

`StatusHandler` never calls `stacks` or `repository_name` — it is the one event handler in this set that ignores the repository binding entirely.

Because Git commit SHAs are content-addressed and are commonly shared across forks, mirrors, and branch-based stacks tracking the same upstream history, an attacker who legitimately controls (as a repo/org admin) any GitHub repository that Shipit has a configured webhook secret for can:
1. Identify or engineer a commit SHA that also exists in a *different*, unrelated Shipit stack (trivial via forking a public repo — the SHA of any un-modified commit is identical between the fork and the original).
2. Trigger (or directly send, since they hold the valid secret for their own org/repo) a `status` webhook event where `repository.owner.login` is their own authenticated organization, but `sha` is the shared commit SHA that also belongs to the victim stack.
3. `verify_signature` passes (their own org's secret validates their own signed payload), and `StatusHandler` writes an attacker-controlled CI status (`state`, `context`, `description`, `target_url`) onto the victim commit in a completely different repository/stack, with no relationship between the authenticated org and the affected stack ever being checked.

### Impact Explanation
Commit statuses are the mechanism Shipit uses to gate deploy safety via the `ci.require` configuration (checked before allowing a commit to be deployed). By forging a passing status (e.g. `state: success`, matching a `context` listed in the victim stack's `ci.require`) on a shared-SHA commit, an unprivileged attacker (who only controls their own unrelated repository/org webhook) can make an otherwise CI-failing or CI-pending commit appear deployable in a stack they have no write access to, undermining the safety check that legitimate Shipit operators rely on before triggering a deploy. This is a direct escalation across a repository/authentication boundary that the signature check is supposed to enforce, and can facilitate an unauthorized/unsafe deploy of a victim's stack.

### Likelihood Explanation
Exploitation only requires: (a) admin/write access to one's own GitHub repository/org that already has a Shipit webhook configured (a routine, unprivileged setup step available to many onboarded teams, not a Shipit-privileged action), and (b) the ability to produce a commit whose SHA also appears in the victim stack's commit history — trivially achievable via forking a public repository and referencing any of its existing commits, since SHA-1 git object IDs are identical across all clones/forks that share that exact commit. No possession of the victim org's `webhook_secret`, `GITHUB_TOKEN`, or Shipit session is required.

### Recommendation
Scope `StatusHandler#process` (and any other handler operating on cross-cutting identifiers like SHA) to the repository authenticated by `verify_signature`, mirroring the pattern already used in `Handler#stacks`/`repository_name`. Concretely, require and validate the `repository.full_name` field in `StatusHandler`'s parameter definition, and filter `Commit.where(sha: params.sha)` down to commits whose `stack.repository` matches the repository derived from the verified payload (i.e., `Repository.from_github_repo_name(params.repository.full_name)`), rejecting or ignoring matches outside that repository.

### Proof of Concept
1. Attacker controls `attacker-org/some-repo`, which has a legitimate Shipit webhook configured with secret `S`.
2. Attacker forks (or otherwise obtains) `victim-org/tracked-repo`, a repository backing a Shipit stack with `ci.require: [ci/tests]`, and identifies a commit `C` (SHA `abc123...`) shared between both repositories (e.g., a commit that predates the fork).
3. Attacker crafts (or naturally triggers, e.g., by re-pushing/tagging) a GitHub `status` event on `attacker-org/some-repo` for SHA `abc123...` with `state: success`, `context: ci/tests`, correctly HMAC-signed with secret `S`.
4. `WebhooksController#verify_signature` resolves `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and verifies successfully against `S`.
5. `StatusHandler#process` runs `Commit.where(sha: "abc123...")`, which also matches commit `C` tracked under the `victim-org/tracked-repo` stack, and calls `create_status_from_github!` on it — writing a forged passing `ci/tests` status onto the victim stack's commit, potentially satisfying `ci.require` and enabling a deploy of that commit despite the attacker having no access to `victim-org`.

Note: I was unable to fully inspect `Commit#create_status_from_github!` and the exact `ci.require`/`deployable?` gating logic within the available index (only match counts were visible, not full file contents), so the precise mechanics of how a forged status feeds into deploy-eligibility gating should be confirmed by reading `app/models/shipit/commit.rb` and `app/models/shipit/deploy_spec.rb` directly in a full checkout.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
