### Title
Cross-organization / cross-repository CI-status forgery via unscoped `Commit` lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController` authenticates a GitHub webhook by picking which organization's `webhook_secret` to verify against based on an **attacker-controlled payload field** (`repository.owner.login`), then hands the parsed payload to the matching event handler. `Shipit::Webhooks::Handlers::StatusHandler`, unlike `PushHandler` and `CheckSuiteHandler`, never scopes its side effect to the repository/stack that was authenticated — it looks up `Commit` by `sha` alone, instance-wide. This breaks the binding "organization that authenticated == repository that is written," letting anyone who legitimately controls a webhook secret for *any* organization/repo onboarded to the shared Shipit instance forge a signed status event whose `sha` belongs to a *different* team's repository, injecting a fake commit status there.

### Finding Description
The webhook signature check derives the signing organization purely from the JSON body, which is otherwise untrusted until the HMAC check passes: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` selects a `GithubApp`/webhook-secret configuration keyed by the organization named inside the payload itself, and `verify_webhook_signature` validates the HMAC only proves the payload was signed with *that organization's* secret: [3](#0-2) 

This proves only that *some* organization/installation whose secret is known to the sender produced the payload — it does **not** prove that the `repository.full_name` used elsewhere in the same payload actually belongs to that organization; both fields are supplied by the same untrusted requester, so anyone controlling a legitimate GitHub App/webhook secret for their own onboarded org can simply put a different repo's identifiers in the rest of the JSON body while keeping `repository.owner.login` set to their own org so it passes signature verification.

Handlers are expected to re-scope to the authenticated repository via the base class helper: [4](#0-3) 

`PushHandler` and `CheckSuiteHandler` correctly use `stacks` (which filters by `repository_name` from `payload.dig('repository','full_name')`): [5](#0-4) [6](#0-5) 

`StatusHandler`, however, ignores repository scoping entirely and queries `Commit` globally by `sha`: [7](#0-6) 

Because commit SHAs are 40-hex-character git object ids that are public/observable (e.g. from GitHub UI, PRs, or a previous legitimate status payload for the target repo), an attacker who has any onboarded repository in the same Shipit instance can supply that arbitrary `sha` value and have `create_status_from_github!` executed against the victim commit, regardless of which repository/organization it belongs to.

### Impact Explanation
This is a cross-repository write: the trust binding "the organization whose signature was verified" vs "the repository/commit actually mutated" is broken, matching the report's underlying bug class (an unlocked/unvalidated correspondence between what was authenticated and what state gets written). An attacker with legitimate control of any single org's webhook secret in a shared, multi-tenant Shipit deployment can:
- Forge a passing/`success` CI status on an arbitrary victim commit in another team's stack, satisfying `ci.require` gating (see `Commit#deployable?`/status-based checks) and enabling an unauthorized deploy that never truly passed CI, or
- Pollute a victim's commit status history / dashboard with attacker-controlled `target_url`, `description`, `context` values.

This falls squarely in the listed High/Critical impact of "cross-repository writes" / "an unauthorized deploy… " triggered without holding an `ApiClient` token, without repository write access to the victim repo, and without the victim org's `webhook_secret`.

### Likelihood Explanation
Requires only that the attacker legitimately controls a webhook secret for some organization/repository already onboarded onto the shared Shipit instance (a normal, unprivileged level of access in a multi-team deployment tool), plus knowledge of a target commit SHA in another tracked repository (trivially obtainable from public GitHub activity). No session, `ApiClient` credential, or victim-org secret is needed, so likelihood is high wherever Shipit is shared across multiple teams/organizations.

### Recommendation
Scope `StatusHandler#process` (and any other handler that doesn't already do so) to the authenticated repository, e.g. restrict the `Commit` lookup to `stacks.flat_map(&:commits)` or otherwise verify `payload.dig('repository','full_name')`'s owner matches the organization whose secret validated the signature, mirroring the pattern already used in `PushHandler`/`CheckSuiteHandler`.

### Proof of Concept
1. Attacker onboards `attacker-org/attacker-repo` to the shared Shipit instance (or already has a repo tracked there) and knows its GitHub App `webhook_secret`.
2. Attacker crafts a `status` event JSON body with `repository.owner.login = "attacker-org"` (so `Shipit.github(organization: "attacker-org")` resolves to their known secret and `verify_webhook_signature` passes) but `sha = "<victim commit sha in victim-org/victim-repo>"`, `state = "success"`.
3. Attacker computes `X-Hub-Signature` using their own known `webhook_secret` over the raw body and POSTs to `/webhooks`.
4. `WebhooksController#verify_signature` passes (valid signature for `attacker-org`).
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)` — matching the victim commit anywhere in the instance — and calls `create_status_from_github!`, writing a forged `success` status onto the victim's commit despite the attacker never having any access to `victim-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
