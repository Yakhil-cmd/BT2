### Title
Cross-repository forgery of commit CI status via `StatusHandler` breaks the "authenticated organization vs. written repository" binding - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook only against the **organization** derived from the payload (`repository.owner.login`), using that organization's shared `webhook_secret`. Once the HMAC check passes, the payload is dispatched to a handler that is expected to act only on the repository that produced the event. `Webhooks::Handlers::StatusHandler`, however, updates commit statuses by looking up commits **globally by SHA**, with no check that the SHA belongs to a stack whose repository matches the payload's `repository.full_name`. This mirrors the `StakingRewards.recoverERC20` pattern: a security check (signature/ownership verification) covers one field (the organization identity) while a sensitive, irreversible action (mutating state used for deploy-safety gating) operates on a different, uncovered field (an arbitrary commit SHA across the whole instance).

### Finding Description
- Signature verification is scoped to organization only: `verify_signature` resolves `github_app = Shipit.github(organization: repository_owner)` and checks the HMAC over the raw payload using that organization's `webhook_secret`. [1](#0-0) [2](#0-1) 

- After signature verification, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the parsed JSON body directly to the matching handler, with no re-validation that the payload's repository matches anything specific to the requester. [3](#0-2) 

- The base `Handler` class exposes a `repository_name` helper (`payload.dig('repository', 'full_name')`) and a `stacks` helper that scopes lookups to that repository, and most handlers (e.g. `PushHandler`) correctly use it. [4](#0-3) [5](#0-4) 

- `StatusHandler`, however, never calls `repository_name`/`stacks`. It resolves the target purely by SHA against the entire `Commit` table:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [6](#0-5) 

The binding that should hold is: **organization that authenticated the webhook == repository whose commits are mutated**. Because `StatusHandler` ignores the payload's `repository` entirely and matches on SHA alone, any repository under an org's shared GitHub App installation (the app's `webhook_secret` is shared across all repositories the App is installed on) can produce a validly-signed `status` event that writes a commit status onto a commit belonging to a **completely different repository/stack** tracked by the same Shipit instance, as long as it guesses/knows that commit's SHA (SHAs are not secret — they are visible in PRs, `git log`, CI dashboards, etc., for any repo, and Shipit's `X-Shipit-User` values, permalinks, and other public views leak them too).

### Impact Explanation
Commit statuses feed directly into Shipit's `ci.require` deploy-safety gating (documented in `README.md`'s CI configuration section) — statuses determine whether a commit is considered "deployable" via `Commit#create_status_from_github!` (referenced in `app/models/shipit/commit.rb`, though full contents were not retrievable from the index). An attacker who controls (or can push commits/CI to) any one repository sharing the org-level GitHub App can forge a `success` status with an arbitrary `context` for a commit SHA belonging to an unrelated, higher-value stack, potentially satisfying `ci.require` and enabling an **unauthorized deploy** of a commit that never actually passed CI on its own repository. This is a cross-repository write of security-relevant state and can escalate to an unauthorized deploy, matching the Critical/High impact classes in scope.

### Likelihood Explanation
Requires only that the attacker controls (or can trigger CI/webhooks from) any single repository installed under the same multi-tenant GitHub App/organization as the victim stack — no Shipit session, ApiClient token, or Shipit-side privilege is needed, since the webhook signature is satisfied by GitHub itself for any repo under that App installation. The attacker additionally needs the target commit's SHA, which is generally discoverable (public repos, PR pages, prior Shipit output, etc.). This is a realistic scenario for any Shipit deployment that serves multiple repositories/teams under one GitHub App per organization, which is the documented default single-org setup.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the repository that produced the event, mirroring `PushHandler`/other handlers' use of `stacks`/`repository_name`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
More generally, audit all `Webhooks::Handlers` subclasses to ensure every state-mutating lookup is scoped through `repository_name`/`stacks`, so that the organization bound by `verify_webhook_signature` is always the same entity whose data gets written.

### Proof of Concept
1. Shipit is configured with a single GitHub App for organization `acme`, tracking `acme/high-value-service` (Stack A) and also having the App installed on `acme/low-value-tool` (a repo an attacker can push to / control CI for), since GitHub Apps are typically installed org-wide.
2. Attacker discovers the SHA of a commit `abcd123` on `acme/high-value-service` that has not yet passed the required `context: "ci/tests"` status check.
3. Attacker triggers (or crafts, if they control a CI integration on `low-value-tool`) a GitHub `status` webhook event with:
   - `repository.owner.login = "acme"` (so `verify_signature` resolves and validates against `acme`'s `webhook_secret` — a valid signature since GitHub itself signs it for any repo under that App installation)
   - `sha = "abcd123"`, `state = "success"`, `context = "ci/tests"`
4. `WebhooksController#verify_signature` passes because the signature is valid for org `acme`. [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: "abcd123")`, matches the Stack A commit (unrelated to `low-value-tool`), and writes a fabricated `success` status onto it. [6](#0-5) 
6. If `ci.require` for Stack A includes `ci/tests`, this forged status can satisfy the safety check, enabling a deploy of `abcd123` on `acme/high-value-service` that never actually passed CI there.

Note: I could not retrieve the full body of `Commit#create_status_from_github!` and the exact `ci.require` gating logic from the index (only grep hits were found, not full file contents), so the precise mechanics of how a forged status affects deploy eligibility should be verified directly in `app/models/shipit/commit.rb` and the deploy-safety check code before remediation.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
