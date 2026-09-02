### Title
Forged `status` webhook accepted for any org with unset `webhook_secret` triggers cross-repository status/merge state changes via `StatusHandler` - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for the resolved organization, and `WebhooksController#verify_signature` resolves that organization purely from the attacker-controlled `repository.owner.login`/`organization.login` field in the JSON body. Because `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with **no repository/stack scoping whatsoever**, an attacker who controls (or names) any org with no `webhook_secret` configured can forge a `status` event carrying an arbitrary `sha` and have it applied to any commit row in the database that matches that SHA, regardless of which stack/repository it actually belongs to.

### Finding Description
The broken binding: the code implicitly assumes `verified_organization == repository_that_owns_the_commit`, but neither `verify_signature` nor `StatusHandler` ever check that equality.

Path:
1. `POST /webhooks` with header `X-Github-Event: status` reaches `Shipit::WebhooksController#create` [1](#0-0)  after `verify_signature` runs as a `before_action` [2](#0-1) .
2. `verify_signature` resolves the org solely from the attacker-supplied payload (`repository.owner.login` or `organization.login`) and asks `Shipit.github(organization: repository_owner)` for a `GitHubApp`, then calls `verify_webhook_signature` [3](#0-2) .
3. `GitHubApp#verify_webhook_signature` returns `true` immediately `unless webhook_secret` — i.e., for any org that has no secret configured, **any** signature (even a garbage one) passes [4](#0-3) .
4. `StatusHandler#process` looks up commits **by SHA only**, with no join/filter on `repository_owner`, `stack.repository`, or any tenant boundary, and calls `create_status_from_github!` on every matching row [5](#0-4) .
5. `Commit#create_status_from_github!` → `add_status` records the new status and, if the state transitions to `pending` or `success`, calls `stack.schedule_merges` and emits `deployable_status`/`commit_status` hooks [6](#0-5) . Since `deployable?` depends on `success?` [7](#0-6) , and `schedule_continuous_delivery`/merge automation act on the victim stack using the stack's configured bot identity (`bot_login`) once the fabricated status flips the commit to deployable, the attacker can force a merge/deploy action to be scheduled for a stack it never authenticated against.

Attacker request: register/control any GitHub org `evil-org` that a Shipit operator has configured (or that resolves) with no `webhook_secret` in `config/secrets.yml`, then send:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything
{"sha":"<victim-commit-sha>","state":"success","context":"ci/anything","repository":{"owner":{"login":"evil-org"}}}
```
Because `repository_owner` is taken from this same forged body, `verify_signature` looks up `evil-org`'s (secret-less) `GitHubApp` and passes; `StatusHandler` then matches the victim's commit row purely by SHA and writes a forged "success" status to it, which can flip `deployable?` for a completely unrelated stack and trigger `schedule_merges`/continuous delivery there.

Existing guards fail because: `verify_signature` never confirms that the org whose secret was checked is actually the org that owns the commit being mutated; `ExplicitParameters` schema on `StatusHandler` only validates types (`sha`, `state`, etc.), not repository identity; there is no `stacks` scope or `Repository` format check anywhere in this handler.

### Impact Explanation
An attacker with no Shipit credentials can inject a forged commit status for a target commit/stack they do not own or control, using only an org that lacks a `webhook_secret`. When that forged status is applied to a stack with `continuous_deployment?` enabled and `bot_login` configured, `add_status`'s `stack.schedule_merges` / continuous delivery scheduling can be triggered as if the commit had genuinely passed CI, causing the bot identity to merge or deploy attacker-influenced state. This is a payload for one (attacker-named) repository/org mutating another repository's stack/commit state — squarely in the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). Repeatable against any commit SHA already known to the attacker (commit SHAs are public on GitHub) and any org lacking a configured `webhook_secret`, so the blast radius scales with the number of misconfigured/secret-less orgs on the Shipit instance.

### Likelihood Explanation
Preconditions: (a) at least one GitHub org registered in Shipit's config without a `webhook_secret` (explicitly acknowledged as an in-scope precondition of this question), and (b) knowledge of the target commit's SHA (public information via GitHub). No GitHub App private key, no Shipit session, no API token, and no team membership is required — the attacker only needs to be able to send an arbitrary HTTP POST to `/webhooks`. Cost is a single unauthenticated HTTP request per forged status; fully repeatable/scriptable.

### Recommendation
- In `WebhooksController#verify_signature`, resolve and verify against the organization that actually owns the *target* resource (the commit's stack/repository), not an org name taken from the untrusted payload, or better, reject payloads unless a `webhook_secret` is configured for that org at all (fail closed instead of the `return true unless webhook_secret` bypass in `GitHubApp#verify_webhook_signature`).
- In `StatusHandler#process` (and any other handler that does `Commit.where(sha: ...)` without repository scoping), join through `stack` and assert `stack.repository_owner`/`stack.repository_name` match `params.repository.full_name` before applying any state change.
- Require `webhook_secret` to be non-empty for all configured orgs, or otherwise disable webhook auto-verification for orgs without one.

### Proof of Concept
minitest plan (e.g. `test/controllers/webhooks_controller_test.rb` and `test/models/commits_test.rb`):
1. Configure two orgs in test secrets: `victim-org` (with `webhook_secret` set) and `attacker-org` (no `webhook_secret`).
2. Create `stack_victim` under `victim-org/repo`, `continuous_deployment: true`, `bot_login` configured; create `commit = stack_victim.commits.create!(sha: "deadbeef", ...)`.
3. Assert binding before: `commit.status.state != "success"` and `stack_victim.deployable_commits` does not include `commit`.
4. POST to `/webhooks` with header `X-Github-Event: status`, arbitrary/garbage `X-Hub-Signature`, and body `{"sha":"deadbeef","state":"success","context":"ci","repository":{"owner":{"login":"attacker-org"}}}`.
5. Assert response is `200 OK` (not `422`), proving `verify_signature` passed for `attacker-org` despite the payload targeting `victim-org`'s commit.
6. Reload `commit`; assert `commit.status.state == "success"` and that `stack_victim.schedule_merges`/`ContinuousDeliveryJob` was enqueued for `stack_victim` — i.e., the equality `verified_org == commit.stack.repository_owner` was false yet the state mutation occurred, proving the invariant is broken.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-6)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L365-386)
```ruby

    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
