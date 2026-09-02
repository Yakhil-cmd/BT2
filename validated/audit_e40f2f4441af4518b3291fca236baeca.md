### Title
`status` webhook accepted with no HMAC for orgs missing `webhook_secret`, then `StatusHandler` applies the status to any commit sharing that SHA regardless of repository - triggering `ContinuousDeliveryJob` on victim stacks - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when the resolved organization's config has a blank `webhook_secret`, so a forged `status` payload naming that org's login is accepted without any HMAC check. `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository/stack scoping, so the attacker's forged status is applied to every `Commit` record across all stacks sharing that SHA, and `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery` will enqueue `ContinuousDeliveryJob` for any stack that is `continuous_deployment?` and `deployable?`.

### Finding Description
The invariant that should hold is: `commit.stack.repository_owner_login == params.dig('repository','owner','login')` for any commit mutated by a webhook, i.e. a `status` event should only affect commits belonging to the repository whose secret authenticated the payload. This is not enforced anywhere in the path.

Trace:
1. `Shipit::WebhooksController#verify_signature` resolves `github_app = Shipit.github(organization: repository_owner)` from the attacker-controlled `repository.owner.login` field [1](#0-0) .
2. `GitHubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank for that org's config: `return true unless webhook_secret` [2](#0-1) . Any organization configured in Shipit without a `webhook_secret` entry lets an attacker forge arbitrary event bodies with zero authentication cost, simply by setting `repository.owner.login` to that org's name.
3. `StatusHandler#process` executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — there is no `stack_id`, `repository`, or org filter at all [3](#0-2) . Any `Commit` row in the entire database with a matching `sha` (e.g., a shared upstream commit, a fork, or a colliding history) receives the attacker's forged status, independent of which repository/org authenticated the request.
4. `create_status_from_github!` creates a `Status` row via `add_status` [4](#0-3) , and `Status` has `after_commit :schedule_continuous_delivery` which calls `commit.schedule_continuous_delivery` [5](#0-4) .
5. `Commit#schedule_continuous_delivery` enqueues `ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)` when `deployable? && stack.continuous_deployment? && stack.deployable?` [6](#0-5) .

Attacker request: `POST /webhooks` with header `X-Github-Event: status`, body `{"sha": "<victim commit sha>", "state": "success", "repository": {"owner": {"login": "<no-secret-org>"}}}`. No signature header is required to pass verification. If the resolved commit's stack has `continuous_deployment` enabled, this can push the stack toward an actual deploy of the now-"green" commit.

Existing guards fail because: `verify_signature` only checks org existence and (if present) HMAC — it does not require a `webhook_secret` to exist, and treats "no secret configured" as "trust unconditionally" rather than "reject." `StatusHandler`'s `ExplicitParameters` schema validates the shape of `sha`/`state`/etc. but never validates that the SHA belongs to a commit under the authenticated repository. There is no `repository_owner`/`stack.repository` cross-check anywhere in `StatusHandler` or `Commit#create_status_from_github!`.

### Impact Explanation
This lets an unprivileged internet attacker inject a fabricated "success" CI status onto any `Commit` record whose SHA is known to them (trivially true for public shared history/forks), for **any org configured without a `webhook_secret`** — an org the attacker did not need to compromise, only needed Shipit to have configured. If the affected commit belongs to a `continuous_deployment`-enabled stack, this schedules `ContinuousDeliveryJob`, which can deploy that commit without any legitimate CI signal. This is a payload naming one (no-secret) organization causing a write against a stack/commit that never authenticated the request — matching "a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy" under the Critical category. The blast radius spans every stack whose commits happen to share SHAs reachable by the attacker (public forks/mirrors are the common case) and is repeatable per request.

### Likelihood Explanation
Preconditions: (a) Shipit must have at least one org configured with `github_app`/`github` config but a blank `webhook_secret` — this is an operator configuration state, not something the codebase forbids, and the ticket accepts this as the "no-secret organization" precondition; (b) a victim stack with `continuous_deployment` enabled; (c) attacker needs to know a valid commit SHA belonging to that stack's repo (readily available for any public/forked repo, or via normal PR activity). Attacker cost is a single unauthenticated HTTP POST, fully repeatable, with no session/token/secret required — satisfying the "unprivileged attacker" constraints.

### Recommendation
- In `GitHubApp#verify_webhook_signature`, do not return `true` when `webhook_secret` is blank; require an explicit "no verification" opt-in only in trusted/test environments, or better, reject payloads for orgs without a secret.
- In `Shipit::WebhooksController#verify_signature`/`StatusHandler`, scope `Commit` lookups by the authenticated repository: resolve the `Stack`/`Repository` from `repository_owner` + `repository.full_name` and constrain `Commit.where(sha: params.sha, stack_id: stack.id)` (or filter by `commit.stack.repository`) rather than searching all commits globally by SHA.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`, matching existing test conventions like `":state create a Status for the specific commit"`):
1. Configure a fixture/stub org (e.g., stub `Shipit.github(organization: 'no-secret-org')` to return a `GitHubApp` built with `config` that omits `webhook_secret`) so `verify_webhook_signature` returns `true` for any body/signature.
2. Create a victim `Stack` fixture with `continuous_deployment: true` and `deployable?` stubbed/true, with a `Commit` whose `sha` is known (`commit.sha`).
3. POST to `/webhooks` with `X-Github-Event: status`, no `X-Hub-Signature` header (or an arbitrary bogus one), body `{ sha: commit.sha, state: 'success', repository: { owner: { login: 'no-secret-org' } } }`.
4. Assertions (both sides of the binding):
   - Before: `commit.stack.repository_owner_login != 'no-secret-org'` (the request did not authenticate against the victim's own org/secret).
   - After: `assert_difference('commit.statuses.count', 1) { post :create, ... }` succeeds, and `assert_enqueued_with(job: ContinuousDeliveryJob, args: [commit.stack])` fires — demonstrating the divergence: a stack that never authenticated the request via its own secret was mutated and scheduled for deployment.
5. Contrast with an org that *has* a `webhook_secret`: same forged, unsigned request must return `422` and enqueue nothing, proving the gap is specific to the "no-secret organization" + missing repository scoping combination.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
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

**File:** app/models/shipit/status.rb (L19-44)
```ruby
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```
