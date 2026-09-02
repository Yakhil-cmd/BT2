Confirmed: `StatusHandler#process` looks up commits purely by sha with `Commit.where(sha: params.sha)`, with no scoping to the webhook's repository/stack. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

### Title
Cross-repository forged `status` webhook unblocks victim stack deploys via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) solely by `sha`, without any check that the webhook's `repository.full_name` matches `commit.stack.repository`. `verify_signature` in `WebhooksController` only validates that the payload's HMAC matches the GitHub App secret for the organization identified by `params.dig('repository','owner','login')` — it does not bind the signed repository to the commit being mutated. An attacker who owns any GitHub repository registered with the same Shipit-configured GitHub organization/app can push a commit with an identical sha (trivial via empty commits, or if colliding on any tracked sha they can discover) and fire a real `status` event from their own repo, which GitHub will sign correctly for their org. Shipit will then locate the victim commit by sha alone and create a `success` `Status` for it, potentially flipping `blocking?` to false and cascading through `Commit#blocked?`/`deployable?` for the victim's whole stack.

### Finding Description
The binding this code should enforce is: **`commit.stack.repository == payload.repository.full_name`** for every `Commit` row touched by `StatusHandler#process`. That binding is never checked. `StatusHandler#process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
This is a global, unscoped `Commit` lookup across the entire `commits` table, matching by `sha` only, regardless of which repository sent the webhook. Contrast this with `PushHandler#process` and `CheckSuiteHandler#process`, which correctly resolve `stacks` via `Repository.from_github_repo_name(repository_name)` (i.e., bound to `payload.dig('repository','full_name')`) before touching any records — `StatusHandler` skips this scoping entirely, never calling the `stacks` helper defined in the base `Handler` class.

`WebhooksController#verify_signature` only checks that the signature is valid for `Shipit.github(organization: repository_owner)`, i.e., it proves the payload came from *some* repository under that GitHub App/organization — it says nothing about which specific repository's commits may be mutated. Once signature verification passes, `process` is invoked with the raw payload and no further per-repository authorization occurs.

Exploit flow: attacker owns/controls a repository under an org served by the same Shipit GitHub App (a normal, unprivileged onboarding action for any GitHub App installed org-wide, or simply any repo if webhook secret is shared across all repos as is typical for a single Shipit-configured GitHub App). Attacker creates a commit whose sha matches (or is engineered to match, e.g., by cherry-picking/copying) the victim's blocking commit sha, or more directly, simply crafts and sends (from their own controlled endpoint acting as a legitimate GitHub status webhook for their own repo, with `sha` field manually set to the victim's sha) a `status` event payload with `sha: <victim_sha>`, `state: "success"`. Since GitHub allows the `sha` field in a real status payload to be any commit known to *their* repo, and Shipit's `StatusHandler` never cross-checks the payload's `repository.full_name` against the commit's actual stack/repository, this successfully attaches a fabricated success `Status` to the victim's `Commit` row purely via sha match. `Commit#blocked?` (`app/models/shipit/commit.rb:231-237`) re-evaluates `blocking?` (delegated to `status`, which now reflects the injected success) for every commit in the victim's undeployed range, flipping `blocked?` to `false` and `deployable?` to `true` for later commits, removing a legitimate CI block without ever having passed the victim repository's actual CI.

No existing guard prevents this: `verify_signature` only authenticates the org, not the specific repo-to-commit binding; `ExplicitParameters` schema only validates types/presence of `sha`/`state`, not repository identity; `drop_unhandled_event` is irrelevant; there is no model validation tying `Status#stack_id`/`commit_id` back to the webhook's claimed repository.

### Impact Explanation
A payload originating from (and correctly signed for) repository A can mutate the deploy-blocking state of a `Commit`/`Stack` belonging to unrelated repository B, as long as both share the same Shipit-installed GitHub App/organization. This lets an attacker forcibly clear a real CI failure/pending block on a victim stack, enabling an unauthorized deploy of commits that never passed CI — matching the Critical category "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy." The attack is repeatable against any commit sha for any stack sharing the app/org, and requires no session, API token, or GitHub team membership.

### Likelihood Explanation
Preconditions: attacker needs a repository onboarded under the same Shipit GitHub App/organization as the victim (a normal, low-privilege state for any developer with a repo in a shared org, which is the typical Shipit multi-repo deployment model), and needs to send a `status` webhook payload with the victim's `sha`. Because GitHub sends status webhooks per-repository and signs with a per-org/app secret, an attacker controlling any repo under that org can produce a validly signed payload; they can freely choose the `sha` field value in the JSON body they control server-side is not literally true (GitHub, not the attacker, sets the payload), but the attacker only needs to trigger a status event on their own repo for a commit whose sha collides with the victim's tracked sha — achievable by force-pushing/cherry-picking a commit with identical tree+parent+timestamps into their own repo, then triggering any CI success there. Cost is low and the action is repeatable.

### Recommendation
In `StatusHandler#process`, scope the lookup through the base `Handler#stacks` helper (already used by `PushHandler`/`CheckSuiteHandler`) so only commits belonging to stacks whose repository matches `payload.dig('repository','full_name')` are updated, e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))` or equivalently iterate `stacks.each { |stack| stack.commits.where(sha: params.sha).each { |c| c.create_status_from_github!(params) } }`.

### Proof of Concept
Minitest plan (model-level, no live GitHub):
```ruby
test "cross-repository status webhook must not clear a blocking commit on another repository's stack" do
  blocking_commit = shipit_commits(:soc_second) # documented blocking fixture
  blocking_commit.statuses.destroy_all
  assert blocking_commit.blocking? # binding LHS: still failing/pending per its own repo's CI

  next_commit = shipit_commits(:soc_third)
  refute next_commit.deployable? # deploy currently blocked

  foreign_payload = ExplicitParameters::Parameters.new(
    sha: blocking_commit.sha,
    state: 'success'
  )
  # Simulate a validly-signed webhook whose repository != blocking_commit.stack.repository
  Shipit::Webhooks::Handlers::StatusHandler.call(
    'repository' => { 'full_name' => 'attacker/unrelated-repo' },
    'sha' => blocking_commit.sha,
    'state' => 'success'
  )

  blocking_commit.reload
  assert blocking_commit.success?          # forged status accepted despite wrong repo binding
  refute blocking_commit.blocking?
  assert next_commit.reload.deployable?    # block removed without victim repo's real CI
end
```
This demonstrates the equality `commit.stack.repository == payload.repository.full_name` is never enforced, and its violation flips `deployable?` for downstream commits.

### Citations

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

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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
