### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `sha` across the entire `commits` table instead of scoping to the repository that authenticated the webhook, unlike the base `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) used elsewhere in the webhook handlers. An attacker who owns any GitHub repository registered with Shipit can push/import a commit object with the same SHA as a victim's tracked commit (trivial: SHAs are content-addressed, so cloning/cherry-picking the exact victim commit into an attacker-owned repo preserves the SHA), fire a real, correctly-signed `status` webhook from their own repository, and have the forged status written onto the victim's `Commit` row in a completely different `Stack`.

### Finding Description
The broken binding: `context` uniqueness for `Status::Group.compact` should be scoped as `(repository.full_name, sha, context)` but is actually keyed only by `(commit_id, context)`, and `commit_id` resolution in `StatusHandler#process` is scoped only by `sha`, not by the authenticated `repository.full_name` of the webhook payload:

```ruby
# app/models/shipit/webhooks/handlers/status_handler.rb:20-24
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

This contrasts with the base `Handler` class, which provides a repository-scoped accessor intended for this exact purpose:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
``` [2](#0-1) 

`StatusHandler` never calls `stacks`; it queries `Commit` globally by `sha` alone, so any commit row anywhere in the Shipit instance sharing that SHA is affected, regardless of which repository's signature validated the request.

`WebhooksController#verify_signature` only proves the payload was HMAC-signed for the `repository_owner`/organization named in the payload — it says nothing about which commits the payload is allowed to affect:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  head(422) unless verified
end
``` [3](#0-2) 

Once `commit.create_status_from_github!(params)` runs, it calls `add_status` → `statuses.replicate_from_github!(stack_id, github_status)`, which creates a `Status` row using the **victim's** `commit.stack_id` (via the `commit.statuses` association), not the attacker's stack:
```ruby
def create_status_from_github!(github_status)
  add_status do
    statuses.replicate_from_github!(stack_id, github_status)
  end
end
``` [4](#0-3) 

`Commit#statuses` is ordered `created_at: :desc`:
```ruby
has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
``` [5](#0-4) 

and `Status::Group#initialize` deduplicates by context keeping the **first** occurrence of that ordering:
```ruby
visible_statuses = reject_hidden(statuses.to_a.uniq(&:context))
...
@statuses = visible_statuses.sort_by!(&:context)
``` [6](#0-5) 

So a forged status created with a later `created_at` (or simply inserted after the real one, since default `created_at` is "now" unless the attacker supplies an older timestamp) for the identical `context` string wins over the genuine CI result and fully replaces it in `Commit#status` (`Status::Group.compact(self, statuses_and_check_runs)`, `app/models/shipit/commit.rb:304-306`). None of the described guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema on `StatusHandler`) check that the resolved `Commit`'s `stack.repository` matches the payload's `repository.full_name` — the schema only validates types/presence of `sha`, `state`, `context`, etc., not repository ownership.

Exploit flow:
1. Attacker recon's the victim's public repo's commit status page (unauthenticated) to learn the exact `context` string used by CI (e.g. `ci/circleci: build`) and identifies a target commit SHA tracked in the victim's Shipit stack.
2. Attacker imports/cherry-picks the identical commit object (same SHA) into a repository they own and register/connect that repo to the same Shipit instance (or already have one connected), so `Shipit.github(organization: attacker_owner)` will produce a valid, verifiable signature for their own webhook secret.
3. Attacker sends `POST /webhooks` with `X-Github-Event: status`, a body whose `repository.owner.login`/`repository.full_name` matches their own repo (so `verify_signature` passes), but `sha` equal to the victim's commit SHA and `context` equal to the victim's CI context, `state: success` (or any desired state).
4. `StatusHandler#process` matches the victim's `Commit` row purely by `sha`, ignoring that the payload's repository differs from the commit's actual stack/repository, and writes a new `Status` scoped to the victim's `stack_id`.
5. `Status::Group.compact`/`uniq(&:context)` now presents the forged status as canonical for that context on the victim's commit, potentially flipping `Commit#deployable?` and triggering `stack.schedule_merges` (`app/models/shipit/commit.rb:383`), enabling unauthorized progression toward deploy/merge for the victim's stack.

### Impact Explanation
An unprivileged, unauthenticated (to the victim) attacker can write forged status data into another tenant's `Stack`/`Commit`, spoofing or overriding CI results without any credential belonging to the victim repository, its maintainers, or Shipit operators. This is a payload for one repository (the attacker's) mutating another repository's commit/stack state — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Practical consequence: forged `success` status can make `Commit#deployable?` true, trigger `Hook.emit(:deployable_status, ...)`, and schedule merges (`stack.schedule_merges`), potentially leading to an unauthorized deploy/merge of code that never actually passed CI. This is repeatable against any commit SHA the attacker can reproduce byte-for-byte (i.e., any commit they can clone/import, which is trivial for any content in a public repo) and blast radius spans all Shipit-tracked stacks sharing that identical commit SHA, not limited to a single tenant.

### Likelihood Explanation
Preconditions: attacker must control (own) at least one repository connected to the same Shipit instance (a low bar — self-service repo registration is generally available to any GitHub org member who can install/authorize Shipit, or already-registered repos an attacker with push/fork access controls), and must be able to reproduce an identical commit object (SHA) as one tracked by the victim's stack — straightforward via `git fetch`/cherry-pick from any public repo, since content-addressed SHAs are trivially reproducible by importing the same tree/parents/commit metadata into another repository. No secrets, tokens, or victim-repo access are required. Cost is a single crafted HTTP POST to `/webhooks` with a validly signed payload for the attacker's own repo. This is fully repeatable and does not require any race condition or timing dependency.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the webhook-authenticated repository, consistent with the `Handler#stacks` pattern used by other handlers, e.g.:
```ruby
def process
  stacks.flat_map { |stack| stack.commits.where(sha: params.sha) }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
Additionally/alternatively, enforce a uniqueness/foreign-key constraint or validation ensuring a `Status`'s `stack_id` matches the `commit.stack_id` it's attached to only when the originating webhook's repository matches that stack's `Repository#full_name`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status handler does not let another repository forge a status for a foreign commit sharing the same sha" do
  victim_stack = shipit_stacks(:shipit) # tracks repository "shopify/shipit-engine"
  victim_commit = victim_stack.commits.create!(sha: 'deadbeef' * 5, ...)
  victim_commit.statuses.create!(
    stack: victim_stack, state: 'failure', context: 'ci/circleci: build', created_at: 1.hour.ago
  )
  assert_equal 'failure', victim_commit.reload.status.state

  # Attacker owns "attacker/evil-repo", connected to Shipit with its own valid webhook secret,
  # and has imported a commit object with the SAME sha as victim_commit (content-addressed SHA reproduction).
  forged_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/circleci: build', # learned via unauthenticated recon of victim's public status page
    'created_at' => Time.now.iso8601,
    'repository' => { 'full_name' => 'attacker/evil-repo', 'owner' => { 'login' => 'attacker' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(forged_payload)

  # BINDING VIOLATED: forged status from attacker's repo now overrides victim's real CI result
  assert_equal 'success', victim_commit.reload.status.state
end
```
This demonstrates the equality `commit.stack.repository.full_name == payload['repository']['full_name']` is never checked before `Status` creation, allowing the forged status (identical `context`, newer `created_at`) to fully replace the genuine failing status via `Status::Group.compact`'s `uniq(&:context)` ordering on `statuses` (`order(created_at: :desc)`). [7](#0-6) [8](#0-7)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-34)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
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

**File:** app/models/shipit/commit.rb (L12-12)
```ruby
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status/group.rb (L24-32)
```ruby
      def initialize(commit, statuses)
        @commit = commit

        visible_statuses = reject_hidden(statuses.to_a.uniq(&:context))
        missing_contexts = required_statuses - visible_statuses.map(&:context)
        visible_statuses += missing_contexts.map { |c| Status::Missing.new(commit, c) }

        @statuses = visible_statuses.sort_by!(&:context)
      end
```
