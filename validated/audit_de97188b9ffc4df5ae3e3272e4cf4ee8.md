### Title
Cross-repository CI-enforcement flip via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits with a global, repository-unscoped query `Commit.where(sha: params.sha)`, unlike the base `Handler#stacks` helper which scopes lookups via `Repository.from_github_repo_name(repository_name)`. Because `verify_signature` in `WebhooksController` only proves the payload was signed by *some* org's webhook secret (the attacker's own org, resolved from `payload['repository']['owner']['login']`), and does not confine which commits/stacks the handler may touch, an attacker who owns any repo can send a `status` event whose `sha` matches a commit belonging to an unrelated victim stack, causing `Status.create!` → `after_create :enable_ci_on_stack` → `commit.stack.enable_ci!` to mutate the victim stack's CI-enforcement flag.

### Finding Description
The broken binding: the code implicitly assumes `commit.stack == stack_owned_by(repository_owner_of_signed_payload)`. In fact `Commit.where(sha: params.sha)` in `StatusHandler#process` [1](#0-0)  iterates over *every* commit row across *all* stacks/repositories sharing that sha string, with no filter on `repository_name`/`repository_owner`. This is unlike the generic `Handler#stacks` method, which correctly scopes by `Repository.from_github_repo_name(repository_name)` [2](#0-1) ; `StatusHandler` does not use that scoping at all.

`WebhooksController#verify_signature` only verifies that the payload was signed using the webhook secret for `repository_owner` derived from the payload itself [3](#0-2)  — it authenticates *that the attacker's own org sent this payload*, not that the `sha` field inside the payload belongs to a commit owned by that org. The `sha` is an attacker-controlled string requiring no proof of possession by the receiving code path.

For each matched `Commit`, `commit.create_status_from_github!(params)` creates a `Status` row tied to `commit.stack` (the commit's actual stack, from `belongs_to :stack` [4](#0-3) ). `Status#after_create :enable_ci_on_stack` then unconditionally calls `commit.stack.enable_ci!` [5](#0-4)  — flipping the CI-enforcement flag of whichever stack actually owns that commit row, regardless of which org's secret signed the webhook.

Exploit flow: attacker registers/controls a GitHub org+repo wired to Shipit (so `verify_signature` succeeds using the attacker's own webhook secret). Attacker (or any internet actor with knowledge of the target sha, which is often public in GitHub commit history/PR pages) sends `POST /webhooks` with `X-Github-Event: status`, a valid signature for their own org, and a JSON body containing `repository.full_name` for their own repo but `sha` copied from a real commit sha in the victim's public repository (git commit shas are content hashes, and commits are frequently shared/duplicated across forks, cherry-picks, or simply publicly known). Since `Commit.where(sha:)` is not scoped by repository, this matches the victim's `Commit` row directly, and `enable_ci!` runs against the victim stack.

Existing guards don't stop this: `drop_unhandled_event` only checks the event type is registered; `verify_signature` only authenticates the org named in the payload, not the sha's true owner; `ExplicitParameters` schema only validates types/presence of `sha`, `state`, etc., not sha ownership; there is no `stacks`/`Repository.from_github_repo_name` scoping applied inside `StatusHandler#process`.

### Impact Explanation
An unprivileged attacker who merely operates a Shipit-connected repo (or even just knows/guesses a victim commit sha, since only the signature needs to be valid for the attacker's own org) can toggle `ignore_ci`/CI-enforcement on an arbitrary victim stack — a payload for one repository mutating another repository's stack/commit state, matching the "Critical" impact category explicitly listed in the rules. Once CI enforcement is disabled on the victim stack, deploys/merges may proceed without required status checks, materially weakening the victim's deployment safety gate. This is repeatable against any stack whose commit sha becomes known to or guessable by the attacker, and the mutation persists until legitimate CI activity re-enables/re-disables the flag.

### Likelihood Explanation
Preconditions: the victim stack must not yet have received a status for that commit (`ignore_ci?` is true when no prior status exists), and the attacker needs a valid sha belonging to a commit already recorded in the victim stack's `Commit` table (readily available since GitHub commit history/PR pages are public, and Shipit records commits from pushes/PRs). The attacker's cost is low: register or use an existing repo connected to Shipit (attacker-owned, requiring no victim credentials), and send one signed `status` webhook — signing only requires the attacker's own webhook secret, which they legitimately possess for their own repo. No GitHub App private key, `api_clients_secret`, or victim secrets are needed. This is fully repeatable per-request against any sha the attacker can enumerate.

### Recommendation
Scope `StatusHandler#process` to the reporting repository, mirroring `Handler#stacks`: resolve the stack(s) via `Repository.from_github_repo_name(repository_name)` first, then restrict the `Commit.where(sha: params.sha)` lookup to `stacks.flat_map(&:commits)` (or `Commit.where(sha: params.sha, stack_id: stacks.map(&:id))`), so a commit can only receive a status from the webhook of the repository/org that actually owns its stack.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, no live GitHub)
test "status webhook for one repo cannot flip CI enforcement on an unrelated stack sharing a commit sha" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = victim_stack.commits.create!(sha: 'deadbeef' * 5, author: AnonymousUser.new)
  assert victim_stack.reload.ignore_ci? # binding LHS: victim_stack.ignore_ci? == true (no status yet)

  attacker_stack = shipit_stacks(:cyclimse) # different repository/org
  attacker_commit = attacker_stack.commits.create!(sha: victim_commit.sha, author: AnonymousUser.new)

  payload = {
    'repository' => { 'full_name' => attacker_stack.github_repo_name, 'owner' => { 'login' => attacker_stack.repository.owner } },
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/attacker'
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # RHS after: victim stack CI enforcement flipped despite payload only authenticating attacker's org
  assert_not victim_stack.reload.ignore_ci?, "victim stack's CI flag was mutated by an attacker-authenticated webhook for a different repository"
end
```
This demonstrates that the equality `commit.stack == stack_owned_by(payload.repository)` does not hold: `victim_commit.stack` (`victim_stack`) is mutated even though the webhook's authenticated repository is `attacker_stack`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
```

**File:** app/models/shipit/status.rb (L18-40)
```ruby
    after_create :enable_ci_on_stack
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
```
