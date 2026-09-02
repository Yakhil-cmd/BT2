### Title
Cross-repository Status forgery via unscoped `Commit.where(sha:)` lookup persists and is served to all viewers of the victim stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits to attach a GitHub `status` webhook to using only the commit `sha`, with no constraint tying the lookup to the repository/organization whose webhook signature was verified. Any commit in the entire Shipit installation that happens to share a SHA with the attacker-controlled payload gets its `Status` overwritten, and that corrupted state is then served unconditionally to any viewer of the victim stack through `Commit#state`.

### Finding Description
The broken binding: `state persisted for victim_commit == state produced by CI runs the victim's own repository authorized` is violated because the actual binding enforced by the code is `state persisted for victim_commit == state provided by whoever's HMAC-signed webhook happens to reference a commit with the same sha`, with no additional check that the commit belongs to the stack/repository that the signature was verified for.

Code path:
1. `WebhooksController#verify_signature` derives `repository_owner` from the payload's `repository.owner.login` and validates the signature against `Shipit.github(organization: repository_owner)`'s configured `webhook_secret` [1](#0-0) [2](#0-1) . Note `GitHubApp#verify_webhook_signature` returns `true` outright when no `webhook_secret` is configured for that organization [3](#0-2) .
2. Once verified for *the attacker's own organization*, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) . This query is **global across the entire `commits` table** — it is not scoped by `stack_id`, `repository`, or any relation back to the verified `repository_owner`/organization.
3. `create_status_from_github!` calls `add_status` → `statuses.replicate_from_github!(stack_id, github_status)`, writing a new `Status` row tied to `commit.stack_id` (the victim's stack, not the attacker's) [5](#0-4) [6](#0-5) .
4. `Status` only validates `state` inclusion in `STATES`; it never validates that the status's `stack`/`commit` correspond to the webhook's originating repository [7](#0-6) .
5. `Commit#status` memoizes `Status::Group.compact` over all statuses/check runs and `Commit#state` delegates directly to it [8](#0-7) [9](#0-8) . Any subsequent read of the victim commit (stack commit list views, API) exposes this state with no re-validation of provenance.

Exploit flow: attacker owns (or has push/fork access to) a repository whose org is already onboarded into the target Shipit instance (or targets an org with no `webhook_secret` configured, which passes signature verification unconditionally) [10](#0-9) . Attacker obtains/replicates a commit with an identical SHA to a commit tracked in the victim's stack (trivial for public/forked repos, since SHA-1 is a deterministic function of tree/parent/commit metadata) and sends `POST /webhooks` with `X-Github-Event: status`, a signature valid for the attacker's own org, `repository.full_name` pointing at the attacker's repo, and `sha` equal to the victim's commit. `StatusHandler#process` matches by `sha` alone and writes the forged state to the victim's commit/stack.

None of the existing guards catch this: `verify_signature` only authenticates the *organization*, not that the payload's `sha` belongs to that organization's tracked commits; `drop_unhandled_event`/`check_if_ping` are irrelevant; the `ExplicitParameters` schema in `StatusHandler` only validates types, not repository ownership [11](#0-10) .

### Impact Explanation
A payload signed for one repository/organization can mutate the `Status`/commit `state` belonging to a completely different repository's stack — this is the "payload for one repository mutating another's stack, commit" Critical category explicitly called out in scope. The corrupted state (`commit.state`) is then rendered to every legitimate viewer of the victim stack via `Commit#state` delegation, persisting until manually corrected or overwritten by a legitimate CI event, and is repeatable against any stack/commit whose SHA the attacker can reproduce.

### Likelihood Explanation
Preconditions: (1) the attacker's organization must itself be a Shipit-tracked org whose webhook signature they can satisfy (either they legitimately control a repo webhooked into this instance, or the target org has no `webhook_secret` configured — a common/permitted misconfiguration per `GitHubApp#verify_webhook_signature`), and (2) the attacker must produce a commit SHA colliding with one in the victim's stack, which is straightforward for public repositories or forks since git SHAs are deterministic and reproducible from public commit metadata. No credentials, sessions, or secrets for the victim org are required. Cost is low (a single crafted, self-signed webhook POST); the attack is fully repeatable.

### Recommendation
Scope the `StatusHandler#process` commit lookup to the repository/organization that was authenticated via the webhook signature, e.g., join `Commit` through `stack: :repository` and filter by the payload's `repository.full_name`/`repository_owner`, mirroring the pattern already used in `PullRequest::EditedHandler#pull_request` which scopes by `repositories: { id: repository.id }` [12](#0-11) . Additionally, require `webhook_secret` to be present for every configured GitHub org (rejecting requests when unset) rather than defaulting to `true`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual, no live GitHub)
test "StatusHandler writes status to a commit belonging to a different stack/repo than the webhook signer" do
  victim_stack = shipit_stacks(:shipit) # e.g. repo "shopify/shipit-engine"
  victim_commit = victim_stack.commits.create!(sha: "deadbeef" * 5, message: "victim commit")
  victim_commit.statuses.create!(stack_id: victim_stack.id, state: "pending")

  attacker_org_repository_full_name = "attacker/unrelated-repo" # different org/repo entirely

  params = ExplicitParameters wrapped hash for StatusHandler:
    { sha: victim_commit.sha, state: "success", context: "forged/ci", repository: { full_name: attacker_org_repository_full_name } }

  Shipit::Webhooks::Handlers::StatusHandler.call(params) # simulates signature already verified for attacker's org

  victim_commit.reload
  assert_equal "success", victim_commit.state   # forged state now persisted on victim's commit
  assert_not_equal "pending", victim_commit.state # differs from the state the victim's own CI produced
end
```
This demonstrates the binding `state surfaced for victim_commit == state authorized by victim's own repository CI` is broken: the state written and subsequently read via `Commit#state` originates from an unrelated, attacker-signed payload for a different repository.

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L219-219)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status
```

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```

**File:** app/models/shipit/status.rb (L16-16)
```ruby
    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L49-61)
```ruby
          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end
```
