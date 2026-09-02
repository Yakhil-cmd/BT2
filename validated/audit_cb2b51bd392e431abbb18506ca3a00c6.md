### Title
`StatusHandler#process` resolves commits by SHA with no repository scoping, letting any webhook-signature-valid org write forged Status rows into another tenant's stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` [1](#0-0)  instead of scoping through `stacks` (the `Repository.from_github_repo_name(repository_name).stacks` helper every other handler like `PushHandler` uses) [2](#0-1) [3](#0-2) . Any org whose GitHub webhook signature validates (i.e. an org that owns its own Shipit-tracked repo) can send a `status` event referencing a SHA that also exists as a `Commit` row in a completely different, unrelated stack, and `commit.create_status_from_github!` will write a `Status` into that victim stack using `commit.stack_id` [4](#0-3) [5](#0-4) .

### Finding Description
The intended binding is: `Status#stack_id == <stack of the repository that produced the webhook>`. Tracing the code shows this is violated: `Status#stack_id == <stack of whichever Commit row(s) happen to match params.sha>`, independent of which repository/org sent the event.

- `WebhooksController#verify_signature` only proves the payload was signed by `repository_owner`'s (the sender's) GitHub App secret [6](#0-5) . It never checks that the `sha` in the payload belongs to a commit that actually lives in that same sender's repository/stack.
- `StatusHandler#process` then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [1](#0-0) , with no filtering by `repository_name`/`stacks`, unlike `PushHandler#process`, which explicitly scopes through `stacks.not_archived.where(branch:)` [3](#0-2) .
- `Commit#create_status_from_github!` writes using the target `Commit`'s own `stack_id`: `statuses.replicate_from_github!(stack_id, github_status)` [4](#0-3) , and `Status.replicate_from_github!` does `find_or_create_by!(stack_id:, state:, ...)` [5](#0-4) , so the row is idempotent per `(stack_id, state, description, ...)` but is still bound to whichever commit matched by sha - not to the sending repository.

Exploit flow: an attacker who owns/administers a repository that Shipit tracks (their own org, with its own valid webhook secret) obtains a git commit object with a SHA identical to one already present as a `Commit` row in a victim's Shipit stack (trivial if the victim repo is public/forked, since git commit hashes are content-addressed and identical across forks that share history). The attacker pushes/fetches that SHA into their own repo and triggers (or directly POSTs, since `X-Hub-Signature` is only checked against their own org's secret, which they can compute if they control a repo GitHub sends real signed webhooks for) a `status` webhook with `state: "success"` for that sha. `WebhooksController#verify_signature` passes because the signature is valid for the attacker's own org. `StatusHandler#process` then finds the victim's `Commit` (matching only by sha, globally) and calls `create_status_from_github!`, creating a `Status` row in the victim's stack. This can be repeated any time the victim's real CI later posts a genuine `failure` status, re-asserting a colliding `success` row that participates in `Commit#state`'s hierarchy alongside the legitimate `failure` row, muddying trust in that commit's CI state for the victim's stack.

None of the existing guards prevent this: `verify_signature`/`GitHubApp#verify_webhook_signature` only authenticates the sender's org, not the sha-to-repository binding; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema on `StatusHandler` only validates presence/type of `sha`/`state`/etc., not repository ownership [7](#0-6) ; and `StatusHandler` never calls the `stacks`/`repository_name` helper that other handlers use to scope by repository [2](#0-1) .

### Impact Explanation
A signed webhook from Tenant A's own repository can write a `Status` row into Tenant B's stack for any `Commit` row whose `sha` happens to collide (trivially achievable via shared git history / forks). This directly matches "a payload for one repository mutating another's stack, commit ... " - Critical severity: it lets an unprivileged-but-webhook-capable org (one that owns any Shipit-tracked repo) inject persistent, repeatable CI status records into an unrelated tenant's commit, corrupting `Commit#state`'s hierarchy-based trust model (used to decide deployability) and providing no column to distinguish provenance between the two `Status` rows.

### Likelihood Explanation
Preconditions: the attacker must control (own/administer) at least one repository that Shipit already tracks as a stack with a valid, working GitHub webhook/signature setup - this is the normal state for any legitimate onboarded repo in a multi-tenant Shipit deployment, not a privileged Shipit-operator action. The attacker does not need any Shipit secret, session, or API token, nor GitHub App private key for the victim's org - only for their own repo, which they legitimately possess. Obtaining a SHA collision with a victim commit is trivial when repos share history (forks) and only moderately harder otherwise (attacker can craft a commit with fully attacker-chosen content, but must match a specific pre-existing SHA the victim already has - straightforward if targeting a fork of a public/shared upstream). This is repeatable indefinitely against any commit sha value already present in `Commit`.

### Recommendation
Scope `StatusHandler#process` (and any other handler resolving by sha) through the `stacks` helper the same way `PushHandler` does - resolve `Repository.from_github_repo_name(payload.dig('repository','full_name'))` first, then only update `Commit` rows belonging to that repository's `stacks`, e.g. `stacks.flat_map(&:commits).select { |c| c.sha == params.sha }` or equivalent scoped query (`Commit.where(sha: params.sha, stack_id: stacks.select(:id))`), rejecting/ignoring the event if the sha does not belong to that repository's own commits.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
test "status webhook is not applied cross-repository when sha collides across stacks" do
  victim_stack = shipit_stacks(:shipit)
  attacker_stack = shipit_stacks(:cyclimse) # unrelated stack/repo

  colliding_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: colliding_sha, author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now, message: "victim commit")

  # Forged payload: signed as if it came from attacker_stack's repository, but sha matches victim_commit
  payload = {
    'sha' => colliding_sha,
    'state' => 'success',
    'context' => 'ci/forged',
    'repository' => { 'full_name' => attacker_stack.github_repo_name, 'owner' => { 'login' => attacker_stack.github_repo_owner } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  victim_commit.reload
  # Binding under test: status.stack_id should equal the sha's OWN repository's stack (attacker_stack),
  # not victim_stack, since the event was signed/sent by attacker_stack's org.
  forged_status = victim_commit.statuses.find_by(context: 'ci/forged')

  refute forged_status, "no Status should be written into victim_stack from an attacker-signed webhook for a different repository"
  # Currently this assertion FAILS: forged_status.stack_id == victim_stack.id, proving the cross-tenant write.
end
```

### Citations

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
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
