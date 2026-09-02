### Title
Cross-tenant Status forgery via global `Commit.where(sha:)` lookup with no repository/stack scoping - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `sha`, with no scoping to the repository named in the webhook payload, and writes a `Status` for every matching `Commit` row regardless of which stack/repository it belongs to. Since GitHub commit SHAs are content-addressed and reproducible from public metadata (tree, parents, author/committer, timestamps, message), an attacker controlling their own repository and its `webhook_secret` can emit a signed `status` webhook whose `sha` collides with a commit already tracked by a victim's Shipit stack, causing that victim commit to receive an attacker-controlled `success`/`failure` status.

### Finding Description
The broken binding: the intended invariant is `Status.sha == Commit.sha AND Status.repository == Commit.repository` (i.e., a status webhook from repo R may only affect commits belonging to R's stacks), but the code only enforces `Commit.sha == params.sha`.

Path: `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) dispatches the parsed payload to `Shipit::Webhooks.for_event('status')`, which is `[Handlers::StatusHandler]` (`app/models/shipit/webhooks.rb:19`). `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-38`) only checks the HMAC signature against `Shipit.github(organization: repository_owner)`'s `webhook_secret` — i.e., it authenticates *which GitHub org sent this request*, not *which commits the payload may touch*. Since the attacker owns that org/repo, this check passes with the attacker's own valid signature.

`StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries the global `Commit` table by `sha` alone — not scoped by `stack_id`/repository — despite `Handler` (the base class) already providing a `stacks`/`repository_name` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) that other handlers (e.g. `PushHandler`) use to scope by the payload's `repository.full_name`. `StatusHandler` does not use it at all. `Commit#create_status_from_github!` → `add_status` (`app/models/shipit/commit.rb:165-169`, `338-386`) creates a `Status` row scoped to `commit.stack_id`, and can trigger `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges` — i.e., it can influence the victim stack's merge-queue processing.

Because git commit SHAs are a deterministic hash of tree, parent(s), author/committer identity+timestamp, and message — all public for any public/open-source commit — an attacker can reconstruct byte-identical commit objects with `git commit-tree`/`git commit --date` in their own fork and obtain the identical `sha` as the victim's already-tracked commit. They then push that commit to a branch in their own repo, and their own CI (fully attacker-controlled) POSTs a `status` webhook (`state: success`, that `sha`) signed with their own repo's `webhook_secret`. `verify_signature` passes because the signature is valid for the attacker's own org. `StatusHandler#process` then matches the victim's `Commit` row by `sha` (since `Commit` is not repository-namespaced on `sha` in this query) and writes a `Status` onto it, potentially affecting the victim's `Stack`.

None of the existing guards prevent this: `verify_signature` authenticates the sender's org but not the target commit's ownership; `drop_unhandled_event` doesn't apply (status is handled); there is no `ExplicitParameters` validation tying `sha` to `repository.full_name`; and the `stacks`/`repository_name` scoping helper exists in the base `Handler` class but is simply not invoked by `StatusHandler`.

### Impact Explanation
A payload authenticated only for the attacker's own repository can create a `Status` row against a commit belonging to a victim's `Stack`, matching the "payload for one repository mutating another's stack/commit" Critical category. Concretely: forging `state: success` on a commit that is pending in the victim's merge queue can cause `add_status` to call `stack.schedule_merges` (`app/models/shipit/commit.rb:383`), influencing whether the victim's `MergeRequest`/CD pipeline proceeds, and can also fire `Hook.emit(:deployable_status, ...)` webhooks visible to the victim's integrations, giving false CI signal for a commit the attacker never controlled in the victim's repo. This is repeatable against any public commit already ingested into any Shipit-tracked stack, without needing any credential belonging to the victim.

### Likelihood Explanation
Preconditions are realistic and cheap: the attacker needs (1) a public GitHub repository they own with a webhook configured against the same Shipit instance (or their own Shipit instance if it happens to share the target database, which is out of scope for a typical multi-tenant deployment but trivially achievable in any deployment that federates multiple orgs' webhooks into one Shipit host — the common intended usage of this engine), and (2) the ability to reconstruct the exact commit object via `git commit-tree` with public metadata, which is deterministic and requires no guessing. No Shipit session, API token, or victim secret is needed. The only real constraint is that both the attacker's and victim's repositories' webhooks must be verified against orgs configured in the same Shipit instance (`Shipit.github(organization: repository_owner)`), which is the standard multi-org setup this engine is built for.

### Recommendation
Scope the `StatusHandler` lookup by the repository/stacks derived from the webhook payload, mirroring `PushHandler`'s use of the `stacks`/`repository_name` helper, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This enforces `Status.sha == Commit.sha AND Commit.stack ∈ stacks(payload.repository)`, closing the cross-tenant write.

### Proof of Concept
minitest plan (`test/models/webhooks/handlers/status_handler_test.rb`, illustrative — actual location may vary):
```ruby
test "status webhook for repo A does not mutate a commit belonging to repo B's stack" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  attacker_stack = create_stack_for("attacker/evil-repo")

  shared_sha = "deadbeef" * 5 # simulate a reproduced identical sha
  victim_commit = victim_stack.commits.create!(sha: shared_sha, author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now, message: "victim commit")

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'repository' => { 'full_name' => attacker_stack.repository.full_name, 'owner' => { 'login' => attacker_stack.repository.owner } }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```
Before the fix, this assertion fails: `StatusHandler.call` executes `Commit.where(sha: shared_sha)`, matches `victim_commit` regardless of `payload['repository']`, and `commit.statuses.count` increases by 1 — proving the cross-tenant write. After applying the recommended fix (scoping by `stacks`), the assertion passes. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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

**File:** app/models/shipit/commit.rb (L366-386)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
