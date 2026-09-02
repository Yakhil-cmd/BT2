### Title
Cross-repository CI status forgery via unscoped `sha` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, with no join or filter against the webhook's own `repository.full_name`, unlike every other handler in this engine which scopes lookups through `Handler#stacks` (which resolves `Repository.from_github_repo_name(repository_name)`). Any attacker who controls a repository/org with a valid `webhook_secret` can send a `status` webhook naming an arbitrary, unrelated `repository.full_name` but a `sha` copied from a public commit page of a different (victim) organization's repo, and the handler will mutate that victim commit's CI status.

### Finding Description
The broken binding: the code implicitly assumes `Commit#sha == params.sha` implies `commit.stack.repository == webhook.repository`, but this equality is never checked. `sha` values are 40-character hex strings with no secret content and are publicly visible on any GitHub commit page, so knowledge of a sha carries zero authorization signal.

Path:
1. `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) parses the raw JSON body and dispatches to `Shipit::Webhooks.for_event(event)` handlers.
2. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) resolves `Shipit.github(organization: repository_owner)` from the attacker-supplied `repository.owner.login` field, then verifies the HMAC signature using that org's `webhook_secret`. If the attacker owns any org with a real Shipit-configured `webhook_secret`, they can produce a valid signature for a payload whose `repository.full_name`/`repository.owner.login` point to *their own* org, while embedding an arbitrary `sha`.
3. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) then runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this query is global across the `commits` table, not scoped to the handler's `repository_name`/`stacks` (contrast with `PushHandler#process`, which does `stacks.not_archived.where(branch:)`, `app/models/shipit/webhooks/handlers/push_handler.rb:12-17`, and `Handler#stacks`, `app/models/shipit/webhooks/handlers/handler.rb:32-34`, both of which scope via `Repository.from_github_repo_name`).
4. `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) writes a new `Status` record and triggers `add_status`, which emits `commit_status`/`deployable_status` hooks and can schedule merges (`app/models/shipit/commit.rb:366-386`).

Attacker request: a raw `status` webhook, signed with the attacker's own org's `webhook_secret`, with `repository.full_name`/`repository.owner.login` set to the attacker's own repo, and `sha` set to a sha copied from Org A's public commit page, `state`, `context`, `description`, `target_url` chosen by the attacker.

Existing guards do not stop this: `verify_signature` only proves the sender owns *some* valid webhook secret for the org named in the payload — it says nothing about the `sha` field or which commits it may affect. The `ExplicitParameters` schema in `StatusHandler` only requires `sha`/`state` be strings; it performs no repository binding. `drop_unhandled_event` and `check_if_ping` are irrelevant here.

Compared to `RefreshStatusesJob` (`app/jobs/shipit/refresh_statuses_job.rb:7-14`), that job takes an internal `commit_id` or `stack_id` — values never attacker-controlled — so it is safe. The webhook path is the actual divergence: `Commit.where(sha:)` with no repository scope.

### Impact Explanation
An attacker who controls one repository (any repository with Shipit configured, satisfying `verify_signature`) can forge a `status` webhook that mutates the CI status of any other organization's commit that happens to share the same sha as one their attacker already knows publicly. This lets an attacker mark another tenant's commit as `success`, unblocking `deployable?`/`blocked?` checks (`app/models/shipit/commit.rb:227-237`) and potentially triggering `schedule_continuous_delivery` (`app/models/shipit/commit.rb:281-287`) and `stack.schedule_merges` (`app/models/shipit/commit.rb:383`), i.e., a payload from one repository mutating another repository's commit/stack state and potentially causing an unauthorized deploy — this matches the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Preconditions: attacker needs (a) control of any org/repo with a Shipit-configured `webhook_secret` (which they can set up themselves if Shipit allows arbitrary org onboarding, or otherwise any org they already have HMAC access to) so `verify_signature` passes, and (b) a known sha string from Org A's public GitHub commit history — trivially obtainable via any public GitHub URL, requiring no push access or shared git history with Org A. This is fully repeatable against any commit sha the attacker can observe, and costs a single HTTP POST per forgery attempt.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` does: resolve commits only through the handler's own `stacks` (derived from `Repository.from_github_repo_name(repository_name)`), e.g. `Commit.joins(:stack).merge(stacks).where(sha: params.sha)` or `stacks.flat_map { |s| s.commits.where(sha: params.sha) }`, so a `status` webhook can only mutate commits belonging to the repository named in its own signed payload.

### Proof of Concept
Minitest plan (no live GitHub, under `test/` conventions used elsewhere in this engine):
```ruby
test "status webhook cannot mutate a commit belonging to a different repository" do
  org_a_stack = shipit_stacks(:shipit) # existing fixture stack for "Org A" repo
  victim_commit = org_a_stack.commits.first
  # Baseline binding check performed BEFORE tracing: assert repository of payload != repository of victim_commit.stack
  attacker_repo_full_name = "attacker-org/unrelated-repo"
  assert_not_equal victim_commit.stack.repository.full_name, attacker_repo_full_name

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/forged',
    'repository' => { 'full_name' => attacker_repo_full_name, 'owner' => { 'login' => 'attacker-org' } }
  }

  assert_no_difference -> { victim_commit.statuses.count }, "status handler must not write status for a commit outside the webhook's own repository" do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
end
```
Given the current code, this assertion fails: `StatusHandler#process` matches `victim_commit` purely by `sha` and calls `create_status_from_github!`, incrementing `victim_commit.statuses.count` even though `payload['repository']['full_name']` never matches `victim_commit.stack.repository.full_name`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-34)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/jobs/shipit/refresh_statuses_job.rb (L7-14)
```ruby
    def perform(params)
      if params[:commit_id]
        Commit.find(params[:commit_id]).refresh_statuses!
      else
        stack = Stack.find(params[:stack_id])
        stack.commits.order(id: :desc).limit(30).each(&:refresh_statuses!)
      end
    end
```
