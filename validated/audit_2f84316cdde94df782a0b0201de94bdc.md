### Title
Cross-repository forged `status` webhook flips victim commit to `deployable?` and enqueues `ContinuousDeliveryJob` for a stack that never authenticated the request - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Webhooks::Handlers::StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, with no correlation to the `repository` in the webhook payload that was actually signature-verified. This lets a `status` event whose signature is valid for the *sender's* organization mutate a `Status`/`deployable?` state and trigger `Shipit::ContinuousDeliveryJob` for a completely different stack/organization whose commit happens to share the same SHA.

### Finding Description
The binding that must hold is: `stack_that_verified_signature == stack_whose_commit_is_mutated`, i.e. `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` must authorize exactly the `commit.stack` that gets acted upon. It does not.

- `WebhooksController#verify_signature` derives `repository_owner` purely from the incoming payload (`params.dig('repository','owner','login')`) and checks the signature against `Shipit.github(organization: repository_owner)` [1](#0-0) . This only proves "some webhook secret known for org X signed this," it never touches which `Stack`/`Commit` will end up being mutated.
- `StatusHandler#process` then looks up commits by `sha` **globally**, without any filter on `repository.full_name` or stack ownership: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [2](#0-1) .
- `Commit#create_status_from_github!` -> `add_status` -> `statuses.replicate_from_github!(stack_id, github_status)` persists the status against `commit.stack_id`, i.e. whichever stack owns that commit row, not the org that was authenticated [3](#0-2) , `Status.replicate_from_github!` [4](#0-3) .
- On create, `Status` fires `after_commit :schedule_continuous_delivery` -> `commit.schedule_continuous_delivery` [5](#0-4) , which checks `deployable? && stack.continuous_deployment? && stack.deployable?` and enqueues `ContinuousDeliveryJob.perform_later(stack)` for `commit.stack` — the victim's stack, unconditional on which org's secret validated the request [6](#0-5) .
- `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))` [7](#0-6) ; a forged `state: "success"` status flips a previously-`pending` commit to deployable when unlocked and unblocked.
- `ContinuousDeliveryJob#perform` only re-checks `continuous_deployment?`, schedule windows and occupancy on the *victim* stack before calling `stack.trigger_continuous_delivery` [8](#0-7) ; none of these checks re-validate which repository originated the webhook.

Exploit flow: attacker forks (or otherwise obtains) a repository whose commit history shares a SHA with a commit already tracked in a victim's Shipit stack (git SHAs are content-addressed and identical across clones/forks for unmodified commits). The attacker then causes a `status` event to be emitted for their own repository/org that passes `verify_webhook_signature` for `repository_owner` = attacker's org (this only requires a webhook whose secret matches whatever GitHub App/secret Shipit associates with that org — the existing per-organization signature check is oblivious to the fact that the `sha` in the payload may belong to an entirely unrelated stack). `StatusHandler#process` then applies that status to every `Commit` row across the whole database sharing that SHA, including the victim's, and the after-create callback chain unconditionally schedules `ContinuousDeliveryJob` for the victim's stack.

None of the existing guards prevent this: `verify_signature` authenticates the sender's org, not the target stack; `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape (`sha`, `state`, etc.), not repository ownership; there is no `force_github_authentication`/`require_permission!` on this webhook path since it is machine-to-machine; and `Commit.where(sha:)` has no `stack_id`/repository scoping (the DB schema even permits multiple stacks to hold rows with the same `sha`, unique only per `(sha, stack_id)`) [9](#0-8) .

### Impact Explanation
Impact: unauthorized state mutation (`Status` record + `deployable?` transition) and an unauthorized deploy trigger (`ContinuousDeliveryJob.perform_later(victim_stack)`) on a stack/organization the attacker never authenticated against — this is "a payload for one repository mutating another's stack, commit... or an unauthorized deploy", matching the Critical category. The blast radius spans any tenant/stack whose tracked commits happen to share a SHA with a repository the attacker controls (forks of public repos are the trivial case), and is repeatable per-SHA/per-victim-stack.

### Likelihood Explanation
Preconditions: (1) the victim stack has `continuous_deployment: true` and the targeted commit is currently `pending`/unblocked/unlocked; (2) the attacker can produce a genuinely GitHub-signed `status` webhook whose signature validates for whatever `Shipit.github(organization: repository_owner)` resolves to from the payload (feasible if the deployment shares a single GitHub App/secret across installations, or the attacker's own org is a legitimately configured Shipit organization); (3) a commit SHA collision across the attacker's and victim's repositories, which is trivially achievable via forking a public repository and reusing untouched history. Given these, the attacker cost is a single crafted/replayed webhook POST, fully repeatable against any stack/commit sharing a SHA with attacker-controlled history.

### Recommendation
`StatusHandler#process` (and analogously `CheckSuiteHandler`, `PushHandler`, etc.) must scope commit/stack lookups by the authenticated repository, not just `sha`. Concretely, filter `Commit.where(sha: params.sha)` to commits whose `stack.repository.full_name` (or owner/name pair) matches the webhook's own `repository.full_name`/`repository.owner.login` that was used in `verify_signature`, and reject/ignore any status update for commits belonging to stacks outside that repository.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test ":status from an unrelated organization can flip an unrelated stack's commit to deployable and enqueue CD" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(continuous_deployment: true)
  victim_commit = victim_stack.commits.last
  victim_commit.statuses.destroy_all
  victim_commit.statuses.create!(stack_id: victim_stack.id, state: 'pending', context: 'ci/travis')

  # Attacker's own repo/org shares this sha (e.g. via fork of victim's public history)
  attacker_repository_params = { repository: { owner: { login: 'attacker-org' } } }
  Shipit.github(organization: 'attacker-org').stubs(:verify_webhook_signature).returns(true)

  body = {
    sha: victim_commit.sha,
    state: 'success',
    context: 'ci/travis',
    branches: [{ name: victim_stack.branch }]
  }.merge(attacker_repository_params).to_json

  request.headers['X-Github-Event'] = 'status'

  assert_enqueued_with(job: ContinuousDeliveryJob, args: [victim_stack]) do
    post :create, body: body, as: :json
  end

  assert_predicate victim_commit.reload, :deployable?
end
```
This demonstrates: signature verification binds only to `attacker-org`, yet the resulting `ContinuousDeliveryJob` is enqueued with `victim_stack`, confirming the two named values in the binding diverge.

### Citations

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
    end
```

**File:** test/dummy/db/schema.rb (L63-87)
```ruby
  create_table "commits", force: :cascade do |t|
    t.integer "additions", limit: 4
    t.integer "author_id", limit: 4
    t.datetime "authored_at", null: false
    t.datetime "committed_at", null: false
    t.integer "committer_id", limit: 4
    t.datetime "created_at"
    t.integer "deletions", limit: 4
    t.boolean "detached", default: false, null: false
    t.integer "lock_author_id", limit: 4
    t.boolean "locked", default: false, null: false
    t.integer "merge_request_id"
    t.text "message", limit: 65535, null: false
    t.string "pull_request_head_sha", limit: 40
    t.integer "pull_request_number"
    t.string "pull_request_title", limit: 1024
    t.string "sha", limit: 40, null: false
    t.integer "stack_id", limit: 4, null: false
    t.datetime "updated_at"
    t.index ["author_id"], name: "index_commits_on_author_id"
    t.index ["committer_id"], name: "index_commits_on_committer_id"
    t.index ["created_at"], name: "index_commits_on_created_at"
    t.index ["sha", "stack_id"], name: "index_commits_on_sha_and_stack_id", unique: true
    t.index ["stack_id"], name: "index_commits_on_stack_id"
  end
```
