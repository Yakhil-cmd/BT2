This confirms the single-config deployment (the common case, and the default in `secrets.yml`/`secrets.test.json` seen in this repo) uses exactly **one** `webhook_secret` for the whole Shipit install regardless of which repository or organization is named in the payload — `Shipit.github(organization: github_default_organization)` returns the same `GitHubApp` for every request when `github_default_organization` is `nil`. Even in the multi-org config, the secret is keyed only by `repository_owner` (organization), never by the individual repository. Either way, signature verification never binds the payload to the specific `repository.full_name` it claims to describe.

### Title
Cross-repository/cross-stack commit-status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Handler#stacks` is supposed to bind every mutation to `Repository.from_github_repo_name(payload['repository']['full_name'])`, exactly as `PushHandler#process` does. `StatusHandler#process` never calls `stacks`; it runs `Commit.where(sha: params.sha)` and mutates every matching row in the database, regardless of which repository or stack that commit actually belongs to.

### Finding Description
Broken binding, stated as an equality that should hold but doesn't:

Expected (enforced by `PushHandler`, `PullRequest::*Handler`): for every mutated stack `s`, `s.repository.full_name == payload.dig('repository', 'full_name')`, because `Handler#stacks` is `Repository.from_github_repo_name(repository_name)&.stacks`. [1](#0-0) [2](#0-1) 

Actual (`StatusHandler`): mutated commit `c` satisfies only `c.sha == params.sha`, with **no** constraint that `c.stack.repository.full_name == payload.dig('repository', 'full_name')`. [3](#0-2) 

Root cause: `Commit.where(sha: params.sha)` queries across every `Stack`/`Repository` in the whole database. The unique index on `commits` is `(sha, stack_id)`, not a global unique key on `sha` alone, so the same sha is expected to legitimately coexist under multiple, unrelated stacks (e.g. two environments of the same repo, or two different repositories that share commit ancestry via a fork). [4](#0-3) 

Why the guards don't stop this:
- `verify_signature` authenticates the *organization*/global GitHub App secret, not the specific repository named in the payload: `Shipit.github(organization: repository_owner)`, and `repository_owner` is read straight from the attacker-controlled `payload.dig('repository','owner','login')`. In the common single-config deployment (`github_default_organization` is `nil`), the same secret is used for literally every repository Shipit could ever be told about. [5](#0-4) [6](#0-5) 
- GitHub's own commit-status API only requires push access to *some* repository to set a status against an arbitrary sha string; the sha does not need to already exist as a commit in that repository. Any user who can push to (or has collaborator/write access to) a single tracked repository/fork can therefore emit a validly-signed `status` webhook naming that repository but carrying the sha of a commit that actually belongs to a different stack/repository.
- `ExplicitParameters` only validates the shape of `sha`/`state`/etc., not that the sha belongs to the named repository, so `StatusHandler#process` happily calls `commit.create_status_from_github!(params)` on whatever `Commit` rows match that sha anywhere in the instance.

Attacker's exact request: a normal `status` webhook payload, signed with the (attacker-obtainable or already-legitimate) GitHub App secret for their own repository/org, where `repository.full_name` is the attacker's own repo but `sha` is the sha of a commit that belongs to a target stack the attacker has no authorization over.

### Impact Explanation
The attacker can write an arbitrary `Status` record (`state`, `description`, `context`, `target_url`, `created_at`) onto a `Commit` belonging to a stack/repository they never authenticated. `Status` creation is not inert: it calls `commit.stack.enable_ci!`, feeds `commit.state`/`schedule_continuous_delivery`, and can enqueue `ProcessMergeRequestsJob`, i.e. it can influence continuous-deployment and auto-merge decisions for an unrelated stack. [7](#0-6) [8](#0-7) 

This matches the "payload for one repository mutating another's stack, commit... or an unauthorized deploy" Critical category: a webhook that is only authenticated (at best) for one repository is used to write into another repository's/stack's commit state, and can feed the continuous-delivery/merge pipeline. It is repeatable for any sha the attacker can discover (commit shas are visible/public on GitHub) and is not limited to one target.

### Likelihood Explanation
Preconditions: (1) the attacker needs some repository under Shipit's watch where they have push/collaborator rights (a fork they own, or any low-value repo in an org that shares the org-wide/global GitHub App webhook secret with the higher-value target); (2) the target stack must have a `Commit` row for the sha the attacker chooses — trivially true for shared history between a fork and its upstream, or between multiple environment stacks of the same repository. No `secret_key_base`, `api_clients_secret`, session, or GitHub private key is required — only ordinary push/collaborator access to a repository that already legitimately reaches Shipit's webhook endpoint. This is low-cost and repeatable against any stack whose commits the attacker can predict (public shas).

### Recommendation
Scope `StatusHandler#process` through `stacks`, mirroring `PushHandler`/`CheckSuiteHandler`: resolve commits only within `Repository.from_github_repo_name(repository_name)&.stacks`, e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))`, or explicitly filter `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` before calling `create_status_from_github!`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, new):
```ruby
test "PushHandler rejects cross-repo target" do
  target_repo = Repository.create!(owner: 'victim', name: 'app')
  target_stack = Stack.create!(repository: target_repo, ...)
  attacker_payload = { 'ref' => 'refs/heads/master', 'after' => 'deadbeef',
                        'repository' => { 'full_name' => 'attacker/app' } }
  Shipit::Webhooks::Handlers::PushHandler.call(attacker_payload)
  # target_stack never touched because Repository.from_github_repo_name('attacker/app') != target_repo
  assert_not_requested(...) # or assert target_stack.commits unchanged
end

test "StatusHandler accepts cross-repo target (vulnerability)" do
  target_repo = Repository.create!(owner: 'victim', name: 'app')
  target_stack = Stack.create!(repository: target_repo, ...)
  shared_sha = 'a' * 40
  commit = target_stack.commits.create!(sha: shared_sha, ...)

  attacker_payload = { 'sha' => shared_sha, 'state' => 'success',
                        'repository' => { 'full_name' => 'attacker/app' } }

  assert_difference('commit.statuses.count', 1) do
    Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)
  end
  # proves: repository.full_name in payload ("attacker/app") != commit.stack.repository.full_name ("victim/app")
  # yet the mutation happened -- binding Handler#stacks is supposed to enforce is absent here.
end
```
This demonstrates the exact asymmetry: identical cross-repo payload shape is rejected by `PushHandler` (via `stacks`) but accepted and mutates state via `StatusHandler` (bypassing `stacks`).

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** app/models/shipit/status.rb (L18-21)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
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
