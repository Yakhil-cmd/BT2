### Title
`StatusHandler#process` writes a GitHub status to any `Commit` matching the attacker-supplied `sha` across all stacks, unlike the repo-scoped `refresh_statuses!` polling path - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Commit#refresh_statuses!` is safe because it fetches statuses via `stack.github_api.statuses(github_repo_name, sha, ...)`, i.e. it is parameterized by the victim stack's own `github_repo_name`, so it can never pull data for a foreign repository [1](#0-0) . `StatusHandler#process`, which is invoked from attacker-controlled webhook `params`, instead resolves the target via `Commit.where(sha: params.sha)` with no repository/stack scoping at all before calling the same `create_status_from_github!` sink [2](#0-1) .

### Finding Description
Binding: `refresh_statuses!`'s GitHub query target == `stack.github_repo_name` (the victim's own repository), and this binding cannot be violated by an attacker because `stack` is looked up server-side, not from external input [1](#0-0) .

For the webhook path, the equivalent binding does not exist: `StatusHandler#process` iterates `Commit.where(sha: params.sha)`, where `params.sha` comes straight from the attacker-supplied JSON payload's `sha` field, validated only for type (`String`) by the `ExplicitParameters` schema, not for repository ownership [3](#0-2) . Notably, the base `Handler` class exposes a `stacks` helper that scopes lookups to the reporting repository via `Repository.from_github_repo_name(repository_name)&.stacks`, and other handlers (e.g. push handling) use this scoping, but `StatusHandler#process` bypasses it entirely and queries `Commit` globally [4](#0-3) .

`WebhooksController#verify_signature` only checks that the HMAC signature matches the GitHub App/webhook secret registered for `repository_owner` (derived from `payload.dig('repository','owner','login')`) [5](#0-4) . It verifies that *some* payload came from a legitimate webhook of that owner's org - it does **not** verify that the `sha` inside the payload actually belongs to a commit of that repository. Since git SHA-1 identifiers are computed from tree/commit content, two different repositories (most commonly a fork and its upstream, both of which may be tracked as separate Shipit stacks/tenants) can and routinely do share identical commit SHAs for ancestor commits. An attacker who controls (or can trigger) a signed `status` webhook for their own repository/org can set `sha` to a value that also exists as a `Commit` row belonging to a victim's stack, causing `create_status_from_github!` -> `add_status` -> `Status.replicate_from_github!` to write a status record against the victim's stack/commit [6](#0-5) [7](#0-6) .

This confirms the asymmetry precisely as stated: pull-based `refresh_statuses!` is safely scoped by `stack.github_repo_name`; push-based `StatusHandler` ingestion has no equivalent scoping and is the sole unscoped path into the shared `create_status_from_github!` sink.

### Impact Explanation
A cross-tenant write: an attacker with a legitimately signed webhook for their own repository can create/mutate `Status` records - and, downstream, influence `commit.state`, CI-gating logic, `enable_ci_on_stack`, and `ProcessMergeRequestsJob` enqueuing - for a `Commit` belonging to a stack/repository they do not own, whenever a SHA collision (e.g., shared fork history) exists between their own repo and the victim's. This can affect deployability decisions and merge-queue processing on the victim's stack, which is a "payload for one repository mutating another's stack/commit" class of issue. The attack is repeatable for any shared-history SHA and is not limited to a single victim stack; any stack containing a `Commit` row with a matching SHA is affected.

### Likelihood Explanation
Preconditions: attacker needs a repository/org already integrated with Shipit's GitHub App/webhook (to pass `verify_signature`), and needs a `sha` value that also identifies a `Commit` row in a victim stack - realistically achievable via forks or repos sharing ancestor history, both tracked as separate Shipit stacks. No Shipit session, API token, or secret is required beyond what the attacker's own registered repository already legitimately has. This is feasible but conditioned on SHA overlap between tenants' commit histories, which is not universal but is a well-known, common scenario (forks, mirrors, template repos).

### Recommendation
Scope `StatusHandler#process` to only update commits belonging to the reporting repository, mirroring the `stacks` helper already used elsewhere in `Handler`, e.g. replace `Commit.where(sha: params.sha)` with a query restricted to `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent join through `Repository.from_github_repo_name(repository_name)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_cross_tenant_test.rb
test "StatusHandler writes a status to a commit belonging to a DIFFERENT repository's stack, given a shared sha" do
  victim_stack = shipit_stacks(:shipit)          # repository: shopify/shipit
  attacker_stack = shipit_stacks(:cyclimse)      # repository: theirorg/theirrepo
  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "ci",
    "branches" => [],
    "repository" => { "full_name" => attacker_stack.repository.full_name,
                       "owner" => { "login" => attacker_stack.repository.owner } }
  }

  assert_difference -> { victim_commit.statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.new(payload).process
  end
end

# Contrast: refresh_statuses! cannot be redirected to a foreign sha/repo
test "refresh_statuses! only queries the commit's own stack repository" do
  victim_stack = shipit_stacks(:shipit)
  commit = victim_stack.commits.first
  Shipit.github.api.expects(:statuses).with(victim_stack.github_repo_name, commit.sha, per_page: 100).returns([])
  commit.refresh_statuses!  # no parameter controls which repo is queried; always victim_stack.github_repo_name
end
```

### Citations

**File:** app/models/shipit/commit.rb (L156-163)
```ruby
    def refresh_statuses!
      github_statuses = stack.handle_github_redirections do
        stack.github_api.statuses(github_repo_name, sha, per_page: 100)
      end
      github_statuses.each do |status|
        create_status_from_github!(status)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
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
