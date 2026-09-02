### Title
`Shipit::Webhooks::Handlers::StatusHandler#process` matches commits by SHA alone, allowing one repository's CI status to be replicated onto another repository's `MergeRequest#head`, triggering an unauthorized merge - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, with no scoping to the repository that authenticated the webhook, unlike `PushHandler` which scopes work to `stacks.not_archived.where(branch:)` derived from the payload's repository. Any repository whose GitHub status webhooks reach this Shipit instance can therefore write a `Status` onto every `Commit` row in the database sharing that SHA, including a victim stack's `MergeRequest#head`, and get `ProcessMergeRequestsJob` to call `merge_request.merge!` (which invokes `stack.github_api.merge_pull_request`) on a repository the attacker never authenticated against.

### Finding Description
The broken binding is: `authenticated_repository (from webhook payload/signature) == repository whose Commit/MergeRequest is mutated`. Before the fix this should hold as `repository_owner (payload) == commit.stack.repository`, but `StatusHandler#process` never checks it: [1](#0-0) 

`WebhooksController#verify_signature` only authenticates that the payload was signed with the secret configured for `repository_owner` derived from the payload itself (`params.dig('repository','owner','login')`) — it proves the request truly came from that organization's GitHub App/webhook, not that the `sha` inside belongs to the stack that will ultimately be mutated: [2](#0-1) 

Once past that check, `StatusHandler#process` iterates `Commit.where(sha: params.sha)` — a global, cross-stack, cross-repository query — and calls `commit.create_status_from_github!(params)` for every match: [3](#0-2) 

`create_status_from_github!` writes the `Status` using the matched commit's *own* `stack_id` (the victim stack), not any stack derived from the webhook payload: [4](#0-3) [5](#0-4) 

Contrast this with `PushHandler#process`, which correctly scopes to stacks matching the payload's target `branch` (and, by extension, is not exploitable across unrelated repositories the same way): [6](#0-5) 

There is no DB-level uniqueness constraint preventing the same `sha` from existing on multiple stacks/commits — only a composite index on `(stack_id, sha)` — so SHA collisions across independent stacks are an accepted/expected condition in this schema, which is exactly what `StatusHandler` fails to account for.

Exploit flow:
1. Attacker forks/creates a repository they control and opens a PR whose head commit is a byte-for-byte copy of an existing commit (identical tree, parents, author/committer identity and timestamps, message) that is also the `head` of a victim `MergeRequest` on a `merge_queue_enabled` stack — the SHA is content-addressed and will be identical.
2. Attacker's own CI (or the attacker) reports a `success` status for that SHA on the attacker's repository. If the attacker's repository is served by the same Shipit instance/GitHub App installation (a realistic condition where one Shipit instance serves many repos/orgs under one org-wide app installation, or multi-org config as shown in `config/secrets.development.shopify.yml`), this produces a genuinely GitHub-signed webhook.
3. `WebhooksController#verify_signature` passes because the signature is valid for the attacker's own (real) organization.
4. `StatusHandler#process` matches `Commit.where(sha: X)`, which includes the victim's `MergeRequest#head` commit, and calls `commit.create_status_from_github!(params)`, writing a `Status(state: 'success')` under the **victim's** `stack_id`.
5. `Status#schedule_continuous_delivery` and the commit state transition enqueue `ProcessMergeRequestsJob(stack)` for the victim stack (see `commits_test.rb:763-777` demonstrating this enqueue behavior on transition to success).
6. `ProcessMergeRequestsJob#perform` calls `merge_request.all_status_checks_passed?` → `StatusChecker.new(head, head.statuses_and_check_runs, ...).success?`, which is now true, and calls `merge_request.merge!`, which invokes `stack.github_api.merge_pull_request` for the **victim's** repository.

None of `verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema (`requires :sha, String`), or `force_github_authentication` validate that the SHA belongs to the authenticated repository — they only validate the presence/type of `sha` and the authenticity of the org that sent the payload, not the ownership of the commit being mutated.

### Impact Explanation
This allows an unrelated, attacker-controlled repository to inject a fabricated `success`/`failure`/`pending` CI status onto **any** commit in the Shipit database that shares its SHA, across stack/tenant boundaries. When the target is a pending `MergeRequest#head` on a `merge_queue_enabled` stack, this results in `Shipit::MergeRequest#merge!` calling `stack.github_api.merge_pull_request` for a repository the attacker never authenticated against — an unauthorized GitHub merge performed with the victim stack's own GitHub App/installation credentials. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." It is repeatable against any stack/repository reachable from the same Shipit instance whenever a SHA collision (achievable via commit copying) can be engineered, and the blast radius spans every stack hosted by the instance, not just the attacker's own.

### Likelihood Explanation
Preconditions: the Shipit instance must serve more than one GitHub organization/repository (common for internally self-hosted deployments, and explicitly supported per `config/secrets.development.shopify.yml`'s multi-org config), and the victim stack must be `merge_queue_enabled` with a `pending` merge request. The attacker needs no Shipit session, API token, or team membership — only the ability to open a PR/fork under a repository whose CI events reach this Shipit instance, and to produce a commit with a specific SHA (achievable deterministically by copying an existing public commit's tree/metadata verbatim, since git SHAs are content-addressed). This is a realistic, low-cost, and repeatable attack against any monorepo/multi-tenant Shipit deployment.

### Recommendation
Scope `StatusHandler#process` (and any other SHA-keyed webhook handler) to the repository that authenticated the webhook, not merely by SHA. Options: derive the target stack(s) from `params.dig('repository', 'full_name')` (mirroring `PushHandler`'s `stacks` scoping) and intersect with `Commit.where(sha: params.sha)`, or add/require a `repository_id`/`github_repo_name` filter on the `Commit`/`Stack` association before calling `create_status_from_github!`, so a status can only be applied to commits belonging to stacks whose configured repository matches the payload's `repository.full_name`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual, no live GitHub)
test "status webhook for a SHA shared with another repository merges an unrelated stack's PR" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(merge_queue_enabled: true)
  victim_pr = shipit_merge_requests(:shipit_pending) # pending, merge_queue_enabled
  shared_sha = victim_pr.head.sha

  attacker_stack = shipit_stacks(:cyclimse) # unrelated repo/org
  attacker_stack.commits.create!(sha: shared_sha, author: shipit_users(:walrus),
                                  committer: shipit_users(:walrus),
                                  authored_at: Time.now, committed_at: Time.now, message: "copied")

  # Simulate a genuinely-signed status webhook coming from the attacker's org for `shared_sha`
  params = ExplicitParameters.build(
    Shipit::Webhooks::Handlers::StatusHandler,
    sha: shared_sha, state: 'success', context: 'ci/attacker', branches: []
  )

  assert_enqueued_with(job: Shipit::ProcessMergeRequestsJob, args: [victim_stack]) do
    Shipit::Webhooks::Handlers::StatusHandler.new.call(params)
  end

  Shipit.github.api.expects(:merge_pull_request).with(
    victim_stack.github_repo_name, victim_pr.number, anything, anything
  ).once

  Shipit::ProcessMergeRequestsJob.new.perform(victim_stack)

  assert_predicate victim_pr.reload, :merged?
end
```
This test demonstrates the equality `authenticated_repository (attacker's org) != commit.stack.repository (victim's stack)` yet `merge_pull_request` is still invoked for the victim's stack, proving the binding fails.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
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

**File:** app/models/shipit/status.rb (L23-34)
```ruby
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
