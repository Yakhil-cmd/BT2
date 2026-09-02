## Title
Status webhook mutates arbitrary Commit rows without verifying the payload's repository matches the commit's stack repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

## Summary
`PushHandler`, `CheckSuiteHandler`, and every `PullRequest::*Handler` scope their side effects through `Handler#stacks`, which resolves `Repository.from_github_repo_name(payload['repository']['full_name'])` before touching any Stack/Commit. `StatusHandler#process`, by contrast, never reads `params.repository` at all and instead runs `Commit.where(sha: params.sha)` globally, so any valid signed status webhook can mutate a Commit belonging to a completely different repository/stack than the one named (or omitted) in the payload.

## Finding Description
The broken binding: `payload.repository.full_name` (or the org tied to the webhook signature) should equal the repository that owns the mutated `Commit`/`Stack`, i.e. `Repository.from_github_repo_name(payload.repository.full_name) == commit.stack.repository`. Every other handler enforces this — e.g. `Handler#stacks` does `Repository.from_github_repo_name(repository_name)&.stacks`, [1](#0-0)  and `PullRequest::OpenedHandler#repository` explicitly resolves the named repo before creating/looking up review stacks. [2](#0-1)  `PushHandler#process` also filters through `stacks` before syncing. [3](#0-2) 

`StatusHandler`'s param schema doesn't even require a `repository` key, and `process` queries `Commit` purely by `sha` with no stack/repository scoping: [4](#0-3) . `Commit#create_status_from_github!` then writes a real `Status` row tied to `commit.stack`, regardless of what repository the webhook named. [5](#0-4)  `Status.replicate_from_github!` persists state/description/context/target_url straight from attacker-controlled params. [6](#0-5) 

Signature verification (`WebhooksController#verify_signature`) only checks that the HMAC matches the secret configured for the organization named in `payload.repository.owner.login` (or `organization.login`) — it says nothing about which specific *repository* within that org the sha belongs to: [7](#0-6) . `GitHubApp#verify_webhook_signature` computes the HMAC purely from the raw body and the org-level `webhook_secret`, which is shared by every repository under that GitHub App installation: [8](#0-7) .

Exploit flow: an attacker who has legitimate write/collaborator access to *any* repository in the same GitHub organization as the victim's monitored stack (a common situation — Shipit's GitHub App is installed at the organization level and covers all repos in that org) can call GitHub's Status API on their own repository, e.g. `POST /repos/<attacker-org>/<attacker-repo>/statuses/<victim_sha>`, supplying the sha of a commit that actually belongs to the victim's monitored stack (visible via the victim stack's public commit history/Shipit UI) and `state: "success"`. GitHub genuinely signs and delivers this webhook using the org's shared `webhook_secret`, so `verify_signature` passes — there is no forgery of the signature required. The webhook's `repository.full_name` names the attacker's own repo, but `StatusHandler#process` never looks at it; it only looks at `sha`, finds the victim's `Commit` row across the whole database, and writes a forged success `Status` onto it. This can flip `commit.state`, trigger `enable_ci_on_stack`, `schedule_continuous_delivery`, and `ProcessMergeRequestsJob` on the victim's stack (confirmed by the state-machine test around `Commit#add_status`). [9](#0-8) 

None of the listed guards prevent this: `verify_signature` authenticates the organization/app, not the specific repository; `drop_unhandled_event`/`ExplicitParameters` schema only validate shape (`sha`, `state`, etc.), not repository identity — `repository` isn't even a declared/required param for this handler. [10](#0-9)  There is no model validation tying a `Status`/`Commit` write to the requesting repository.

## Impact Explanation
An attacker with only ordinary collaborator access to one repository in a shared GitHub organization can inject fabricated CI status ("success"/"failure"/"pending", with attacker-chosen `description`/`target_url`/`context`) onto a `Commit` belonging to a totally different stack/repository they don't administer. Since `Status` creation cascades into `enable_ci_on_stack`, `schedule_continuous_delivery`, and `ProcessMergeRequestsJob`, this can influence whether a commit is treated as deployable/mergeable on a stack the attacker has no legitimate authority over — this is exactly the "payload for one repository mutating another's stack/commit" and "unauthorized deploy/merge" category (Critical). It is fully repeatable for any known commit sha and any number of target stacks under the same GitHub App installation, giving a broad blast radius across every repository sharing that org-level app.

## Likelihood Explanation
Preconditions: (1) the attacker must have write access to commit-statuses on at least one repository under the same GitHub organization/App installation as the victim stack (very common — GitHub Apps are installed per-org, covering many repos with differing per-repo permissions), and (2) the attacker must know a target commit's sha (frequently public via the Shipit UI, GitHub commit history, or PR merge commits). No Shipit secrets, session, or API token are needed since the webhook is genuinely signed by GitHub. This is low-cost and repeatable — a single authenticated GitHub API call per forged status.

## Recommendation
In `StatusHandler`, require and validate the `repository` object like `PullRequest::OpenedHandler` does, resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, and scope the commit lookup to that repository's stacks/commits (e.g. `Commit.joins(:stack).where(sha: params.sha, stacks: { repository_id: repository.id })`) instead of the unscoped `Commit.where(sha: params.sha)`.

## Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status handler mutates commits belonging to a repository not named in the payload" do
  repo_a = shipit_repositories(:shipit) # attacker-controlled repo (per payload)
  stack_b = shipit_stacks(:cyclimse)    # victim stack, different repository
  victim_commit = stack_b.commits.create!(sha: 'f' * 40, ...)

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'repository' => { 'full_name' => repo_a.github_repo_name, 'owner' => { 'login' => repo_a.owner } }
  }

  assert_difference -> { victim_commit.statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end
  # payload named repo_a, but repo_b/stack_b's commit was mutated -> binding broken

  # Contrast: OpenedHandler enforces the binding and makes zero changes to stack_b
  opened_payload = { 'action' => 'opened', 'repository' => { 'full_name' => repo_a.github_repo_name }, ... }
  assert_no_difference -> { stack_b.commits.count } do
    Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.call(opened_payload)
  end
end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/models/commits_test.rb (L763-777)
```ruby
    test "#add_status schedule a MergeMergeRequests job if the commit transition to `pending` or `success`" do
      commit = shipit_commits(:second)
      github_status = OpenStruct.new(
        state: 'success',
        description: 'Cool',
        context: 'metrics/coveralls',
        created_at: 1.day.ago.to_formatted_s(:db)
      )

      assert_equal 'failure', commit.state
      assert_enqueued_with(job: ProcessMergeRequestsJob, args: [@commit.stack]) do
        commit.create_status_from_github!(github_status)
        assert_equal 'success', commit.state
      end
    end
```
