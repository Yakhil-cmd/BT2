### Title
Cross-Repository Commit Status Forgery via Unscoped `StatusHandler` Webhook - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a request using the organization derived from the *payload itself* (`repository.owner.login` / `organization.login`), which is correct and matches the request being processed. [1](#0-0)  However, once a request is authenticated for a given organization/repository, individual event handlers are expected to further scope their side effects to that same repository via the `Handler#stacks` helper, which resolves `Repository.from_github_repo_name(repository_name)` from the same payload. [2](#0-1)  `PushHandler` and `CheckSuiteHandler` correctly do this. [3](#0-2) [4](#0-3)  `StatusHandler`, however, never calls `stacks`; it looks up commits globally by SHA across the entire installation and writes a status to every match: [5](#0-4) 

### Finding Description
The binding that should hold is: *organization that authenticated the webhook == repository whose data is written*. `verify_signature` authenticates the request only for the organization named in the payload's `repository`/`organization` field. [6](#0-5)  That authentication says nothing about which repository's *commits* may be mutated — that scoping must happen in the handler.

`StatusHandler#process` ignores the payload's `repository` field entirely and instead does a system-wide lookup:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

`Commit` records are global across the whole Shipit installation (all stacks/repositories share the `commits` table), and `sha` is not unique to a repository. [7](#0-6)  Because Git commit SHA-1 hashes are content-addressed, two independent repositories (e.g., an upstream repo and any fork of it) share identical SHAs for identical commit history. Any GitHub organization/App installation that is a legitimate, distinct tenant in this Shipit instance — including one installed by an attacker on their own fork of a tracked repository — can send a genuinely-signed `status` webhook (signed with *that org's own* `webhook_secret`, satisfying `verify_signature` for that org) referencing a SHA that is shared with (or identical to) a commit belonging to a **different** stack/organization tracked by the same Shipit instance. `StatusHandler` will then create/replicate a CI status onto that unrelated stack's commit, because it never checks that the commit's `stack.repository` matches the authenticated `repository_owner`/`repository_name` from the payload.

This is a direct violation of the required binding: the organization whose secret validated the request is not the same as the repository whose `Commit`/`Status` row gets written.

### Impact Explanation
Commit statuses (`Status`/`create_status_from_github!`) directly feed `Stack#required_statuses`, `blocking_statuses`, and `MergeRequest::StatusChecker`/`all_status_checks_passed?`, which gate whether a `MergeRequest` is auto-merged by `ProcessMergeRequestsJob` and whether a commit is `deployable?`. [8](#0-7) [9](#0-8)  By forging a `success` status for a shared/foreign commit SHA, an attacker who controls a completely unrelated, independently-onboarded repository can flip required CI checks to green on someone else's stack, enabling an **unauthorized merge** via the merge queue or unblocking an **unauthorized deploy**. This satisfies the High/Critical impact bar ("an unauthorized deploy, rollback or merge").

### Likelihood Explanation
The prerequisite is only that the attacker controls (or forks/onboards) any single repository that is independently connected to the same multi-tenant Shipit instance — no privileged access to the victim's repository, Shipit session, or `ApiClient` token is required, and the attacker never needs to know any other organization's `webhook_secret` since they use their own valid, GitHub-issued signature. The only non-trivial constraint is obtaining a SHA collision with a target commit, which is trivially satisfied for shared ancestor commits between a public repository and any fork of it (identical byte-for-byte git objects hash identically). This is a realistic, low-effort attack path for any Shipit deployment that tracks multiple independent GitHub organizations/repositories (a documented, supported configuration). [10](#0-9) 

### Recommendation
Scope `StatusHandler#process` to the repository named in the payload, mirroring `PushHandler`/`CheckSuiteHandler`, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
using the existing `Handler#stacks` (which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) so that a status can only ever be written to commits belonging to the same repository that authenticated the webhook.

### Proof of Concept
1. Deploy Shipit configured for multiple GitHub organizations, each with its own `webhook_secret` (a documented supported setup). [10](#0-9) 
2. Victim org "upstream" has a public repo tracked as a Shipit stack; commit `abc123...` on its `main` branch requires CI status `ci/required` to be `success` before merge/deploy.
3. Attacker forks "upstream" into their own GitHub account/org "attacker-org" (identical git history, so the fork also contains commit `abc123...`), and installs their own Shipit GitHub App / gets "attacker-org" onboarded as an independent tenant of the same Shipit instance, receiving their own legitimate `webhook_secret`.
4. Attacker uses the GitHub Status API (which they can legitimately call for their own fork) to set a status of `success` for `context: "ci/required"` on commit `abc123...` in `attacker-org/upstream-fork`.
5. GitHub sends a `status` webhook to Shipit, correctly signed with `attacker-org`'s `webhook_secret`; `verify_signature` passes because it only checks that the signature matches the org named in the payload (`attacker-org`). [11](#0-10) 
6. `StatusHandler#process` runs `Commit.where(sha: "abc123...")` with no repository filter and finds the **victim's** `Commit` row for the same SHA, creating a `success` status on it. [5](#0-4) 
7. The victim's `MergeRequest#all_status_checks_passed?` now returns true using the forged status, and `ProcessMergeRequestsJob` merges/deploys code that never actually passed the victim's real CI. [12](#0-11)

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/commit.rb (L11-13)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :check_runs, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
```

**File:** app/models/shipit/merge_request.rb (L164-191)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-30)
```ruby
      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
```
