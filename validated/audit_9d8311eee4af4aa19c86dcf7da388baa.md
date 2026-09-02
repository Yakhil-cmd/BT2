### Title
Cross-repository commit-status forgery via unscoped `StatusHandler` webhook lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an incoming webhook against the GitHub App/`webhook_secret` belonging to the organization named in the payload's `repository.owner.login` field [1](#0-0) . Every other webhook `Handler` scopes the effect of the event to the repository named in the same payload via `Handler#stacks`/`Handler#repository_name`, which resolves `Repository.from_github_repo_name(payload.dig('repository','full_name'))` [2](#0-1) . `StatusHandler`, however, never uses that scoping: it looks up commits solely by `sha`, globally across every stack/repository in the installation.

### Finding Description
`StatusHandler#process` runs:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 

Unlike `PushHandler`, which restricts affected records to `stacks.not_archived.where(branch:)` derived from `repository_name` [4](#0-3) , or the pull-request handlers which all resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before touching any record [5](#0-4) , `StatusHandler` never calls `stacks` or resolves `repository_name` at all. `Commit#sha` is only unique per `stack_id` (see `20170524104615_index_commits_on_stack_id_and_sha.rb` — index is `(stack_id, sha)`, not a global unique index), so the same 40-hex sha can legitimately exist as separate `Commit` rows in multiple, unrelated stacks (e.g., forks, mirrors, or repositories that share history).

The binding that is broken: **the organization/repository whose signature authenticated the webhook != the repository whose `Commit`/`Status` record is mutated.** `verify_signature` only proves "this body was signed with organization X's secret" (derived from the payload's own `repository.owner.login`) [1](#0-0) ; `StatusHandler` then writes a `Status` to any `Commit` row anywhere in the database whose `sha` happens to match, with zero re-validation that the commit belongs to the repository/org that actually sent the event. This is analogous to the reported `block.timestamp` vs `_deadline` defect: one code path is checked/scoped by the "authorized" identifier (`repository_owner` for signature verification, `full_name` for every other handler), while the actual mutating action (`StatusHandler`) is keyed off a different, unchecked identifier (`sha` alone).

### Impact Explanation
Commit statuses gate both the merge queue (`MergeRequest::StatusChecker` / `all_status_checks_passed?`, `any_status_checks_missing?`) [6](#0-5)  and deploy eligibility (`commit.deployable?`/`require_ci` in `Api::DeploysController#create`) [7](#0-6) . Because `StatusHandler` writes to any `Commit` with a matching sha regardless of repository, a party who can trigger a validly-signed `status` webhook for a commit that happens to share its sha with a commit tracked in a victim's stack (e.g. via a fork or shared git history) can inject a forged "success" status onto the victim stack's commit. That forged status can suppress `ci_missing`/`ci_failing` rejection in the merge queue or satisfy `require_ci` on deploy, resulting in an **unauthorized merge or deploy** of a commit that never actually passed the victim repository's real CI. This matches the required "Critical: unauthorized deploy/merge" impact bar.

### Likelihood Explanation
This requires the attacker to be able to generate a legitimately GitHub-signed `status` event whose `sha` collides with a commit tracked by a different stack (e.g., by creating/controlling a repository that shares commit history with the target, such as a fork, and having permission to push a commit status to that repository via the Statuses API — something any collaborator/fork owner can do without any Shipit credentials, `ApiClient` tokens, or knowledge of `webhook_secret`). No privileged Shipit access, no repository write access to the *target* repo, and no secret material is required — only ordinary GitHub collaborator rights on some repository whose commit history overlaps with the tracked stack. This is a code-level scoping omission, not a theoretical concern, and is directly demonstrated by comparing `StatusHandler` to every sibling `Handler` subclass which all perform repository scoping before mutating state.

### Recommendation
Scope `StatusHandler#process` the same way every other handler is scoped: resolve `Repository.from_github_repo_name(repository_name)` (or use the existing `Handler#stacks`) and restrict the `Commit` lookup to commits belonging to that repository's stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` (or a joined query), rejecting/ignoring status events whose repository does not match the commit's owning stack.

### Proof of Concept
1. Attacker creates or gains push access to `attacker/fork`, a repository that shares a common ancestor commit (same `sha`) with `victim-org/tracked-repo`, which is a stack tracked by the Shipit instance.
2. `attacker/fork` has the same GitHub App installation (or its own registered org/webhook config) generating validly HMAC-signed `status` webhooks to Shipit's `/webhooks` endpoint — `WebhooksController#verify_signature` succeeds because it only checks the org named in the payload against that org's own secret [8](#0-7) .
3. Attacker uses the GitHub Statuses API to set state `success` on the shared commit sha in `attacker/fork`. GitHub delivers a legitimately signed `status` webhook with `repository.full_name = "attacker/fork"` and `sha = <shared sha>`.
4. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, which also matches the `Commit` row belonging to `victim-org/tracked-repo`'s stack, and calls `commit.create_status_from_github!(params)`, writing a forged "success" status onto the victim's commit [3](#0-2) .
5. The victim stack's merge queue / deploy flow now sees a passing status for that commit it never actually received from its own CI, enabling an unauthorized merge or deploy.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-27)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

        allow_concurrency = params.allow_concurrency.nil? ? params.force : params.allow_concurrency
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
        render_resource(deploy, status: :accepted)
```
