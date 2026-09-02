### Title
Cross-repository status webhook forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `sha`, with no scoping to the repository or stack that emitted the webhook, then writes a real `Status` row for every matching `Commit` across the entire installation. Because git commit SHAs are content-addressed and reproducible from public data (not secret), an attacker who owns any repository can reconstruct a victim commit's exact SHA, push it to their own repo, and set a `success` status there; a legitimately GitHub-signed webhook for the attacker's own repo will then flip `commit.deployable?` to `true` on the victim's stack.

### Finding Description
The broken binding: `commit.deployable?` for stack **S** must equal `S`'s own repository's actual CI result for that commit — i.e. `commit.deployable?(S) == ci_result(S.repository, sha)`. Instead, after this bug, `commit.deployable?(S) == ci_result(attacker_repository, sha)` whenever `sha` collides between the two.

Code path:
- `StatusHandler#process` executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no repository/stack filter [1](#0-0) .
- `create_status_from_github!` writes into `statuses` keyed by the matched commit's own `stack_id`, via `add_status`/`statuses.replicate_from_github!` [2](#0-1) .
- `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))`, purely a function of the `statuses`/`status` records on that commit [3](#0-2) .
- `Api::DeploysController#create` checks `stack.locked?` only when `!params.force`, and separately checks `commit.deployable?` only when `params.require_ci` is set — with `force: true, require_ci: true` the controller bypasses the lock gate entirely but still trusts `commit.deployable?` as the CI signal [4](#0-3) .

Root cause: `Commit.where(sha:)` treats `sha` as a globally unique key, but SHAs are only unique per git object graph, not per Shipit installation. Git SHA-1 is a hash over tree, parents, author, committer, and message — all of which are public/knowable for a public repository — so an attacker can reproduce the identical commit object (same SHA) in a repository they control (e.g., a fork containing the same commit, or by rebuilding the object with `git commit-tree` using identical metadata) with no secret material required.

Exploit flow:
1. Attacker identifies a commit SHA that exists in the victim's Shipit stack (trivial if the victim repo is public).
2. Attacker reproduces/pushes that exact commit (identical SHA) into a repository they own, where Shipit's GitHub App is installed.
3. Attacker uses the GitHub REST API (their own permissions on their own repo) to set a `success` commit status on that SHA.
4. GitHub sends a legitimately-signed `status` webhook for the attacker's own organization/repo — this passes `WebhooksController#verify_signature`, which validates only that the payload is authentically from GitHub for `repository_owner` in the payload, not that the `sha` belongs to that repository [5](#0-4) .
5. `StatusHandler#process` finds every `Commit` row (any repo, any stack) with that SHA — including the victim's — and calls `create_status_from_github!`, writing a fresh `success` status scoped to the victim's `stack_id`.
6. `commit.deployable?` on the victim's commit now returns `true`, even though the victim repository's own CI never ran.

Why existing guards don't stop this: `verify_signature` authenticates the *sender* (attacker's own org, legitimately), not the *sha's ownership*; `ExplicitParameters` only validates the shape of `sha`/`state`, not repository binding; no code cross-checks that the commit's `stack.repository` matches the payload's `repository.full_name` before writing the status.

### Impact Explanation
An unprivileged internet actor who merely owns any GitHub repository with Shipit's app installed can forge a CI "success" state for an arbitrary victim commit/stack that shares a SHA with a commit they control. This is a payload from one repository mutating another repository's `Commit`/`Status` records — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Downstream, automation or operators using the `force: true, require_ci: true` combination on `Api::DeploysController#create` [4](#0-3)  can be tricked into triggering an unauthorized deploy on a stack that is under an incident lock, believing CI is green when it is not — matching "an unauthorized deploy." This is repeatable against any victim stack/commit whose SHA the attacker can reproduce, and scales across all tenants sharing the Shipit installation since the query has zero repository scoping.

### Likelihood Explanation
Preconditions: victim repository commit content must be knowable (public repos, or any repo whose commit metadata leaks) so the attacker can reconstruct an identical SHA; attacker needs any repository with the Shipit GitHub App installed (their own fork/org) to legitimately emit a real, correctly-signed webhook. No Shipit secrets, sessions, or API tokens are required — only ordinary GitHub permissions on a repo the attacker owns. This is low-cost and repeatable at will against any commit whose SHA the attacker can reproduce.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and the analogous check-run handler) by repository, not just SHA — e.g. join through `stack.repository` and require `params.dig('repository','full_name')` (or owner/name) to match the commit's stack's repository before calling `create_status_from_github!`. Reject/ignore statuses whose payload repository doesn't match the commit's own stack repository.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook does not corrupt commits belonging to another repository's stack" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(lock_reason: "incident freeze")
  victim_commit = victim_stack.commits.create!(sha: "a" * 40, message: "victim commit")

  attacker_stack = shipit_stacks(:cyclimse) # different repository
  attacker_stack.commits.create!(sha: "a" * 40, message: "attacker-controlled duplicate sha")

  payload = { sha: "a" * 40, state: "success", context: "ci", repository: { full_name: attacker_stack.repository.full_name } }

  assert_equal false, victim_commit.reload.deployable?
  Shipit::Webhooks::Handlers::StatusHandler.new.call(payload) # simulate authenticated webhook for attacker's repo
  assert_equal true, victim_commit.reload.deployable?, "victim commit should not become deployable from an unrelated repo's status"
  assert victim_stack.reload.locked?
end
```
This demonstrates `commit.deployable?` flips to `true` for the victim's commit purely from a status emitted under the attacker's own (unrelated) repository, with the victim stack still locked — confirming the cross-tenant write.

### Citations

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
