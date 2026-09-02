### Title
Cross-repository status forgery flips `Commit#deployable?` via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits to update purely by `sha`, without scoping to the repository that sent the webhook, unlike every other handler which scopes work through the base `Handler#stacks` method (which resolves `Repository.from_github_repo_name(repository_name)`). Because the `commits` table's uniqueness index is `(stack_id, sha)` and not `sha` alone, a status webhook legitimately signed for one repository/organization can flip `success?`/`deployable?` on a commit row belonging to an entirely different stack that happens to share the same sha (e.g. shared git ancestry via a fork). A legitimate operator's `require_ci: true` deploy request against that victim stack will then read the poisoned `deployable?` and bypass the CI gate.

### Finding Description
The equality the system is supposed to enforce is: `commit.stack.repository.full_name == payload.dig('repository', 'full_name')` for every `Status` row created from a webhook. The base class already implements this correctly for other handlers: [1](#0-0) 

`StatusHandler#process`, however, bypasses this entirely and queries the global `Commit` table by `sha` only: [2](#0-1) 

`Signature` verification (`WebhooksController#verify_signature`) only proves the payload came from *some* organization/app Shipit knows about (resolved via `repository_owner`), it does not prove the payload's repository matches the repository of every `Commit` row that shares the posted `sha`: [3](#0-2) 

Root cause: `sha` is only unique per stack (`index_commits_on_stack_id_and_sha`), not globally, so the same sha can legitimately exist as separate `Commit` rows across unrelated stacks/repositories (e.g. shared history between a repository and its fork, or two Shipit-tracked repos that share ancestor commits). `StatusHandler#process` updates the status of *every* `Commit` row matching that sha, regardless of which repository's webhook produced it.

`Commit#deployable?` reads exactly this poisoned state: [4](#0-3) 

And `Api::DeploysController#create`'s `require_ci` gate trusts it unconditionally: [5](#0-4) 

Exploit flow: attacker owns/controls a repository that is (or can become) a Shipit-tracked stack, sharing commit history/sha with the victim's stack (e.g. a fork sharing an ancestor commit, or two org repos with the same commit graft). Attacker triggers a genuine GitHub `status` event on their own repository for that shared sha with `state: success` (e.g. by running any CI check on their fork's PR referencing the shared commit). GitHub signs and delivers this webhook; `verify_signature` passes because it is validated against the attacker's own organization's app credentials, not against the victim's repository. `StatusHandler#process` then finds and updates **all** `Commit` rows with that sha, including the one belonging to the victim's stack, flipping its `success?`/`deployable?` to true. A legitimate operator later calls `Api::DeploysController#create` with `require_ci: true`; `commit.deployable?` is now `true`, `param_error!` is skipped, and `stack.trigger_deploy` runs — an unauthorized deploy of code that never actually passed CI on the victim's own CI system.

None of the existing guards catch this: `verify_signature` authenticates the sender's own organization only, `drop_unhandled_event`/`ExplicitParameters` validate shape not scope, and `Handler#stacks` (the correct scoping mechanism) is simply never invoked by `StatusHandler`.

### Impact Explanation
A payload legitimately originating from repository A (attacker-controlled) mutates commit/status state belonging to stack/repository B (victim), directly satisfying "a payload for one repository mutating another's stack, commit" and enabling "an unauthorized deploy... enabled entirely by cross-tenant status forgery" — Critical. The blast radius is any pair of Shipit-tracked repositories/stacks that share commit sha values (forks, mirrors, shared submodule/vendor commits, or repos with common history), and is repeatable for every shared commit and every subsequent `require_ci` deploy attempt against the victim stack.

### Likelihood Explanation
Preconditions: (1) the attacker must control a repository already tracked by Shipit as a stack (or capable of being installed with a valid webhook/app), (2) that repository must share at least one commit sha with the victim stack's commit history (realistic for forks or repos derived from a common upstream), (3) the victim stack must have a legitimate operator later issuing a `require_ci: true` deploy on the poisoned commit. No secrets, sessions, or `ApiClient` tokens are required from the attacker — only the ability to emit a normal, correctly-signed GitHub status webhook from a repository they legitimately own. This is a config/architecture gap rather than a rare edge case, since Shipit explicitly supports multiple stacks/repos and sha collisions across shared history are a known git phenomenon.

### Recommendation
Scope `StatusHandler#process` the same way every other handler is scoped: resolve the webhook's `stacks` via `Repository.from_github_repo_name(repository_name)` (as the base `Handler#stacks` method already does) and restrict the `Commit.where(sha: params.sha)` lookup to `commits` belonging to those stacks only, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`.

### Proof of Concept
Minitest plan (model/controller level, no live GitHub):
1. Create two stacks `victim_stack` (repo `victim/repo`) and `attacker_stack` (repo `attacker/repo`), each with a `Commit` row sharing the same `sha` value (simulating shared ancestry), with the victim commit having no passing statuses (`refute victim_commit.deployable?`).
2. Simulate the attacker's webhook: instantiate `Shipit::Webhooks::Handlers::StatusHandler.call(sha: shared_sha, state: 'success', context: 'ci/attacker', repository: { full_name: 'attacker/repo' })` (bypassing controller-level signature check, as it is orthogonal to the scoping bug).
3. Reload `victim_commit` and assert `assert victim_commit.deployable?` — demonstrating the cross-repo poisoning (binding broken: attacker's repo != victim commit's stack repo, yet state changed).
4. Call `Shipit::Api::DeploysController#create` (or `stack.trigger_deploy`/direct controller test) for `victim_stack` with `sha: victim_commit.sha, require_ci: true` as an authenticated legitimate operator/API client scoped to `victim_stack`.
5. Assert no `param_error!` is raised (response is `:accepted`, not `:unprocessable_entity`) and `assert_difference('Deploy.count', 1)` — proving an unauthorized deploy proceeded despite the victim's real CI never passing.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
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
