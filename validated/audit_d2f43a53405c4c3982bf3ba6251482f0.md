### Title
Cross-repository status forgery satisfies `require_ci` gate in `Shipit::Api::DeploysController#create` - (File: app/controllers/shipit/api/deploys_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` updates commit status by SHA only, with no scoping to the repository that produced the (correctly signed) webhook. This lets any repository whose GitHub status webhooks are accepted by Shipit mark a same-SHA commit in an unrelated stack as "success", which is later trusted verbatim by `DeploysController#create`'s `require_ci` check to authorize a deploy.

### Finding Description
The claimed binding is: `repository_that_signed_the_webhook.full_name == commit.stack.repository.full_name`. Tracing the code shows this equality is never enforced.

`WebhooksController#verify_signature` only checks that the payload's signature is valid for the *organization named in the payload* via `Shipit.github(organization: repository_owner)` [1](#0-0) . This confirms the webhook genuinely originated from GitHub for that org/repo, but it says nothing about which Shipit-tracked commit records the payload should touch.

`StatusHandler#process` then applies the status to every commit in the database matching the SHA, irrespective of repository: [2](#0-1) 
There is no `stack_id`, `repository_id`, or `repository_owner`/`repository_name` filter — only `Commit.where(sha: params.sha)`. If an attacker owns/controls a repository (their own public fork or repo with an identical commit object, hence identical SHA, to a commit tracked in a victim's Shipit stack) and that repository has the Shipit GitHub App/webhook installed, they can cause GitHub to emit a genuinely-signed `status` event for their own repo with `state: success` for that shared SHA. `verify_signature` passes because the signature is authentic for the attacker's org. `StatusHandler#process` then writes that state onto the victim's commit row as well, because the lookup is by SHA alone.

Downstream, `Shipit::Api::DeploysController#create` does: [3](#0-2) 
`commit.deployable?` reads exactly the state field that was polluted by the cross-tenant write, with no re-validation of which repository actually produced that state. `require_permission :deploy, :stack` only checks that the caller (an existing low-trust API client for the *victim's* stack) is authorized to deploy that stack — it does not, and cannot, check the provenance of the commit's CI state, because that provenance was already lost in `StatusHandler`.

None of the listed guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters`, `require_permission!`, model validations) touch this gap: they all operate correctly for the repository named in the *webhook* payload, but the vulnerable write in `StatusHandler#process` never checks that named repository against the commit's actual owning stack/repository before mutating it.

### Impact Explanation
An attacker who can get any signed webhook accepted for a repository they control (their own fork/repo with the Shipit app installed) can flip `deployable?` to true for a same-SHA commit belonging to a completely different, victim-owned stack. Combined with an existing legitimate but low-trust API client for that victim stack, this allows `params.require_ci && !commit.deployable?` to pass and `stack.trigger_deploy` to fire — an unauthorized deploy triggered using CI state that was never produced by the victim's own CI/repository. This is a cross-tenant data write leading to an unauthorized deploy, matching the "Critical" category (payload for one repository mutating another's commit/stack state, enabling an unauthorized deploy).

### Likelihood Explanation
Preconditions: (1) the victim stack must gate deploys behind `require_ci`, (2) the attacker needs a repository under their control that shares a commit SHA with a commit tracked by the victim's Shipit stack (trivial via forking public repos, since git SHAs are content-addressed and identical across forks), (3) the attacker's repository must have the same GitHub App/webhook configuration Shipit trusts (`Shipit.github(organization: repository_owner)` must resolve for that org), (4) a caller with at least deploy permission on the victim's stack must invoke the API — this could be a legitimate but compromised or low-trust integration, not the raw unauthenticated attacker. This makes the deploy-trigger step itself require an authenticated caller, but the state-pollution step (`StatusHandler`) requires no privilege beyond controlling one's own repository — fully repeatable against any commit SHA shared across repos.

### Recommendation
Scope `StatusHandler#process` (and any other handler that resolves `Commit` purely by `sha`) to the repository named in the webhook payload, e.g. join through `Stack`/`Repository` and filter `Commit.joins(stack: :repository).where(sha: params.sha, repositories: { owner: repository_owner, name: repository_name })` before calling `create_status_from_github!`. Add a regression test asserting that a status webhook for repo A never mutates a commit belonging to a stack under repo B even when SHAs collide.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (illustrative, not literal file placement per rules)
test "status webhook does not leak state across repositories with colliding SHA" do
  victim_stack = shipit_stacks(:shipit)
  attacker_stack = create_stack(repository: create_repository(owner: 'attacker-org', name: 'evil'))

  shared_sha = 'a' * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha)
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha)

  StatusHandler.new.call(
    'repository' => { 'owner' => { 'login' => 'attacker-org' }, 'name' => 'evil' },
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/build'
  )

  assert_not victim_commit.reload.deployable?, "victim commit must not become deployable from attacker-org webhook"
  assert attacker_commit.reload.deployable?
end
```
```ruby
# test/controllers/api/deploys_controller_test.rb (illustrative)
test "require_ci deploy is rejected when only a foreign repository's webhook marked the SHA successful" do
  # simulate cross-repo pollution as above, then:
  post :create, params: { stack_id: victim_stack.to_param, sha: shared_sha, require_ci: true }
  assert_response :unprocessable_entity
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
