### Title
Cross-repository commit status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` updates commit status by looking up commits with `Commit.where(sha: params.sha)`, with no filter tying the lookup to the repository that was actually verified by the webhook signature. Because git commit SHAs are content-addressed and portable across repositories, an attacker who owns/controls any repository monitored by Shipit (a capability explicitly granted in the threat model: "emit webhooks from a repository they own") can push a byte-identical copy of a victim commit into their own repo and set a `success` status on it, causing Shipit to flip the status of the *victim's* `Commit` row as well.

### Finding Description
The claimed binding is: `verified_webhook.repository_owner/repository == stack(commit).repository`. Tracing the code shows this binding is never enforced for status events.

- `Shipit::WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) only proves the payload was signed by GitHub for the org named in `params.dig('repository','owner','login')`. It says nothing about which `Commit`/`Stack` rows in Shipit's DB may be mutated. [1](#0-0) 
- `Handler` base class provides a repository-scoping helper, `stacks`, which resolves `Repository.from_github_repo_name(repository_name)` from the payload's `repository.full_name` — this is the mechanism other handlers are expected to use to bind actions to the correct repository. [2](#0-1) 
- `StatusHandler#process` does **not** use `stacks`/`repository_name` at all. It runs a global, unscoped query: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. Any `Commit` row anywhere in the Shipit instance whose `sha` matches the payload's `sha` gets its status updated, regardless of which repository the verified webhook belongs to. [3](#0-2) 
- Downstream, `UndeployedCommit#deploy_disallowed?` gates the deploy UI purely on `!deployable? || !stack.deployable?`, i.e., on the (now attacker-influenced) status state, with no re-check of repository identity. [4](#0-3) 
- `Api::DeploysController#create` re-checks `commit.deployable?` only when `require_ci` is passed, again with no repository comparison between the commit and the request's stack beyond the existing `stack.commits.by_sha` scope (which is fine — the commit row itself is already corrupted). [5](#0-4) 

Exploit flow: attacker owns/controls a repository that has the Shipit GitHub App/webhook installed (a repo they own, per the stated threat model). Attacker obtains the exact byte-for-byte contents of a victim commit (SHA is content-addressed, so pushing the identical tree/parent/author/committer/message/timestamp into their own repo reproduces the same SHA) and pushes it into their own repo. Attacker then triggers (or has GitHub naturally send) a `status` event for that SHA with `state: success` from their own repository — this webhook is genuinely signed by GitHub for the attacker's own org, so `verify_signature` passes legitimately. `StatusHandler#process` finds the pre-existing victim `Commit` row (same SHA, different stack/repository) and calls `create_status_from_github!`, flipping it to `success`. The victim's stack UI now shows the commit as deployable; an operator clicks Deploy; `Api::DeploysController#create` with `require_ci: true` no longer 422s and proceeds to `stack.trigger_deploy`, eventually reaching `Command#start`/`PTY.spawn` on the deploy host.

None of the existing guards catch this: `verify_signature` authenticates the *webhook sender's own repo*, not the *target commit's repo*; `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape; there is no `Repository`/`Stack` comparison anywhere in `StatusHandler`.

### Impact Explanation
This is a payload for one repository (attacker-owned) mutating another repository's `Commit` record (victim stack), which then unlocks an unauthorized deploy of code that never actually passed CI for the victim's stack — reaching `Command#start`/`PTY.spawn` on the deploy host for the victim's stack. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy." It is repeatable against any repository/stack whose commits' SHAs the attacker can reproduce (any commit that is public, e.g. visible on GitHub, since git SHAs are computed over public metadata and any commit already present in a public history can be reproduced bit-for-bit in another repo the attacker controls, e.g. via `git fetch`/`git push` of the same commit object). Blast radius spans every stack/repository hosted by the same Shipit instance, since the vulnerable lookup is entirely global (`Commit.where(sha:)` with no repository scope).

### Likelihood Explanation
Preconditions: (1) attacker needs a repository they own/control that has Shipit's GitHub webhook configured to send `status` events to the same Shipit instance (explicitly within the granted attacker capability of "emit webhooks from a repository they own"); (2) the target victim commit's exact content must be reproducible/pushable into that repo, which is trivial for any commit that is public (SHA1 is a content hash, not a repo-bound secret); (3) an operator needs to click Deploy afterward, but the whole point of the described threat is that the UI now legitimately shows "green"/deployable, so a normal, non-malicious operator action suffices. No secrets (`webhook_secret`, `api_clients_secret`, GitHub App private key) are required by the attacker. This makes the attack low-cost and repeatable.

### Recommendation
Scope the `StatusHandler` (and ideally all commit-mutating webhook handlers) lookups to the repository verified by the webhook, mirroring the `stacks`/`repository_name` helper already present in `Handler`. Concretely, change `StatusHandler#process` to only update commits belonging to stacks under `Repository.from_github_repo_name(repository_name)` (or equivalently `stacks.flat_map(&:commits).where(sha: params.sha)`), rather than a global `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook from an unrelated repository must not affect a commit belonging to a different stack" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = shipit_commits(:first)
  assert_equal victim_stack, victim_commit.stack

  attacker_repo_full_name = "attacker/unrelated-repo"
  # attacker's payload claims a *different* repository but reuses victim_commit.sha
  payload = {
    "sha" => victim_commit.sha,
    "state" => "success",
    "repository" => { "full_name" => attacker_repo_full_name, "owner" => { "login" => "attacker" } },
  }

  before_state = victim_commit.reload.state
  Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  after_state = victim_commit.reload.state

  # Binding under test: webhook's verified repository (attacker/unrelated-repo)
  # must equal victim_commit.stack.repository.full_name for the commit to be mutated.
  refute_equal attacker_repo_full_name, victim_commit.stack.repository.full_name
  assert_equal before_state, after_state, "status of a commit outside the verified repository must not change"
end
```
A second integration-level test can drive this through `Api::DeploysController#create` with `require_ci: true`, asserting the response stays `:unprocessable_entity` after the forged cross-repo status, per the binding above.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/undeployed_commit.rb (L39-41)
```ruby
    def deploy_disallowed?
      !deployable? || !stack.deployable?
    end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-28)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

        allow_concurrency = params.allow_concurrency.nil? ? params.force : params.allow_concurrency
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
        render_resource(deploy, status: :accepted)
      end
```
