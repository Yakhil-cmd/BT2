### Title
Webhook signature verification uses `repository.owner.login`/`organization.login` while `CheckSuiteHandler` looks up the target repo from `repository.full_name`, allowing cross-tenant `schedule_refresh_check_runs!` forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/check_suite_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the `webhook_secret`) used to authenticate a webhook purely from `repository.owner.login` (or `organization.login` as fallback), while `Handler#repository_name`/`CheckSuiteHandler#process` independently resolve the target `Repository`/`Stack`/`Commit` from `repository.full_name`. Nothing in the code enforces that these two attacker-controlled fields refer to the same organization, and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when the selected organization has no `webhook_secret` configured.

### Finding Description
Binding claimed: organization verifying (`params.dig('repository','owner','login') || params.dig('organization','login')` in `repository_owner`, [1](#0-0) ) == organization named in `repository.full_name` consumed by `CheckSuiteHandler` via `Handler#repository_name` ( [2](#0-1) ). Tracing the code shows this binding is never enforced.

`WebhooksController#create` parses the raw body once and passes the *same* hash to every handler for the event: [3](#0-2) . Before `create` runs, `verify_signature` picks the `GitHubApp` config using only `repository_owner`, which reads `repository.owner.login` first, falling back to `organization.login`: [4](#0-3) [1](#0-0) . `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever the resolved org's config has no `webhook_secret` set: [5](#0-4) .

`CheckSuiteHandler#process` never looks at `repository.owner.login` or `organization.login`; it resolves the target stacks purely via `Handler#repository_name`, i.e. `payload.dig('repository', 'full_name')`, and schedules `schedule_refresh_check_runs!` on any matching commit: [6](#0-5) [2](#0-1) .

Because `repository.owner.login` (used for auth) and `repository.full_name` (used for repo resolution) are two independently attacker-controlled JSON fields with no cross-check, an attacker who knows that *any* organization configured in this Shipit instance has no `webhook_secret` set (this is an explicitly supported, non-error configuration state per `GitHubApp#verify_webhook_signature`) can craft:
```json
{
  "repository": { "owner": {"login": "org-without-secret"}, "full_name": "victim-org/victim-repo" },
  "check_suite": { "head_branch": "master", "head_sha": "<victim commit sha>" }
}
```
`verify_signature` resolves `repository_owner = "org-without-secret"`, verification trivially passes (no secret configured), and `CheckSuiteHandler#process` then operates against `victim-org/victim-repo`, which was never involved in the authentication decision, scheduling a refresh of check runs for a real commit belonging to a completely different, unrelated (and possibly fully secured) organization.

The narrower "organization-only, no `repository` key" variant in the question is self-defeating: without a `repository` key, `repository_name` is `nil`, `Repository.from_github_repo_name(nil)` returns `nil`, and `stacks` falls back to `Stack.none`, so no commit is affected. The exploitable path requires the `repository` key to be present with a `full_name` pointing at the victim, while `repository.owner.login` names the unsecured organization — which the question also raises as the alternative and is the actually valid path.

None of the existing guards stop this: `drop_unhandled_event` only checks the event has a registered handler; `ExplicitParameters` (`CheckSuiteHandler.params`) only validates `check_suite.head_sha`/`head_branch` types, not the repository binding; there is no `force_github_authentication`/`User#authorized?`/`require_permission!` involved since webhooks bypass the session/API-client auth stack entirely.

### Impact Explanation
An attacker can cause `Commit#schedule_refresh_check_runs!` to fire for a commit belonging to a victim stack/repository that the attacker's forged request never authenticated against, mutating task/commit state cross-tenant without holding any secret for the victim org. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." The technique is repeatable against any commit/branch combination the attacker can guess or observe (branch names and commit SHAs are typically public), for as long as any organization in the Shipit instance lacks a configured `webhook_secret`.

### Likelihood Explanation
Exploitability is entirely gated on operational configuration: it requires at least one organization registered in Shipit's multi-org GitHub config (`secrets.github`) that has no `webhook_secret` set — a state the code explicitly tolerates (`return true unless webhook_secret`) rather than rejects. If that precondition holds, the attacker needs no credentials, tokens, or knowledge of any secret: they only need to know (a) the name of the unsecured org, and (b) the `full_name`/branch/SHA of a target commit in the victim repo, both of which are typically discoverable from public GitHub activity. Attacker cost is a single unauthenticated `POST /webhooks` request per exploitation attempt, and the attack is fully repeatable.

### Recommendation
Enforce a single source of truth for organization identity in `WebhooksController#verify_signature` and require that `repository.full_name`'s owner equals `repository_owner`/`organization.login` before dispatching to handlers; alternatively, have `Handler#repository_name` re-derive/verify against the same organization value used during signature verification, and reject payloads where they diverge. Consider also making `webhook_secret` mandatory for every configured organization (fail closed) rather than silently permitting unauthenticated webhooks when absent.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":check_suite forged owner without webhook_secret schedules refresh for a different (victim) org's stack" do
  # Precondition: configure an org "unsecured-org" in Shipit.github config with no webhook_secret,
  # and a real Stack/Commit under a different org, e.g. "victim-org/victim-repo".
  victim_stack = shipit_stacks(:shipit) # repo full_name e.g. "shopify/shipit-engine"
  victim_commit = shipit_commits(:first)
  victim_stack.update!(branch: "master")
  victim_commit.update!(sha: "deadbeef" * 5)

  request.headers['X-Github-Event'] = 'check_suite'
  body = {
    repository: { owner: { login: 'unsecured-org' }, full_name: victim_stack.repository.full_name },
    check_suite: { head_branch: 'master', head_sha: victim_commit.sha }
  }.to_json

  # No X-Hub-Signature header sent at all -- verify_webhook_signature returns true
  # because 'unsecured-org' has no webhook_secret configured.
  assert_enqueued_with(job: RefreshCheckRunsJob) do
    post :create, body:, as: :json
    assert_response :ok
  end

  # Equality check both sides:
  # organization verifying   == "unsecured-org"      (from repository.owner.login)
  # organization in full_name == owner of victim_stack.repository.full_name (different org)
  # -> mismatch, yet schedule_refresh_check_runs! still fired for victim_commit.
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
