### Title
Webhook `repository.owner.login` authenticates the request while unrelated `repository.full_name` selects the mutated Stack, enabling cross-repository forced sync - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/push_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to verify against using `payload.dig('repository','owner','login')`, while `Handler#stacks`/`#repository_name` (used by `PushHandler#process`) select the Stack to mutate using `payload.dig('repository','full_name')`. These are two independent, attacker-controlled fields in the same unauthenticated JSON body, and the code never checks that `full_name` is consistent with `owner.login`. Additionally, `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the resolved organization has no `webhook_secret` configured.

### Finding Description
The broken binding: the equality the code implicitly assumes is `repository.owner.login == repository.full_name.split('/').first` (i.e., "the org whose secret authenticated this request" == "the org/repo the handler acts on"). This equality is never enforced.

Path:
- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-30) computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (line 61) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)`.
- `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-83): `return true unless webhook_secret` — if the resolved org's config in Shipit has no `webhook_secret`, verification is bypassed entirely regardless of the actual signature header.
- Once `verify_signature` passes, `WebhooksController#create` dispatches the **entire raw JSON payload** to `PushHandler.call(params)` (app/controllers/shipit/webhooks_controller.rb:10-15).
- `Handler#repository_name` (app/models/shipit/webhooks/handlers/handler.rb:36-38) reads `payload.dig('repository', 'full_name')` — a completely separate field from the one used for authentication.
- `Handler#stacks` (handler.rb:32-34) resolves `Repository.from_github_repo_name(repository_name)` and its `.stacks`.
- `PushHandler#process` (app/models/shipit/webhooks/handlers/push_handler.rb:12-17) runs `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }`.

Exploit: attacker crafts a JSON body with `repository.owner.login` set to an org that Shipit has configured (so `Shipit.github(organization:)` doesn't raise `GithubOrganizationUnknown`) but for which no `webhook_secret` is set, `repository.full_name` set to `"victim-org/victim-repo"`, `ref: "refs/heads/master"`, and `after: "<attacker-chosen 40-hex sha>"`. Because `verify_webhook_signature` returns `true` unconditionally for that org, `verify_signature` passes with no valid signature needed. `PushHandler#process` then resolves the victim's Stack purely from `full_name` and calls `stack.sync_github(expected_head_sha: <attacker-chosen sha>)`.

None of the existing guards catch this: `drop_unhandled_event` only checks the event type exists; `verify_signature` only checks the signature for the org named in `owner.login`, never cross-checking it against `full_name`; `ExplicitParameters` schemas for `PushHandler` only require `ref` and `after` to be present/typed, not that `repository.full_name` matches `repository.owner.login`; there is no `Repository` ownership check tying the authenticated org to the acted-upon repo.

### Impact Explanation
This is a cross-repository/cross-tenant mutation: a request that never authenticates against the victim repository's secret ends up invoking `Stack#sync_github` for the victim's stack with an attacker-chosen `expected_head_sha`. `sync_github` drives GitHub sync/deploy pipeline state (via `GithubSyncJob`) for a repository the attacker does not control and did not authenticate against. This matches the "payload for one repository mutating another's stack" Critical category. The attack is repeatable against any victim stack whose repo full_name is known, as long as any Shipit-configured organization (potentially the attacker's own) has no `webhook_secret` set — blast radius spans every tenant stack tracked by the instance, not just the org named in `owner.login`.

### Likelihood Explanation
Preconditions: (1) a Shipit organization config exists (so `Shipit.github(organization:)` doesn't raise `GithubOrganizationUnknown` and return 422) that has no `webhook_secret` configured — a plausible/real misconfiguration when a Shipit operator onboards an org before wiring up its webhook secret, or leaves a default entry unconfigured; (2) the victim stack exists and tracks `victim-org/victim-repo` on `master`. Given precondition (1), the attacker needs zero secrets, zero Shipit credentials, and can send the crafted payload directly to `POST /webhooks` from any internet client. This is trivially repeatable and scriptable against arbitrary victim repos/stacks.

### Recommendation
In `WebhooksController`/`Handler`, derive the organization used both for signature verification and for repository/stack resolution from the *same* validated field, and explicitly assert `repository.full_name.split('/').first == repository.owner.login` (case-insensitively) before dispatching to handlers — reject the payload otherwise. Additionally, remove or gate the `return true unless webhook_secret` short-circuit in `GitHubApp#verify_webhook_signature` (lib/shipit/github_app.rb:76-83) so that a missing `webhook_secret` for a configured org fails closed (422) instead of auto-accepting unsigned/any-signed requests.

### Proof of Concept
Minitest plan (test/controllers/webhooks_controller_test.rb style, no live GitHub):
```ruby
test "cross-repo push forgery: owner.login authenticates one org, full_name mutates a different victim stack" do
  # Arrange: victim stack tracks victim-org/victim-repo on master
  victim_repo = shipit_repositories(:shipit) # or create with owner: 'victim-org', name: 'victim-repo'
  victim_stack = shipit_stacks(:shipit)      # branch: 'master', repository: victim_repo

  # Configure an attacker org known to Shipit but with NO webhook_secret
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GitHubApp.new('attacker-org', {}) # no :webhook_secret key
  )

  forged_sha = 'a' * 40
  payload = {
    'ref' => 'refs/heads/master',
    'after' => forged_sha,
    'repository' => {
      'full_name' => victim_repo.github_repo_name, # e.g. 'victim-org/victim-repo'
      'owner' => { 'login' => 'attacker-org' }
    }
  }.to_json

  request.headers['X-Github-Event'] = 'push'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # invalid/arbitrary, irrelevant since webhook_secret is nil

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: victim_stack.id, expected_head_sha: forged_sha]) do
    post :create, body: payload, as: :json
  end
  assert_response :ok
end
```
Assertions on both sides of the equality:
- LHS (authenticated org): `repository_owner` == `'attacker-org'` (attacker-controlled, no secret required).
- RHS (mutated repo/stack): `repository_name` == `victim_repo.github_repo_name` == `'victim-org/victim-repo'`, and `Stack#sync_github` is invoked for `victim_stack.id` with `expected_head_sha: forged_sha` — proving the two never had to match for the mutation to occur.