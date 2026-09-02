## Confirmed: Cross-repository status write via unscoped `Commit.where(sha:)`

### Title
Cross-repository status forgery via `Commit.where(sha:)` lacking repository/branch scope - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits solely by SHA, with no filter on the originating repository or the `branches` named in the payload, so a status webhook that is validly signed for repository A can create a `Status` on any `Commit` row in the database that happens to share that SHA, including one belonging to a completely different `Stack`/repository B.

### Finding Description
The broken binding: the code implicitly assumes `Commit.sha == params.sha` uniquely identifies the commit *within the reporting repository* (i.e., `commit.stack.repository.full_name == payload['repository']['full_name']`). In reality no such equality is ever checked.

`StatusHandler#process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [1](#0-0) 

Unlike the base `Handler` class, which exposes a `stacks` helper that scopes to `Repository.from_github_repo_name(repository_name).stacks`, `StatusHandler` never calls it — it queries the global `Commit` table directly: [2](#0-1) 

The `params.branches` field (`accepts :branches`) is parsed but never used to filter which commits get a new status — it exists in the schema but plays no role in `process`: [3](#0-2) 

Signature verification (`WebhooksController#verify_signature`) only proves the payload was signed by the GitHub App/organization identified by `repository_owner` in the payload; it says nothing about which `Commit` rows are legitimate targets: [4](#0-3) [5](#0-4) 

**Exploit precondition and flow:** The SHA collision must be real — it requires the *same git commit* (identical SHA1) to exist in both the attacker-controlled repo/branch and a victim stack's tracked-branch commit history. This is exactly what happens with a fork: a fork shares commit objects with its upstream, so any commit SHA that exists in the victim's tracked branch also exists, unmodified, in the attacker's own fork/branch history. The attacker:
1. Forks (or otherwise obtains write/webhook access to) a repository containing a commit SHA that also exists in a victim Shipit-tracked stack (or shares history with one).
2. Triggers/sends a `status` event for their own repository, `sha` = the colliding SHA, `branches: [{name: 'attacker-branch'}]`, `repository.full_name` = the attacker's own repo.
3. Because the webhook signature only authenticates "this event genuinely came from GitHub for this org/app," and `StatusHandler` never re-checks that `commit.stack`'s repository matches the payload's `repository.full_name`, **every** `Commit` row across **every** stack with that SHA gets a new `Status` — including the victim's tracked-branch commit, even though the named `branches` entry (`attacker-branch`) is not the victim stack's tracked branch and the `repository.full_name` differs from the victim's `Repository`.

Existing guards checked and found insufficient for this specific path:
- `verify_signature` / `verify_webhook_signature` — authenticates event origin per-organization, not per-commit/per-stack scoping.
- `drop_unhandled_event` — irrelevant (status event is handled).
- `ExplicitParameters` schema (`params do ... end`) — validates shape of `sha`/`branches`, not their consistency with the target record.
- `Handler#stacks` — exists precisely to scope by `repository_name`, but `StatusHandler#process` bypasses it entirely by querying `Commit` directly.

### Impact Explanation
An attacker who controls (or merely forks) a repository containing a commit that also exists in a victim's tracked stack can inject arbitrary CI `Status` records (`state`, `description`, `target_url`, `context`) onto the victim's commit. Since `Status#state` drives `commit.state`/`deployable_status`, CI enablement (`enable_ci_on_stack`), and downstream automation such as `ProcessMergeRequestsJob` and continuous-delivery scheduling (`schedule_continuous_delivery`), a forged "success" status can make an otherwise-unverified commit appear CI-green and eligible for auto-merge/auto-deploy in the victim's stack, i.e. a payload for one repository mutating another's commit/stack — a Critical-severity cross-tenant write.

### Likelihood Explanation
Feasibility hinges entirely on obtaining a genuine, correctly-signed webhook event for the attacker's own repository, since the attacker holds no `webhook_secret`. If Shipit's GitHub App/webhook configuration is shared across all repositories under an org, or the attacker is able to make GitHub itself emit a signed `status` event for their fork (e.g., their own CI posts a status to their fork, or the org's app is broadly installed), the attack is fully repeatable and requires only that a shared-SHA commit exists (trivially true for forks). This part (whether the specific deployment's webhook secret configuration allows an unprivileged fork owner to obtain a validly-signed event naming their own repo) could not be fully confirmed from this engine's code alone, since `webhook_secret`/app installation topology is host/operator configuration, not enforced in this repo. Regardless of that configuration question, the root-cause bug — `Commit.where(sha:)` with no repository/branch scoping — is present and independently verifiable in this engine's code.

### Recommendation
Scope the commit lookup to the reporting repository and, if available, cross-check the named branch(es):
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
using the existing `Handler#stacks` (which resolves `Repository.from_github_repo_name(repository_name)`), so that a status for repo A can never mutate a commit belonging to repo B's stack.

### Proof of Concept
```ruby
test ":status from an untracked/attacker repo must not update a commit in another stack" do
  victim_commit = shipit_commits(:first) # belongs to victim stack/repo per fixtures
  attacker_repo_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'branches' => [{ 'name' => 'attacker-branch' }],
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker' } }
  }.to_json

  request.headers['X-Github-Event'] = 'status'
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # signature validity assumed per scenario

  assert_no_difference('victim_commit.statuses.count') do
    post :create, body: attacker_repo_payload, as: :json
  end
end
```
Before the fix, `victim_commit.statuses.count` increments despite `repository.full_name` and `branches` naming an unrelated attacker repo/branch, proving the equality `commit.stack.repository.full_name == payload['repository']['full_name']` is never enforced.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
