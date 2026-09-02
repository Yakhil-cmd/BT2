### Title
Webhook signature verification keyed on `repository.owner.login` while state mutation is keyed on `repository.full_name`, allowing cross-tenant `ReviewStack`/`PullRequest` creation - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / secret to validate the request against using `params.dig('repository','owner','login')`, but `OpenedHandler` and `ReviewStackAdapter` resolve and mutate the target `Repository`/`ReviewStack` using the independent, attacker-controlled field `repository.full_name`. Because these two fields are never cross-checked, an attacker can pass verification cheaply against any organization with no `webhook_secret` configured, while causing a database write scoped to a completely different (victim) organization's repository.

### Finding Description
The broken binding as an explicit equality that the code implicitly (and wrongly) assumes but never enforces: `params.dig('repository','owner','login') == params.dig('repository','full_name').split('/').first`.

Trace:
- `verify_signature` in <cite repo="Jaredbentat/shipit-engine--014" path="app/controllers/shipit/webhooks_controller.rb" start="24,30" end="30,30" /> computes `repository_owner` from `params.dig('repository', 'owner', 'login')` ( [1](#0-0) ) and looks up `Shipit.github(organization: repository_owner)`, then calls `verify_webhook_signature`.
- `GithubApp#verify_webhook_signature` in [2](#0-1)  contains `return true unless webhook_secret` — if the resolved organization has no configured `webhook_secret` (the stated precondition for `no-secret-org`), **any** payload is accepted, signature or not.
- `create` then dispatches to handlers with the full raw params: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` ( [3](#0-2) ).
- `OpenedHandler#repository` resolves the actual target repository from `params.repository.full_name` — a nested field the attacker controls independently of `repository.owner.login` — via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` ( [4](#0-3) ).
- If that repository exists and has review stacks enabled/provisioning allowed, `ReviewStackAdapter#find_or_create!` creates a `ReviewStack` and its `PullRequest` scoped to `repository.review_stacks` for that resolved repository ( [5](#0-4)  and [6](#0-5) ).

Nothing in `verify_signature`, `Handler#initialize`/`ExplicitParameters` schema, `OpenedHandler`, or `ReviewStackAdapter` cross-validates that `repository.owner.login` (used to select the signing organization) matches the owner embedded in `repository.full_name` (used to select and mutate the actual `Repository`/`ReviewStack` row). The `ExplicitParameters` schema for `OpenedHandler` ( [7](#0-6) ) only requires `repository.full_name` to be present as a `String`; it does not require or check equality with any owner field.

Attacker's exact request: `POST /webhooks` with `X-Github-Event: pull_request`, no valid `X-Hub-Signature` needed (or any value), and body:
```json
{
  "action": "opened",
  "number": 999,
  "repository": {"owner": {"login": "no-secret-org"}, "full_name": "victim-org/victim-repo"},
  "pull_request": {"number": 999, "head": {"ref": "attacker-branch"}, "base": {"ref": "main"}, ...},
  "sender": {"login": "attacker"}
}
```
`verify_signature` resolves `Shipit.github(organization: "no-secret-org")`; since that org has no `webhook_secret`, `verify_webhook_signature` short-circuits `true` regardless of the actual signature header. The handler then operates on `victim-org/victim-repo`.

### Impact Explanation
An attacker with zero secrets and no relationship to `victim-org` can trigger creation/mutation of a `ReviewStack` and `PullRequest` record scoped to `victim-org/victim-repo`, as long as that repository exists in Shipit with `review_stacks_enabled` and a matching provisioning behavior (`allow_all`, or label-based conditions the attacker can also satisfy since they control the PR's labels on their own fork/PR payload fields). This is a cross-tenant write: a payload "verified" only against `no-secret-org` results in a persisted row under `victim-org`. This matches the "Critical" impact category: "a payload for one repository mutating another's stack ... an unauthorized deploy, rollback or merge" is enabled once a review stack is provisioned (`ReviewStackProvisioningQueue.add(stack)` is triggered), potentially kicking off deploy/provisioning behavior for `victim-org`'s infrastructure. The attack is repeatable against any repository whose actual owner differs from any org configured without a `webhook_secret`.

### Likelihood Explanation
Preconditions required: at least one GitHub organization configured in Shipit without a `webhook_secret` (explicitly the scenario given, `no-secret-org`), and a victim repository with review-stack support enabled and a provisioning behavior the attacker's payload satisfies. No Shipit session, API token, or GitHub secret is needed — the attacker only needs to know (a) the name of an org lacking a webhook secret and (b) the victim's `owner/repo` full name, both of which are typically discoverable/guessable or public. This is a single unauthenticated HTTP POST, fully repeatable and scriptable.

### Recommendation
In `WebhooksController#verify_signature`, derive `repository_owner` and enforce that the organization used to select the signing secret matches the actual owner embedded in `repository.full_name` before dispatching to handlers. At minimum, reject events where `params.dig('repository','full_name')&.split('/')&.first != repository_owner`. Additionally, do not treat a missing `webhook_secret` as an automatic pass in `GithubApp#verify_webhook_signature`; require explicit configuration or fail closed, and have each `Handler` validate that the resolved `Repository`'s `owner` matches the verified webhook organization before creating/mutating any records.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "opened pull_request from secret-less org cannot mutate victim org's repository" do
  victim_repo = shipit_repositories(:shipit) # owner: 'victim-org', name: 'victim-repo', review_stacks_enabled: true, provisioning_behavior: 'allow_all'

  Shipit.stubs(:github).with(organization: 'no-secret-org').returns(
    Shipit::GithubApp.new('no-secret-org', {}) # no webhook_secret configured -> verify_webhook_signature returns true
  )

  request.headers['X-Github-Event'] = 'pull_request'
  body = {
    action: 'opened',
    number: 999,
    pull_request: {
      id: 1, number: 999, url: 'https://api.github.com/x', title: 't', state: 'open',
      additions: 1, deletions: 1,
      head: { sha: 'abc', ref: 'attacker-branch' },
      user: { login: 'attacker' }, assignees: [], labels: []
    },
    repository: { owner: { login: 'no-secret-org' }, full_name: 'victim-org/victim-repo' },
    sender: { login: 'attacker' }
  }.to_json

  assert_difference -> { Shipit::ReviewStack.where(repository: victim_repo).count }, 1 do
    post :create, body:, as: :json
  end

  # Binding check: the org verified against ('no-secret-org') != the org whose row was written ('victim-org')
  assert_not_equal 'no-secret-org', victim_repo.owner
end
```
This asserts that verification succeeded solely against `no-secret-org` (no secret configured) while the persisted `ReviewStack` row belongs to `victim-org/victim-repo`, proving the two organizations diverge.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-85)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end
```
