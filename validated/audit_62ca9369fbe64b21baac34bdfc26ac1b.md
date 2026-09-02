### Title
Webhook signing-organization (`repository.owner.login`) is decoupled from the mutated repository (`params.repository.full_name`), letting a cross-org signed payload reopen/unarchive another org's stack - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the HMAC against using `repository.owner.login` (or `organization.login`) from the JSON body, while `ReopenedHandler` (and its siblings) resolve the actual `Repository`/`Stack` to mutate using the independently-attacker-controlled `repository.full_name` field from the *same* body. Nothing enforces that these two fields describe the same repository, so a payload signed with organization A's secret can name organization B's repository in `full_name` and cause `ReopenedHandler#process` to call `stack.unarchive!` on organization B's review stack.

### Finding Description
The broken binding, stated as an equality that the code assumes but never checks:

`repository_owner (used to pick the webhook_secret for HMAC verification) == owner(params.repository.full_name) (used to resolve the Repository/Stack that gets mutated)`

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` via `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and uses it to fetch the per-org `github_app`/`webhook_secret` for HMAC verification [2](#0-1) .
- If verification succeeds, the raw, unmodified `params` hash is dispatched unchanged to every handler for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .
- `ReopenedHandler#repository` independently re-reads `params.repository.full_name` from that same body to resolve the target `Repository` (`Shipit::Repository.from_github_repo_name(params.repository.full_name)`), and `#stack` builds a `ReviewStackAdapter` scoped to `repository.review_stacks`, ultimately calling `stack.unarchive!` [4](#0-3) .
- `Repository.from_github_repo_name` simply splits `"owner/name"` and does a `find_by` - it has no relationship to which org's secret signed the request [5](#0-4) .

Root cause: the two fields (`repository.owner.login` and `repository.full_name`) are read from the same attacker-supplied JSON independently, at different layers (controller vs. handler), with no assertion that `full_name` starts with `repository_owner`. An attacker who legitimately owns/administers an organization already configured in Shipit (and therefore knows that org's `webhook_secret`, per the question's stated precondition) can sign a payload where `repository.owner.login` = their own org (so the correct/known secret is used and verification passes) but `repository.full_name` = `"victim-org/victim-repo"` (an unrelated tenant's repository already onboarded to the same Shipit instance).

Exploit flow:
1. Attacker POSTs to `/webhooks` with header `X-Github-Event: pull_request`, a valid `X-Hub-Signature` computed with their own org's `webhook_secret`, and a JSON body where `repository.owner.login` = `"attacker-org"` but `repository.full_name` = `"victim-org/victim-repo"`, `action` = `"reopened"`.
2. `verify_signature` fetches `Shipit.github(organization: "attacker-org")` and verifies the signature successfully (attacker knows this secret).
3. `ReopenedHandler` resolves `repository` via `params.repository.full_name` = `"victim-org/victim-repo"`, finds the real `Repository`/`Stack` belonging to the victim org, and unarchives its review stack if `unarchive?` conditions (provisioning behavior/labels, attacker-controlled in the payload) are met.

None of the existing guards stop this: `drop_unhandled_event` only checks the event type is handled [6](#0-5) ; `verify_signature` only authenticates that *some* org's secret matches, not that it's the org named in `full_name`; the `ExplicitParameters` schema in `ReopenedHandler` only validates types/presence of `repository.full_name`, not its relation to the verifying org [7](#0-6) ; and `Repository` model validations only constrain character sets, not cross-tenant binding [8](#0-7) .

### Impact Explanation
An attacker holding no more privilege than control of a repository/org already integrated with a shared Shipit instance can force `stack.unarchive!` (and, by the same pattern, `archive!` via `ClosedHandler`, or `update` calls via `EditedHandler`/`AssignedHandler`) on another organization's `Repository`/`Stack`/`PullRequest` records that they do not own. This is a payload-for-one-repository-mutating-another's-stack condition, matching the Critical severity category explicitly listed in the rules. Unarchiving a review stack can re-trigger the review-stack provisioning/deploy pipeline for the victim's repository, effectively driving CI/deploy automation on infrastructure the attacker does not control. The same class of bug (using `params.repository.full_name` for record resolution independent of the signature-verifying org) affects `ClosedHandler`, `EditedHandler`, `AssignedHandler`, `LabeledHandler`, `UnlabeledHandler`, and `OpenedHandler`, so the blast radius spans every PR-related webhook handler, and is repeatable against arbitrary victim repositories already onboarded to the shared Shipit instance.

### Likelihood Explanation
Preconditions: the attacker must control (or know the `webhook_secret` for) at least one organization that is legitimately configured in the shared Shipit instance's `Shipit.github_apps`/`github` config - consistent with the question's stated attacker capability ("verified under their own org's webhook_secret"). No Shipit session, API token, or GitHub App private key is needed beyond that. The attack is a single crafted HTTP POST with no rate limiting or additional secrets required, and is trivially repeatable against any other onboarded repository whose `owner/name` the attacker can guess or discover (repository names are not secret).

### Recommendation
In `WebhooksController` (or the base `Handler`), assert that the organization used to verify the signature (`repository_owner`) matches the owner segment of every repository-scoped field consumed by handlers (e.g., `payload.dig('repository','full_name')`) before dispatching to handlers - reject the request (422) on mismatch. Alternatively, have each handler's `repository` lookup scope by the verified `repository_owner` (passed down from the controller) rather than trusting `params.repository.full_name` alone.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb` or a new cross-org test file):
1. Create two orgs/repos: `stack_a = shipit_stacks(:attacker_org_repo)` (archived) and `stack_b = shipit_stacks(:victim_org_repo)` (archived), each with a distinct `Shipit.github(organization: ...)` config carrying its own `webhook_secret`.
2. Build a `payload` hash with `action: "reopened"`, `repository: { full_name: "victim-org/victim-repo", owner: { login: "attacker-org" } }`, and provisioning-eligible `pull_request.labels`.
3. Compute `X-Hub-Signature` using `attacker-org`'s `webhook_secret` (known/simulated as attacker-controlled).
4. POST to `/webhooks` with that signature and body; assert `response` is `:ok` (signature verification passes because `repository_owner` == `"attacker-org"`).
5. Assert the binding: `assert_not stack_b.reload.archived?` should FAIL (demonstrating the bug) because `ReopenedHandler` unarchives `victim-org/victim-repo`'s stack despite the payload being signed only for `attacker-org`.
6. After the fix, assert `stack_b.reload.archived?` remains `true` (or response is `422`), proving `ReopenedHandler` only mutates `PullRequest`/`Stack` rows scoped to the verifying organization (`repository_owner == owner(params.repository.full_name)`).

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
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
