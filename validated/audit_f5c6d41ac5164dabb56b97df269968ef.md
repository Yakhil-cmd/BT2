### Title
Signature-verification org and payload-mutation repo are decoupled, letting a no-secret org forge writes onto any other repository's review-stack labels - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` config using `params.dig('repository','owner','login')`, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org's `webhook_secret` is blank. Every `pull_request` handler, including `LabelCapturingHandler`, then resolves the *affected* repository/stack independently via `params.repository.full_name`. Because these two fields are never cross-checked, an attacker who finds one configured-but-secretless organization can forge a payload whose `repository.owner.login` is that org (to pass verification for free) while `repository.full_name` points at an entirely different, victim organization's repository, causing the victim's `ReviewStack#pull_request.labels` to be overwritten.

### Finding Description
The broken binding is: `repository_owner` (used to authenticate the request) `==` `params.repository.full_name`'s owner (used to select the record that gets mutated). Nothing enforces this equality.

- `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` is `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` immediately if `webhook_secret` is blank for that org's config, so no HMAC is required [3](#0-2) .
- Once verification passes, `WebhooksController#create` dispatches the parsed body to all `pull_request` handlers [4](#0-3) .
- `LabelCapturingHandler#repository` resolves the record independently, using only `params.repository.full_name` (not `repository.owner.login`) via `Shipit::Repository.from_github_repo_name` [5](#0-4) , then finds the stack through `repository.review_stacks` scoped `ReviewStackAdapter#stack` (`scope.find_by(environment: "pr#{number}")`) [6](#0-5) [7](#0-6) .
- `capture_labels` then does `pull_request.update!(labels: params.pull_request.labels.map(&:name))` on the victim's `ReviewStack`'s `PullRequest` [8](#0-7) .
- Those labels are later exposed as uppercased environment variables via `ReviewStack#env`, which merges `pull_request.labels.each { |l| labels[l.upcase] = "true" }` into the deploy/task environment [9](#0-8) .

Root cause: the identity used for authentication (`repository.owner.login`) and the identity used for the write target (`repository.full_name`) come from the same untrusted JSON body but are read from two unrelated keys with no consistency check between them. `Repository.from_github_repo_name` does not re-validate against the authenticated organization [10](#0-9) .

Existing guards do not close this gap: `drop_unhandled_event` only checks the event type [11](#0-10) ; the `ExplicitParameters` schema in `LabelCapturingHandler` only validates shape/types of `repository.full_name`, not its owner-vs-signature consistency [12](#0-11) ; and `Repository` model validations only constrain character sets, not cross-org binding [13](#0-12) .

However, one part of the question's premise does not hold structurally: `LabelCapturingHandler` only ever mutates a `Shipit::ReviewStack` found through `repository.review_stacks.find_by(environment: "pr#{params.number}")` — it can never touch the organization's primary "production" `Stack`, because that lookup is always keyed by the PR-number-derived environment string, not `"production"` [7](#0-6) . `ReviewStack` and the production `Stack` are distinct STI records (`repository.review_stacks` vs. `repository.stacks`) [14](#0-13) . So the "production environment stack" amplification claimed in the question is not accurate for this handler — the real, demonstrable impact is confined to review-stack `PullRequest.labels`/`env`, not the production deploy environment.

### Impact Explanation
An attacker who identifies any Shipit-configured GitHub organization lacking a `webhook_secret` can forge a `pull_request` webhook whose `repository.full_name` names a completely unrelated victim repository/organization that does have review stacks provisioned. This lets the attacker overwrite that victim `ReviewStack`'s `PullRequest#labels`, which then surface as arbitrary uppercase environment variables (`ReviewStack#env`) consumed by deploy/task commands for that review stack — i.e., a payload authenticated for one repository mutates another repository's record and injects attacker-chosen environment variables into its task execution environment. This matches the "payload for one repository mutating another's stack" Critical category. It does **not**, however, reach the production `Stack`/production deploy environment as the question's title implies, since `LabelCapturingHandler` is hard-scoped to `review_stacks` keyed by PR number.

### Likelihood Explanation
Requires: (1) at least one GitHub organization configured in Shipit's `secrets.github` without a `webhook_secret` — an operator misconfiguration precondition, not something the attacker controls; (2) a victim organization/repository with review stacks enabled and an existing open-PR `ReviewStack`. Given those preconditions, the attack is trivial and repeatable: a single unauthenticated `POST /webhooks` with a crafted, internally-inconsistent JSON body and `X-Github-Event: pull_request` header, no signature needed.

### Recommendation
In `WebhooksController#verify_signature`, after verifying the signature for `repository_owner`'s org, also assert that `params.repository.full_name`'s owner segment matches `repository_owner` (case-insensitively) before dispatching to handlers; reject with 422 otherwise. Additionally, treat a configured organization with a blank `webhook_secret` as a hard misconfiguration (fail closed / refuse to boot or refuse all webhooks for that org) rather than silently accepting unsigned payloads in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (or a new test file):
1. Configure two orgs in `Shipit.stubs(:github_app_config)`/credentials: `no-secret-org` with no `webhook_secret`, and `victim-org` (unrelated).
2. Create `victim-org/victim-repo` `Repository` with `review_stacks_enabled` and an existing `ReviewStack` (environment `pr1`) with a `PullRequest` whose `labels` are `[]`.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, no `X-Hub-Signature`, and body:
   ```json
   {
     "action": "opened",
     "number": 1,
     "pull_request": {..., "labels": [{"name":"evil"}], "head": {"ref":"x","sha":"x"}, "user":{"login":"attacker"}, "assignees": []},
     "repository": {"owner": {"login": "no-secret-org"}, "full_name": "victim-org/victim-repo"},
     "sender": {"login": "attacker"}
   }
   ```
4. Assert response is `200 OK` (bypasses `verify_signature`) — establishing `repository_owner == "no-secret-org"` while the mutated record belongs to `"victim-org"`.
5. Reload `victim-org/victim-repo`'s `ReviewStack#pull_request.labels` and assert it now equals `["evil"]`, and `stack.env["EVIL"] == "true"`, proving cross-tenant mutation without any secret for `victim-org`.
6. Negative control: assert the same payload with `repository.owner.login` set to `"victim-org"` (which *does* have a secret) and no valid signature is rejected with `422`, confirming the divergence is specifically caused by the owner/full_name decoupling combined with the no-secret org.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-17)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L96-98)
```ruby
          def environment
            "pr#{params.number}"
          end
```

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
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

**File:** app/models/shipit/repository.rb (L47-48)
```ruby
    has_many :stacks, dependent: :destroy
    has_many :review_stacks, dependent: :destroy
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
