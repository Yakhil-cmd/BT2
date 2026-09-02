### Title
Cross-repository state forgery via `repository.owner.login`/`repository.full_name` field split in webhook signature verification - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the `webhook_secret`) to verify a webhook against using `params.dig('repository','owner','login')`, while the PR handlers (e.g. `LabeledHandler`) resolve the target repository/stack using the independent field `params.repository.full_name`. Because these are two separate attacker-controlled strings in the same unsigned JSON body, and because `GitHubApp#verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for the named organization, an attacker who owns (or names) any organization configured in Shipit without a `webhook_secret` can forge a `pull_request`/`labeled` payload whose `repository.owner.login` is that no-secret org but whose `repository.full_name` points at an arbitrary victim repository, causing the handler to archive/unarchive/mutate the victim's review stack.

### Finding Description
The broken binding is: `verify_signature` treats `repository_owner == params.dig('repository','owner','login')` as authorizing the payload for `repository.full_name`, i.e. it implicitly assumes `repository.full_name.split('/').first == repository_owner`. Nothing enforces that equality.

Path:
- `WebhooksController#create` parses the raw JSON body and dispatches to `Shipit::Webhooks.for_event(event)` [1](#0-0) , guarded only by `before_action :verify_signature` [2](#0-1) .
- `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` (or `organization.login`) and looks up `Shipit.github(organization: repository_owner)`, then calls `verify_webhook_signature` [3](#0-2) [4](#0-3) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization has no configured `webhook_secret`, independent of signature or algorithm [5](#0-4) .
- The `pull_request`/`labeled` event fans out to `Handlers::PullRequest::LabeledHandler` [6](#0-5) , which resolves the target repository purely from `params.repository.full_name`, not from `repository.owner.login` [7](#0-6) , and then archives/unarchives the matching `ReviewStack` via `ReviewStackAdapter#archive!`/`#unarchive!` [8](#0-7) [9](#0-8) .

Exploit: attacker crafts a JSON body:
```json
{
  "action": "labeled",
  "number": 42,
  "repository": {"owner": {"login": "attacker-no-secret-org"}, "full_name": "victim-org/victim-repo"},
  "pull_request": { ...state:"open", head:{...}, labels:[{"name":"<provisioning label>"}], user:{"login":"attacker"} },
  "sender": {"login": "attacker"}
}
```
sent to `POST /webhooks` with `X-Github-Event: pull_request` and any (or no) `X-Hub-Signature`. Because `attacker-no-secret-org` has no `webhook_secret` configured in Shipit, `verify_webhook_signature` returns `true` regardless of the header/algorithm supplied, satisfying the question's premise that a `sha1=` header (or any bogus signature) is accepted. `drop_unhandled_event` and the `ExplicitParameters` schema both pass because `pull_request`/`labeled` is a registered handler and the payload matches the declared schema shape [10](#0-9) . The handler then loads `victim-org/victim-repo`'s `Repository` and mutates its review stack — a repository the attacker never proved control over and whose real owning organization's `webhook_secret` was never checked.

### Impact Explanation
An unauthenticated attacker can archive or unarchive (deprovision/reprovision) another tenant's review stack — a repository/organization completely unrelated to the one whose (absent) secret was "verified" — by controlling only the JSON body of an unauthenticated `POST /webhooks` request. This is repeatable against any repository with `review_stacks_enabled`, as long as any organization configured on the Shipit instance lacks a `webhook_secret`. This matches "Critical — a payload for one repository mutating another's stack," since it lets one (weakly configured) tenant write into another tenant's stack lifecycle without ever authenticating as that tenant.

### Likelihood Explanation
Requires at least one organization to be configured in Shipit without a `webhook_secret` (`@config[:webhook_secret]` absent/blank) — plausible in staging/multi-org setups or during incremental webhook-secret rollout, and is entirely a hosting configuration detail, not something the attacker needs privileged access to discover (it's directly testable by sending forged payloads and observing `head(422)` vs `head(:ok)`). Once such an org exists, the attack is a single unauthenticated HTTP POST with attacker-chosen JSON, fully repeatable and scriptable against arbitrary target repositories.

### Recommendation
Enforce that `repository.owner.login` (the field used for signature-organization selection) matches the owner segment of `repository.full_name` before dispatching to handlers, and/or require handlers to re-derive/verify the repository's owning organization against the org whose secret validated the request. Additionally, do not treat a missing `webhook_secret` as automatic success — fail closed, or scope such "open" organizations so they cannot be leveraged to sign payloads referencing other organizations' repositories.

### Proof of Concept
```ruby
test "labeled event with mismatched owner/full_name mutates a different org's stack" do
  victim_repo = shipit_repositories(:shipit) # owned by "shopify", review_stacks_enabled: true
  review_stack = shipit_review_stacks(:review_stack) # under victim_repo

  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    stub(verify_webhook_signature: true) # no webhook_secret configured for attacker-org
  )

  body = {
    action: 'labeled',
    number: review_stack.pull_request.number,
    repository: { owner: { login: 'attacker-org' }, full_name: victim_repo.full_name },
    pull_request: { ... state: 'open', labels: [{ name: victim_repo.provisioning_label_name }], head: { sha: 'x', ref: 'x' }, user: { login: 'attacker' }, assignees: [] },
    sender: { login: 'attacker' }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef'

  assert_equal 'attacker-org', JSON.parse(body).dig('repository','owner','login')
  refute_equal JSON.parse(body).dig('repository','owner','login'), victim_repo.full_name.split('/').first

  post :create, body:, as: :json

  assert review_stack.reload.archived? # side effect landed on victim repo's stack despite attacker-org's (secret-less) verification
end
```
This demonstrates the two sides of the broken equality — `repository_owner` used for verification ("attacker-org") vs. the actual owner of the repository/stack mutated ("shopify"/victim) — diverge, and the divergence is not caught anywhere in the controller or handler chain.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-6)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks.rb (L9-18)
```ruby
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L8-39)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-50)
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

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```
