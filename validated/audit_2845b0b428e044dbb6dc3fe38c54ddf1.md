This is a genuine vulnerability confirmed in the code. `verify_signature` derives the HMAC-verification organization solely from `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) , while the actual repository record used to create the `ReviewStack` is resolved from a completely independent field, `params.repository.full_name`, in `OpenedHandler#repository` [3](#0-2) . Nothing ties these two fields together after signature verification — `create` simply re-parses the same raw body and dispatches to handlers [4](#0-3) , and `ReviewStackAdapter#create!` persists a `ReviewStack` for whatever repository the handler resolved [5](#0-4) .

### Title
Cross-organization webhook signature confusion allows forging `ReviewStack` creation for arbitrary repositories - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to verify a webhook against using `repository.owner.login`, but the actual repository whose state gets mutated is looked up later using the unrelated `repository.full_name` field from the same attacker-controlled JSON body. An attacker who owns any organization configured in `Shipit.github` (with a known `webhook_secret`) can sign a payload with their own secret while setting `repository.full_name` to a victim repository, causing a `ReviewStack` to be provisioned against the victim's repository.

### Finding Description
The broken binding: `organization_that_verified_the_signature (params.dig('repository','owner','login'))` should equal `organization_that_owns_the_mutated_repository (params.dig('repository','full_name').split('/').first)`. There is no code anywhere enforcing this equality.

Path: `verify_signature` calls `Shipit.github(organization: repository_owner)` where `repository_owner` reads `params.dig('repository', 'owner', 'login')` [1](#0-0) . If `attacker-org` is a legitimately configured Shipit GitHub organization (attacker's own org, with its own `webhook_secret`), `Shipit.github(organization: 'attacker-org')` returns a `GitHubApp` instance whose `verify_webhook_signature` HMACs the raw body with the attacker's own secret [6](#0-5)  — which the attacker can compute themselves since it's their own secret. Verification passes.

`create` then re-parses `request.raw_post` and dispatches to `Shipit::Webhooks.for_event(event)` handlers [4](#0-3) . `OpenedHandler#repository` resolves the target `Shipit::Repository` using `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a completely separate field from the one used for signature routing [3](#0-2) . If `provision?` passes (victim repo has `review_stacks_enabled` and `provisioning_behavior_allow_all?`), `ReviewStackAdapter#create!` persists a `ReviewStack` scoped to the victim repository [5](#0-4) .

Exact attacker request: `POST /webhooks` with header `X-Github-Event: pull_request`, body `{"action":"opened","repository":{"owner":{"login":"attacker-org"},"full_name":"victim-org/prod-repo"},"pull_request":{...},"sender":{"login":"attacker"}}`, and `X-Hub-Signature` computed with `attacker-org`'s known `webhook_secret`.

No guard prevents this: `drop_unhandled_event` only checks the event type exists in the handler registry [7](#0-6) ; `ExplicitParameters` schemas in handlers (e.g. `OpenedHandler.params`) validate shape/types of `repository.full_name` but do not cross-check it against the owner used for signing [8](#0-7) ; `Handler#initialize` just re-parses the same untrusted payload [9](#0-8) .

### Impact Explanation
A `ReviewStack` (and its underlying `Stack`/branch/environment) gets provisioned against `victim-org/prod-repo` purely from a payload signed by an unrelated organization's secret — the attacker's own. This is a cross-repository write triggered by a payload that never authenticated against the victim organization at all, matching the Critical category "a payload for one repository mutating another's stack." It is repeatable against any repository with `review_stacks_enabled` and `provisioning_behavior_allow_all?` (or satisfying the label-based provisioning conditions), as long as the attacker controls at least one configured GitHub organization/secret in `Shipit.github`.

### Likelihood Explanation
Requires: (1) attacker controls a `webhook_secret` for *some* org configured in `Shipit.github` — realistic in multi-tenant Shipit deployments where organizations self-onboard and each org's `webhook_secret` is independently known to that org's admins; (2) the victim repository has review stacks enabled with an auto-provisioning policy. Both are plausible operational configurations, and the attack costs a single crafted HTTP POST with a known signature — no guessing, no brute force, fully deterministic and repeatable.

### Recommendation
In `verify_signature`, after selecting the `GitHubApp` by `repository_owner`, additionally verify that `repository_owner` matches the owner segment of `params.dig('repository','full_name')` (reject if they diverge). More robustly, resolve the target `Repository` first and verify the signature using the secret associated with that repository's actual owning organization, rather than trusting an attacker-supplied `owner.login` field to pick the verification key.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual, no live GitHub required)
test "cross-org signature confusion mutates victim repository's review stacks" do
  # Setup: two configured orgs in Shipit.github config: 'attacker-org' (secret known to attacker)
  # and 'victim-org' (secret unknown to attacker). Repository 'victim-org/prod-repo' exists with
  # review_stacks_enabled: true, provisioning_behavior: allow_all.

  body = {
    action: 'opened',
    number: 42,
    repository: { owner: { login: 'attacker-org' }, full_name: 'victim-org/prod-repo' },
    pull_request: { id: 1, number: 42, url: 'x', title: 't', state: 'open',
                     additions: 1, deletions: 0, head: { sha: 'abc', ref: 'feature' },
                     user: { login: 'attacker' }, assignees: [], labels: [] },
    sender: { login: 'attacker' }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest('sha1', attacker_org_webhook_secret, body)

  assert_no_difference -> { Shipit::ReviewStack.where(stack_type: 'victim-org/prod-repo').count rescue 0 } do
    # binding check BEFORE: repository_owner ('attacker-org') != full_name owner ('victim-org')
  end

  post shipit.webhooks_path, params: body, headers: {
    'X-Github-Event' => 'pull_request',
    'X-Hub-Signature' => signature,
    'CONTENT_TYPE' => 'application/json'
  }

  assert_response :ok
  # binding check AFTER: a ReviewStack was created under victim-org/prod-repo despite
  # signature having been verified with attacker-org's secret — equality was never enforced.
  assert Shipit::Repository.from_github_repo_name('victim-org/prod-repo').review_stacks.exists?(environment: 'pr42')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L21-24)
```ruby
        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end
```
