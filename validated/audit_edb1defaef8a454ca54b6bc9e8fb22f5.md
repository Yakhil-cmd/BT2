Confirmed: `Repository.from_github_repo_name` looks up purely by `owner`/`name` parsed from `params.repository.full_name`, with no cross-check against `repository_owner` used during signature verification. This confirms the decoupling of the two fields is real and unguarded anywhere in the code path.

### Title
Webhook signature verification is keyed on `repository.owner.login`, but repository mutation is keyed on the independently-attacker-controlled `repository.full_name`, allowing cross-org forgery of PullRequest events - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to validate a webhook against using `params.dig('repository', 'owner', 'login')`, while every PullRequest handler (e.g. `OpenedHandler#repository`) resolves the target `Shipit::Repository` using the separate, independently attacker-suppliable `params.repository.full_name` field [1](#0-0) . Because these two JSON fields are never checked for consistency, an attacker POSTing directly to `/webhooks` can pick an org whose GitHub App has no `webhook_secret` configured for the `owner.login`/signature check, while pointing `repository.full_name` at a completely different, victim-owned repository whose review-stack provisioning rules then get evaluated and mutated.

### Finding Description
Binding that should hold: `repository_owner` (the org used to select the `GitHubApp` and enforce `verify_webhook_signature`) must equal the owner encoded in `params.repository.full_name` (the org whose `Repository`/`review_stacks` scope is written to). In code this is:
```
Equality required: params.dig('repository','owner','login') == params.repository.full_name.split('/').first
```

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` (or `organization.login`) and calls `Shipit.github(organization: repository_owner)` [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for that org's config [3](#0-2) . Multiple documented/example Shipit configurations show `webhook_secret: # nil` as a legitimate per-org config value in multi-org setups [4](#0-3) .
3. Once `head(422) unless verified` passes, `WebhooksController#create` dispatches the *entire, attacker-controlled* `params` (not scoped to the verifying org) to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .
4. `OpenedHandler#repository` resolves the model purely via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, which parses `owner/name` straight out of that field with zero relation to `repository_owner` used above [6](#0-5) , [7](#0-6) .
5. `provision?` then evaluates against the resolved victim `Repository`'s real `provisioning_behavior_prevent_with_label?`/label config [8](#0-7) .
6. If true, `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` runs `create!`, writing a new row into the victim repository's `review_stacks` association using attacker-chosen `branch: params.pull_request.head.ref` and PR metadata, then immediately calls `Shipit::ReviewStackProvisioningQueue.add(stack)` [9](#0-8) , which calls `stack.enqueue_for_provisioning` [10](#0-9) , scheduling real provisioning work against a Stack the attacker fabricated for a foreign repository.

Why existing guards fail: `verify_signature` only proves the request was (or, if `webhook_secret` is blank for the chosen org, wasn't even) authenticated *for the org named in `repository.owner.login`* — it makes no claim about, and never re-checks, the `repository.full_name` field the handlers actually act on. `ExplicitParameters` only enforces types/presence of `repository.full_name`, not that it matches `repository.owner.login` or the org used for signature verification. No model validation or scope ties `Repository#review_stacks` writes back to the verified org.

### Impact Explanation
An attacker who can get one org's GitHub App configured in Shipit to have a blank/absent `webhook_secret` (a state the codebase's own example configs and multi-org docs treat as a normal, supported state) can forge fully-signed-looking webhooks that mutate **any other org's** repositories tracked by the same Shipit instance: creating brand-new `ReviewStack` records, enqueuing them for provisioning (`ReviewStackProvisioningQueue.add`), and seeding `branch`/`environment`/PR association values entirely from attacker input. This is a cross-tenant write executed without any authentication tied to the actual target repository, matching the Critical category ("a payload for one repository mutating another's stack ... or an unauthorized deploy"). It is repeatable against every repository tracked by Shipit as long as at least one configured org lacks a `webhook_secret`, and the downstream provisioning queue can go on to execute real deploy `Command`s against attacker-influenced branch refs.

### Likelihood Explanation
This requires a specific but realistic operational precondition: Shipit must be configured with at least one GitHub App entry (in the `github:` multi-org secrets hash) whose `webhook_secret` is blank. This is not a purely hypothetical state — the shipped example configs (`config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`) all model `webhook_secret: # nil` as valid, and operators onboarding additional orgs incrementally can easily leave a new entry without a secret set while GitHub Apps for other orgs are already fully configured. Given that precondition, exploitation costs the attacker only a single crafted HTTP POST to `/webhooks` with attacker-chosen JSON — no GitHub webhook delivery, no valid HMAC, and no Shipit credentials are needed at all. It is fully repeatable and requires no interaction with the victim repository or its actual owning org.

### Recommendation
Bind the org resolved from `repository.full_name` (and any other repository-bearing fields used by handlers) to the same `repository_owner` value used for `verify_webhook_signature`, and reject the request if they differ — regardless of whether the resolved org's `webhook_secret` is present. Additionally, treat a blank/unset `webhook_secret` for any configured org as a hard misconfiguration (refuse to boot or log loudly) rather than silently downgrading to `verify_webhook_signature` returning `true`.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb` style):
```ruby
test "cross-org forgery: unauthenticated org's payload cannot mutate a different org's repository" do
  # Victim repository, real org "shopify", prevent_with_label, no provisioning label on PR
  victim_repo = shipit_repositories(:shipit) # owner: "shopify"
  victim_repo.update!(review_stacks_enabled: true, provisioning_behavior: :prevent_with_label,
                       provisioning_label_name: "no-provision")

  # Configure a second org "org-with-no-secret" with webhook_secret nil, distinct from "shopify"
  Shipit.stubs(:github_app_config).with('org-with-no-secret').returns(app_id: 1, installation_id: 1, private_key: 'x', webhook_secret: nil)

  payload = JSON.parse(payload(:pull_request_opened))
  payload["repository"]["owner"]["login"] = "org-with-no-secret" # used only for signature check
  payload["repository"]["full_name"] = victim_repo.full_name      # "shopify/shipit-engine" - actually mutated

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/invalid, irrelevant because secret is blank

  assert_difference -> { victim_repo.review_stacks.count }, 1 do
    assert_enqueued_with(job: nil) do # or assert ReviewStackProvisioningQueue.expects(:add)
      post :create, body: payload.to_json, as: :json
    end
  end
  assert_response :ok
end
```
Assertions on both sides of the binding:
- Before: `repository_owner` (verified) = `"org-with-no-secret"`; repository actually written to = `victim_repo` whose `owner` = `"shopify"`. These differ.
- After: `victim_repo.review_stacks.count` increased by 1, and `ReviewStackProvisioningQueue.add` was invoked for a stack under `victim_repo` — despite the verified org never being `"shopify"`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-11)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
    end
```
