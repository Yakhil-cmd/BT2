### Title
Signature verification org (`repository.owner.login`) diverges from the mutated repository (`repository.full_name`), and `provision?`'s operator precedence lets label-based provisioning bypass `review_stacks_enabled` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret using `repository.owner.login` while `OpenedHandler#repository` resolves the mutated `Shipit::Repository` using the unrelated `repository.full_name` field, so an attacker can pick a configured-but-secretless org for signature checking while pointing `full_name` at a victim repository the attacker doesn't own. Independently, `OpenedHandler#provision?` only ANDs `review_stacks_enabled` with the `allow_all` branch, so `provisioning_behavior_allow_with_label?`/`provisioning_behavior_prevent_with_label?` branches provision review stacks even when `review_stacks_enabled` is `false`.

### Finding Description
The broken binding: the code implicitly assumes `params.dig('repository','owner','login') == Shipit::Repository.from_github_repo_name(params.repository.full_name).owner`, but nothing enforces this equality.

- `Shipit::WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` reads `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org's `webhook_secret` is blank: `return true unless webhook_secret` [3](#0-2) .
- Once past `verify_signature`, `OpenedHandler#repository` resolves the *actual* repository being mutated using a completely different payload field, `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name` [4](#0-3) [5](#0-4) .
- `process` then calls `ReviewStackAdapter#find_or_create!`, which creates a `ReviewStack` (`branch: params.pull_request.head.ref`, `environment: "pr#{params.number}"`) scoped to `repository.review_stacks` [6](#0-5) [7](#0-6) .
- Separately, `provision?` is written as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)` [8](#0-7) . Ruby's `&&`/`||` precedence means `review_stacks_enabled` only gates the `allow_all` term; the `allow_with_label` and `prevent_with_label` terms are evaluated independent of `review_stacks_enabled`. This is directly confirmed by the existing test suite, where `configure_provisioning_behavior` tests for `allow_with_label`/`prevent_with_label` never set `provisioning_enabled: false` and still expect stack creation [9](#0-8) , and the one existing negative test that disables provisioning uses `behavior: :allow_all` specifically [10](#0-9)  — there is no test covering `review_stacks_enabled: false` combined with `allow_with_label`/`prevent_with_label`, which is exactly the untested gap that the precedence bug creates.

Exploit flow: an attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, `action: "opened"`, `repository.owner.login` set to an org configured in Shipit that has no `webhook_secret` set, and `repository.full_name` set to `victim-org/victim-repo` (a repo whose owning org does have a secret and whose `provisioning_behavior` is `allow_with_label` or `prevent_with_label`, with `review_stacks_enabled` set to `false`). `verify_signature` passes trivially because the secretless org is checked. `OpenedHandler` resolves `victim-org/victim-repo`'s `Repository` row via `full_name`, and `provision?` returns `true` despite `review_stacks_enabled == false`, provisioning an unauthorized `ReviewStack`/`branch`/`environment` for the victim repository, using attacker-supplied `pull_request.head.ref` and PR metadata.

### Impact Explanation
This lets an unauthenticated/unprivileged sender forge a webhook that is authenticated against one organization's (secretless) config but mutates a completely different repository's `ReviewStack` state — a write for a repository/org that did not authenticate the request, matching the "payload for one repository mutating another's stack" Critical class. The provisioned `ReviewStack` triggers `Shipit::ReviewStackProvisioningQueue.add(stack)`, which drives downstream provisioning/deploy tooling for the victim repo using attacker-controlled `branch` and `sender` values, on a repo whose operator explicitly disabled review-stack auto-provisioning. This is repeatable against any repository whose owning org has `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` and where at least one org known to Shipit lacks a `webhook_secret`.

### Likelihood Explanation
Preconditions: (1) Shipit must know of at least one org with a blank `webhook_secret` (plausible in multi-org deployments, e.g., a low-security/test org configured alongside production orgs), (2) the victim repository must have `review_stacks_enabled: false` with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (a real, documented configuration option, not a corner case) [11](#0-10) . Given these, the attack costs a single unauthenticated HTTP POST with no signature needed, and is fully repeatable/scriptable against any matching repository.

### Recommendation
1. In `verify_signature`, derive the authenticating organization from the same repository record that will be mutated (i.e., resolve `Repository.from_github_repo_name(params.repository.full_name)` first and use its `owner`), not from the untrusted `repository.owner.login` field, and reject if the two disagree.
2. In `GitHubApp#verify_webhook_signature`, do not silently return `true` when `webhook_secret` is blank for orgs that own tracked repositories — require an explicit "no webhook auth" configuration flag or reject unsigned requests.
3. Fix `OpenedHandler#provision?` so `review_stacks_enabled` gates ALL provisioning behaviors, not just `allow_all`, e.g. `repository.review_stacks_enabled && (allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?))`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "pull_request opened event authenticated by one org cannot provision a different org's review stack" do
  # victim repo belongs to org with a real secret and disabled review stacks but label-based behavior
  victim = shipit_repositories(:shipit) # owner e.g. "shopify"
  victim.update!(
    review_stacks_enabled: false,
    provisioning_behavior: :prevent_with_label,
    provisioning_label_name: "no-deploy"
  )

  # attacker-controlled payload: owner.login names a secretless org, full_name points at victim
  payload = payload_parsed(:pull_request_opened)
  payload["repository"]["owner"]["login"] = "secretless-org" # configured org w/ blank webhook_secret
  payload["repository"]["full_name"] = victim.github_repo_name
  payload["pull_request"]["labels"] = [] # satisfies prevent_with_label (no label present)

  assert_difference -> { victim.review_stacks.count }, 1 do
    post shipit.webhooks_path,
      params: payload.to_json,
      headers: { 'X-Github-Event' => 'pull_request', 'Content-Type' => 'application/json' }
      # no X-Hub-Signature needed because "secretless-org" has no webhook_secret
  end
  assert_response :ok
end
```
Assert on both sides of the binding: `payload["repository"]["owner"]["login"]` (the org used for `verify_signature`) `!=` `Shipit::Repository.from_github_repo_name(payload["repository"]["full_name"]).owner` (the org actually mutated), and that despite `victim.review_stacks_enabled == false`, `victim.review_stacks.count` increases by 1 after the request.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-98)
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

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end

          def environment
            "pr#{params.number}"
          end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L96-107)
```ruby
          test "only provision stacks for repos with auto-provisioning enabled" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              provisioning_enabled: false,
              behavior: :allow_all
            )

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload_parsed(:provision_disabled_pull_request)).process
            end
          end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L129-172)
```ruby
          test "creates stacks for repos that allow_with_label when label is present" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :allow_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          test "does not create stacks for repos that allow_with_label when label is absent" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :allow_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = []

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          test "create stacks for repos what prevent_with_label when label is absent" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = []

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end
```
