### Title
Cross-organization webhook forgery via `WebhooksController#verify_signature` / `PullRequest::OpenedHandler#repository` binding mismatch - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate a webhook against using `repository.owner.login` from the untrusted JSON body, while every `PullRequest::*Handler` resolves the repository/Stack to mutate using the completely independent `repository.full_name` field from the same body. Because `GithubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatically valid, an attacker who can name any Shipit-configured organization that has no secret configured can pass signature verification while pointing the payload's `repository.full_name` (and `pull_request.head/base.repo.full_name`) at a completely different, secret-protected organization's real repository/Stack.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces: `repository_owner` (used in `verify_signature`) == `owner(params.repository.full_name)` (used by every `PullRequest::*Handler#repository`). These two values are independently attacker-controlled inside the same JSON body and are never cross-checked.

- `WebhooksController#verify_signature` derives the signing organization purely from the payload: `params.dig('repository', 'owner', 'login')`, then does `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
- `GithubApp#verify_webhook_signature` short-circuits to `true` whenever the resolved organization's `webhook_secret` is blank: `return true unless webhook_secret`. [3](#0-2) 
- The `create` action then dispatches the raw, still-unverified-against-the-target-org body to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [4](#0-3) 
- Every relevant PullRequest handler (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `LabelCapturingHandler`) resolves the target repository strictly from `params.repository.full_name`, never from `repository_owner`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)`. [5](#0-4) [6](#0-5) 
- `ReviewStackAdapter#find_or_create!`/`#archive!`/`#unarchive!` then create or mutate a `Stack`/`PullRequest` scoped to that resolved repository, using attacker-supplied branch/labels/head sha etc. [7](#0-6) 

Exploit flow: attacker sends `POST /webhooks` with header `X-Github-Event: pull_request` and a body where `repository.owner.login = "orgA"` (an organization configured in Shipit's multi-org `github:` config with `webhook_secret: nil`, e.g. as shown in the documented multi-org example config) and `repository.full_name = "orgB/real-repo"`, `pull_request.head.repo.full_name`/`base.repo.full_name` also pointing at org B. `verify_signature` resolves `Shipit.github(organization: "orgA")`, finds no secret, and returns `true` unconditionally — no `X-Hub-Signature` is even required to be correct. The handler then processes the payload as an authentic event for org B's tracked repository, creating/mutating `Shipit::PullRequest` and `Shipit::Stack` rows, and can archive/unarchive review Stacks and enqueue `GithubSyncJob`/provisioning jobs against org B's real infrastructure. [8](#0-7) 

Existing guards do not stop this: `drop_unhandled_event` only filters unknown event types, not payload consistency; the `ExplicitParameters` schema (`requires :repository { requires :full_name }`) only validates types/presence, not that `full_name`'s owner matches `repository.owner.login`; `GithubOrganizationUnknown` is raised only if the org name is entirely unconfigured, not if it is configured without a secret. [9](#0-8) 

### Impact Explanation
Any Shipit deployment using per-organization webhook configuration (as documented) where at least one configured organization lacks a `webhook_secret` allows an unauthenticated attacker to forge `pull_request` (and by the same mechanism, other) webhooks that create, archive, unarchive, or otherwise mutate `PullRequest`/`Stack` records belonging to any *other* configured organization's tracked repository — a payload "verified" against org A mutating org B's Stack, matching the Critical category explicitly listed in scope. This is repeatable per request against any repository tracked by Shipit, is not rate-limited by any authentication, and can trigger downstream side effects such as `ReviewStackProvisioningQueue` enqueues and `GithubSyncJob` scheduling against org B's real GitHub state. [10](#0-9) 

### Likelihood Explanation
Requires: (1) Shipit configured with multiple GitHub organizations (documented, supported feature — `config/secrets.development.shopify.yml` shows exactly this pattern with `webhook_secret: # nil` for both orgs), and (2) at least one configured organization left without a `webhook_secret`. [11](#0-10)  Given the setup docs describe `webhook_secret` as optional ("If you've set a webhook secret during the App creation, you should copy it here"), this is a realistic and low-cost misconfiguration, not a theoretical one — no secrets, tokens, or privileged access are required by the attacker, only knowledge of one org's name that lacks a secret. [12](#0-11) 

### Recommendation
In `WebhooksController#verify_signature`, after determining `repository_owner`, additionally verify that every organization referenced inside the payload (`repository.full_name`'s owner, `pull_request.head.repo.full_name`'s owner, `pull_request.base.repo.full_name`'s owner) is identical to `repository_owner`, rejecting the request otherwise. Additionally, do not treat a missing `webhook_secret` as automatically valid in `GithubApp#verify_webhook_signature`; require an explicit "unsigned" opt-in flag per organization instead of silently trusting any payload when a secret is absent.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "pull_request payload naming secret-less org A mutates org B's stack" do
  # org B has a real, secret-protected app and an existing tracked repository/stack
  org_b_repo = shipit_repositories(:shipit) # e.g. "shopify/shipit-engine"
  org_b_repo.update!(review_stacks_enabled: true, provisioning_behavior: :allow_all)

  Shipit.stubs(:github).with(organization: "org-a-no-secret").returns(
    Shipit::GithubApp.new("org-a-no-secret", { webhook_secret: nil })
  )

  payload = JSON.parse(payload(:pull_request_opened))
  payload["repository"]["owner"]["login"] = "org-a-no-secret" # binding claimed by verify_signature
  payload["repository"]["full_name"] = org_b_repo.github_repo_name # binding actually mutated

  request.headers["X-Github-Event"] = "pull_request"
  request.headers["X-Hub-Signature"] = "sha1=deadbeef" # arbitrary/incorrect signature

  assert_difference -> { Shipit::PullRequest.count }, 1 do
    post :create, body: payload.to_json, as: :json
  end

  assert_response :ok
  # equality broken: verifying org ("org-a-no-secret") != stack-owning org (org_b_repo.owner)
  assert_not_equal "org-a-no-secret", org_b_repo.owner
  assert org_b_repo.stacks.reload.exists?, "expected org B's Stack to be created/mutated"
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

**File:** app/controllers/shipit/webhooks_controller.rb (L39-49)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-50)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
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
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```
