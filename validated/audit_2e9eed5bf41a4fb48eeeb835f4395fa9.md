### Title
Webhook signature verified against `repository.owner.login`/`organization.login` while all handlers act on the unauthenticated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/organization used to check the HMAC signature from one payload field, while every webhook handler (`Handler#stacks`/`#repository_name`, `PushHandler`, `PullRequest::ReviewStackAdapter`, etc.) resolves the repository/stack it operates on from a *different* field of the same, otherwise-unverified JSON body. Nothing binds these two fields together, so an org whose webhook secret is known to the caller can be used to authenticate a payload that actually targets a completely different (victim) repository.

### Finding Description
`verify_signature` computes the organization used for signature verification like this: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (or `organization.login`) from the **same untrusted, attacker-supplied JSON body** that is later processed. `Shipit.github(organization: repository_owner)` looks up a per-organization `GitHubApp` instance keyed by that organization name, each with its own independently configured `webhook_secret`: [3](#0-2) 

Signature verification itself only checks that the HMAC-SHA1 of the raw body matches the secret configured for that organization: [4](#0-3) 

Once verification passes, `create` dispatches the *entire, unauthenticated* payload to the registered handlers: [5](#0-4) 

But every handler resolves which `Repository`/`Stack` to act on from `payload.dig('repository', 'full_name')` — a field that has no relationship to `repository_owner` used for signature selection: [6](#0-5) 

`PushHandler` uses this to trigger a resync with an attacker-chosen `expected_head_sha`: [7](#0-6) 

More critically, `PullRequest::OpenedHandler`/`ReviewStackAdapter` create a brand-new `ReviewStack` for `params.repository.full_name` whose `branch` is taken directly from attacker-controlled `pull_request.head.ref`, and whose PR head sha comes straight from the payload, with no cross-check against the org used for signing: [8](#0-7) [9](#0-8) 

**Equality broken:** the engine implicitly assumes `organization(repository.owner.login) == organization(repository.full_name)`, but nothing enforces it. An attacker who controls (owns/administers) *any* organization onboarded to this multi-tenant Shipit instance — i.e., knows only their *own* org's `webhook_secret` in `secrets.github.<their_org>` — can:
1. Set `repository.owner.login` (or `organization.login`) to their own org, so `verify_signature` selects their own `GitHubApp`/secret and the HMAC check passes.
2. Set `repository.full_name` to `victim-org/victim-repo`, causing `Handler#stacks`/`ReviewStackAdapter` to look up and act on a `Stack`/`Repository` belonging to a completely different organization whose secret they never had.

### Impact Explanation
This breaks the deployment-trust binding "an organization that authenticated versus the repository that is written." Depending on the handler triggered, the attacker can: force `sync_github` resyncs against a victim stack with attacker-chosen `expected_head_sha`, and — most seriously — provision a new `ReviewStack` (and its associated deploy/task execution machinery) under the victim repository with a `branch`/head that is entirely attacker-supplied. Since review stack provisioning subsequently checks out and runs `shipit.yml` steps for that branch/sha via `Shipit::ReviewStackProvisioningQueue`, this can lead to command execution on the deploy host against a victim's repository/stack that the attacker never had legitimate write or webhook access to — an unauthorized deploy/provisioning action and a cross-repository write. This satisfies the Critical impact bar ("cross-repository writes" / "an unauthorized deploy").

### Likelihood Explanation
The `/webhooks` endpoint is a public, unauthenticated HTTP endpoint by design (it's meant to receive GitHub-originated JSON). The only barrier is the HMAC signature, and this design flaw means an attacker only needs the webhook secret for *any org they legitimately control* on a multi-tenant Shipit install (the per-org GitHub App config shown in `Shipit.github_app_config`), not the victim's secret. No Shipit session, ApiClient token, or GitHub App private key of the victim is required — only knowledge of a secret the attacker legitimately possesses for their own onboarded organization. This is realistic wherever Shipit is deployed with multiple independent orgs each installing their own GitHub App (the exact scenario the per-org keyed config in `lib/shipit.rb#github_app_config` is built for).

### Recommendation
Bind the field used to select the verification secret to the field used for repository resolution: after determining `repository_owner`, verify that `Repository.from_github_repo_name(payload.dig('repository','full_name'))`'s owner matches `repository_owner` (and same for `organization.login` events) before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
1. Attacker legitimately administers `attacker-org`, which is onboarded to this Shipit instance with its own GitHub App and its own `webhook_secret` (`secrets.github.attacker-org.webhook_secret`), known to the attacker.
2. Attacker crafts a `pull_request` (or `push`) JSON payload where:
   - `repository.owner.login = "attacker-org"` (or `organization.login = "attacker-org"`)
   - `repository.full_name = "victim-org/victim-repo"`
   - `pull_request.head.ref` / `sha` = attacker-chosen values
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org's webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: pull_request`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature using the attacker's own secret.
5. `create` dispatches the payload to `PullRequest::OpenedHandler`, which resolves `repository` via `params.repository.full_name` = `victim-org/victim-repo`, and (if provisioning is enabled for that repo) creates a `ReviewStack` with `branch: params.pull_request.head.ref`, queuing it for provisioning/deployment — all without ever having presented `victim-org`'s webhook secret.

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
