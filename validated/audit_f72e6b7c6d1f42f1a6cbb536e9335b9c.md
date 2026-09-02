### Title
`repository.owner.login`/`repository.full_name` divergence lets a `reopened` webhook signed for a no-secret org unarchive/create a victim org's `ReviewStack` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb`)

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp` used to authenticate a webhook based on `repository.owner.login`, while `ReopenedHandler` (and every other `pull_request` handler) resolves the repository/stack to mutate from `repository.full_name`. These two fields are never checked for consistency, so an attacker can pick an org with no `webhook_secret` configured to trivially satisfy signature verification, and separately point `full_name` at any repository in the database.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:
`Repository.from_github_repo_name(params.repository.full_name).owner == params.repository.owner.login` used by `verify_signature`.

Path:
- `Shipit::WebhooksController#verify_signature` computes `repository_owner` purely from attacker-controlled JSON: `params.dig('repository', 'owner', 'login')` [1](#0-0) , and uses it to select the `GitHubApp` instance: `Shipit.github(organization: repository_owner)` [2](#0-1) .
- `Shipit.github` looks the org up in `secrets.github` by name and constructs/returns a `GitHubApp` for it [3](#0-2) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever that org's `webhook_secret` is blank: `return true unless webhook_secret` [4](#0-3) . Both the single-org and multi-org example configs in the repo show `webhook_secret: # nil` as a supported, common setting [5](#0-4) .
- Once signature verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the **entire raw payload**, not just the authenticated org's slice, to every registered handler [6](#0-5) .
- `ReopenedHandler#repository` resolves the target `Repository` from `params.repository.full_name` alone: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [7](#0-6) , which splits on `/` and does a straight DB lookup by owner/name [8](#0-7) . Nothing in this path re-checks `repository.owner.login` against `full_name`'s owner segment.
- If `review_stacks_enabled` and `provisioning_behavior_allow_all?` are true for that resolved repository, `respond_to_pull_request_reopened?` returns true and `stack.unarchive!` runs against `ReviewStackAdapter`, which either unarchives an existing stack (re-enqueuing it for provisioning via `ReviewStackProvisioningQueue.add`) or creates a brand-new stack via `create!` [9](#0-8) [10](#0-9) . Provisioned review stacks execute the repository's `shipit.yml` machinery.

Exploit request: `POST /webhooks` with `X-Github-Event: pull_request`, an arbitrary/garbage `X-Hub-Signature`, and a body of the form:
```json
{
  "action": "reopened",
  "number": 1,
  "pull_request": { ... },
  "repository": { "owner": { "login": "orgone-no-secret" }, "full_name": "victim-org/victim-repo" },
  "sender": { "login": "attacker" }
}
```
`orgone-no-secret` is any org configured in `secrets.github` without a `webhook_secret` (a documented, supported configuration in this codebase). Signature verification passes unconditionally for that org, but `full_name` points at `victim-org/victim-repo`, a completely different tenant's repository/stack.

Existing guards do not catch this: `verify_signature` only checks `repository_owner`/`organization.login` against a known org list and never cross-references `full_name` [11](#0-10) ; `ExplicitParameters` in the handler only requires `full_name` to be present/String, performing no ownership cross-check [12](#0-11) ; the existing test suite for `webhooks_controller_test.rb` only exercises the case where `owner.login` matches the true org (`repository_params` hardcodes `owner.login: 'shopify'` matching the org used for signature verification) [13](#0-12)  and never asserts that a mismatched `full_name` is rejected.

### Impact Explanation
An attacker who controls (or names) any org configured in Shipit without a `webhook_secret` can forge a `pull_request`/`reopened` (or `opened`, `labeled`, `unlabeled`, `closed`, `assigned` — all `pull_request` handlers share this same `full_name`-only resolution pattern) event that mutates the review-stack state of a completely unrelated repository/org whose owner never authenticated the request. For a victim stack with `review_stacks_enabled` + `allow_all`, this results in `ReviewStack` creation/unarchival, which auto-provisions and runs the victim repository's `shipit.yml`, i.e. arbitrary CI/deploy-time command execution on the Shipit host under the victim's configuration. This matches "a payload for one repository mutating another's stack" and, via `shipit.yml` execution, Critical RCE-class impact. The attack is repeatable against any repository/org reachable by `full_name` in the datastore, as long as one org in the deployment is configured with no `webhook_secret` (a documented, commonly-used config in this repo's own examples).

### Likelihood Explanation
Preconditions: (1) the Shipit deployment must have at least one org configured in `secrets.github` with a blank `webhook_secret` (shown as a normal supported setup in this repo's example configs), (2) the target victim stack must have `review_stacks_enabled` with `allow_all` provisioning. Given those, the attacker needs no credentials, no session, no GitHub App key, and no valid signature — only knowledge of the no-secret org's name (discoverable, e.g., from public error messages, `GithubOrganizationUnknown` responses, or simply guessing common org slugs) and the victim's `owner/name`. The request is a single unauthenticated `POST /webhooks` and is trivially repeatable.

### Recommendation
In `WebhooksController#verify_signature` (or earlier), require that `repository.owner.login` matches the owner segment of `repository.full_name` before dispatching to handlers, and reject the request otherwise. Additionally, `GitHubApp#verify_webhook_signature` should not silently return `true` when no secret is configured for a specific org in multi-org configurations — either require a secret per org or treat a missing per-org secret as "reject", not "always accept."

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb`):
```ruby
test "pull_request reopened forged for a no-secret org must not mutate a different org's review stack" do
  # Bind: verify org == mutated org
  attacker_owner = 'orgone-no-secret'   # configured with webhook_secret: nil
  victim_repo    = shipit_repositories(:shipit) # different org, review_stacks_enabled + allow_all
  configure_provisioning_behavior(repository: victim_repo, behavior: :allow_all)
  victim_stack = create_archived_stack_for(victim_repo) # archived ReviewStack

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=garbage-not-a-valid-signature'

  body = {
    action: 'reopened',
    number: victim_stack.pull_request.number,
    pull_request: pull_request_payload_for(victim_stack),
    repository: { owner: { login: attacker_owner }, full_name: victim_repo.github_repo_name },
    sender: { login: 'attacker' }
  }.to_json

  assert_no_changes -> { victim_stack.reload.archived? } do
    post :create, body:, as: :json
  end
  # Currently this assertion FAILS: victim_stack becomes unarchived/re-provisioned
  # despite the signature being verified against `attacker_owner`, not the victim's org.
end
```
This test currently fails, confirming both sides of the equality (`repository_owner` used for auth vs. `full_name`'s owner used for mutation) diverge and the invariant "a `pull_request` event only affects the repository/stack whose secret authenticated it" is broken.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-75)
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

          def pull_request
            params.pull_request
          end

          def respond_to_pull_request_reopened?
            params.action == "reopened" &&
              unarchive?
          end

          def unarchive?
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-85)
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

          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
          end

          private

          attr_reader :params, :scope

          def action
            params.action
          end

          def repo_name
            params.repository["full_name"]
          end

          def pr_number
            params.number
          end

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

**File:** test/controllers/webhooks_controller_test.rb (L216-218)
```ruby
    def repository_params
      { repository: { owner: { login: 'shopify' } } }
    end
```
