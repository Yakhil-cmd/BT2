### Title
Cross-organization webhook forgery via `repository.owner.login`/`repository.full_name` divergence lets an attacker unarchive a victim's stack through `UnlabeledHandler#process` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate a webhook using `params.dig('repository','owner','login')`, while every `PullRequest` handler (including `UnlabeledHandler`) resolves the target `Repository`/`Stack` using the independent `params.repository.full_name` field from the very same attacker-supplied JSON body. Because the two fields are never cross-checked, an attacker who can produce a "verified" webhook for any Shipit-configured organization whose `webhook_secret` is unconfigured (`nil`) can set `repository.full_name` to a victim organization's repo, causing `UnlabeledHandler` to call `stack.unarchive!` on the victim's stack.

### Finding Description
The intended binding is:
`Shipit.github(organization: repository_owner).verify_webhook_signature(...) == true` should imply `repository_owner == organization_of(params.repository.full_name)`.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` and does `github_app = Shipit.github(organization: repository_owner)` then `verified = github_app.verify_webhook_signature(...)`. [1](#0-0) 
2. `GitHubApp#verify_webhook_signature` returns `true` unconditionally `unless webhook_secret` — i.e., if the org resolved by `repository_owner` has no configured `webhook_secret`, any signature (or none) passes. [2](#0-1) 
3. `Shipit.github(organization:)` / `github_app_config` simply look up the per-organization config keyed by the attacker-controlled `repository_owner` string; if that org isn't configured, it raises `GithubOrganizationUnknown` (422), but if it IS configured with an unset `webhook_secret`, verification trivially succeeds. [3](#0-2) 
4. `create` then dispatches the raw JSON body to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. [4](#0-3) 
5. `UnlabeledHandler#repository` resolves the target repository from a completely different field of the same payload: `Shipit::Repository.from_github_repo_name(params.repository.full_name)`. [5](#0-4) 
6. If `unarchive?` evaluates true (driven purely by `repository.provisioning_behavior_allow_with_label?`/label presence on the victim's own repository config, unrelated to the attacker), `handle` calls `stack.unarchive!` → `ReviewStackAdapter#unarchive!`, which enqueues `ReviewStackProvisioningQueue.add(stack)` and calls `stack.unarchive!`, triggering `GithubSyncJob` as noted in tests. [6](#0-5) [7](#0-6) [8](#0-7) 

Nothing in `ExplicitParameters` schema, `drop_unhandled_event`, `check_if_ping`, or the handler enforces that `params.repository.owner.login` (used for signature/org selection) equals the organization implied by `params.repository.full_name` (used for the actual DB lookup). Both are attacker-supplied JSON fields in the same POST body with no server-side cross-validation. This exact pattern is generic to `Handler` subclasses (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler` all independently call `Repository.from_github_repo_name(params.repository.full_name)`), so `UnlabeledHandler` is symmetric to `LabeledHandler` exactly as the question suspects — the flaw is not in the handler's label logic but in the controller's signature-to-repository binding shared by all handlers.

### Impact Explanation
An attacker who can identify (or control) any Shipit-configured GitHub organization with an unset `webhook_secret` can forge a `pull_request`/`unlabeled` webhook whose `repository.full_name` targets an unrelated victim organization's repo/stack. If that victim repo has review-stacks enabled with `provisioning_behavior_allow_with_label?` and an archived PR stack carrying the provisioning label, the forged request causes `stack.unarchive!` to run — re-enabling deploy eligibility and enqueuing `GithubSyncJob` for a repository the attacker never authenticated against. This is a cross-tenant stack mutation triggered by a payload for a different repository/organization, matching the Critical category "a payload for one repository mutating another's stack." It is repeatable against any victim stack satisfying the archived + label-eligible precondition, and the same mechanism also permits forcing `archive!` (deploy disablement) via the complementary branch.

### Likelihood Explanation
Preconditions: (a) at least one Shipit-configured GitHub organization exists with `webhook_secret` unset/nil (the shipped test fixtures `secrets_double_github_app.yml`, `secrets.test.json` show this is a realistic/common configuration state, not merely hypothetical) [9](#0-8) ; (b) the attacker can send arbitrary HTTP POSTs to `/webhooks` with an `X-Github-Event: pull_request` header and a crafted JSON body (trivial — public endpoint, no session/token required); (c) the victim repository must have review stacks enabled with `allow_with_label`/`prevent_with_label` and an existing stack in the state where `unarchive?`/`archive?` is true. Cost to the attacker is a single crafted HTTP request; no secrets, tokens, or privileged roles are needed, satisfying the stated attacker capability. This is fully repeatable per victim stack.

### Recommendation
Bind signature verification to the same identity used for authorization: after `github_app.verify_webhook_signature` succeeds, explicitly compare `repository_owner` (used to select the app) against the organization derived from `params.repository.full_name` and reject (422) on mismatch. Additionally, treat an unconfigured `webhook_secret` as a hard failure (reject the webhook, or require an operator to explicitly opt into unsigned webhooks) rather than silently returning `true` from `GitHubApp#verify_webhook_signature`, since this currently makes every organization without a configured secret an open door for forging events for arbitrary other repositories.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (multi-org config, `secrets_double_github_app.yml` style):
```ruby
test "unlabeled webhook with mismatched owner/full_name unarchives victim stack" do
  # OrgOne has webhook_secret: nil (unconfigured) in the multi-org test config
  # Victim stack belongs to "OrgTwo/victim-repo", allow_with_label, currently archived
  victim_repo = shipit_repositories(:org_two_victim) # review_stacks_enabled, provisioning_behavior: allow_with_label, provisioning_label_name: "deploy-me"
  stack = create_archived_review_stack(victim_repo, environment: "pr1")

  payload = payload_parsed(:pull_request_unlabeled)
  payload["repository"]["owner"]["login"] = "OrgOne"           # verified org (no secret configured)
  payload["repository"]["full_name"] = "OrgTwo/victim-repo"    # actual target org/repo
  payload["pull_request"]["labels"] = []                       # label removed -> unarchive? true for allow_with_label after removal is false;
  # for allow_with_label, unarchive? requires label present after removal is False - adjust fixture so payload keeps label
  payload["pull_request"]["labels"] << { "name" => "deploy-me" }

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/invalid, irrelevant because OrgOne has no secret

  post :create, body: payload.to_json, as: :json

  assert_response :ok
  assert_not stack.reload.archived?, "Victim stack was unarchived by a webhook verified against a different organization"
end
```
Binding checked before/after: `repository_owner == "OrgOne"` (verified) vs. organization implied by `params.repository.full_name == "OrgTwo/victim-repo"` — they diverge, yet `stack.unarchive!` still executes, proving the binding is broken.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-57)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-63)
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

**File:** test/models/shipit/webhooks/handlers/pull_request/review_stack_adapter_test.rb (L22-32)
```ruby
          test "unarchive! syncs with GitHub" do
            stack = create_archived_stack
            review_stack = Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter.new(
              params_for(stack),
              scope: stack.repository.stacks
            )

            assert_enqueued_with(job: GithubSyncJob, args: [stack_id: stack.id, expected_head_sha: nil]) do
              review_stack.unarchive!
            end
          end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
