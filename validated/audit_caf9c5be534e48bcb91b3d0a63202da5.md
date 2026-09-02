### Title
Webhook signature verified against `repository.owner.login`'s org while `LabeledHandler` mutates the stack keyed on `repository.full_name` — cross-repository stack mutation - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to check via `params.dig('repository','owner','login')`, but `LabeledHandler#repository`/`#stack` (and the sibling `OpenedHandler`, `UnlabeledHandler`, `ReopenedHandler`) resolve and mutate the target `Repository`/`Stack` using `params.repository.full_name`. Nothing in the request pipeline enforces that these two values name the same repository/org, so a signature valid for one organization's webhook secret can be replayed with a `full_name` pointing at a completely different, victim-owned repository, whose `ReviewStack` gets archived/unarchived.

### Finding Description
Broken binding (equality that is assumed but never checked):
`Repository.from_github_repo_name(params.repository.full_name).owner == params.dig('repository','owner','login')`

Trace:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` purely from `params.dig('repository','owner','login')` (`app/controllers/shipit/webhooks_controller.rb:59-62`), fetches `Shipit.github(organization: repository_owner)` and checks `X-Hub-Signature` against that org's `webhook_secret` (`lib/shipit/github_app.rb:76-83`). `Shipit.github` supports a multi-tenant config keyed by organization (`lib/shipit.rb:170-200`), so distinct organizations can have distinct, independently-known `webhook_secret`s — an org's own admin, having configured the GitHub webhook for their own org, legitimately knows their own secret.
- If the check passes, `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` (`app/controllers/shipit/webhooks_controller.rb:10-15`), which for a `pull_request`/`labeled` event invokes `LabeledHandler.new(params).process`.
- `LabeledHandler#repository` resolves the repository solely from `params.repository.full_name`: `Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new` (`app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb:65-68`). The value of `repository.owner.login` used earlier for signature selection is never consulted again.
- `LabeledHandler#stack` builds a `ReviewStackAdapter` scoped to `repository.review_stacks` (`app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb:59-63`), and `#handle` calls `stack.archive!`/`stack.unarchive!` (`app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb:49-57`), which in `ReviewStackAdapter` perform real state changes: `stack.remove_from_provisioning_queue`, `stack.deprovision`, `stack.archive!(user, ...)` or `Shipit::ReviewStackProvisioningQueue.add(stack)` / `stack.unarchive!(...)` (`app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:23-50`).
- The `ExplicitParameters` schema for `LabeledHandler` (`app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb:8-39`) only requires `repository.full_name`; it never requires or validates `repository.owner.login`, so there is no schema-level cross-check between the field used for authentication and the field used for authorization/target-selection.

Attacker request: a `pull_request`/`labeled` webhook where `repository.owner.login = "org-c"` (attacker's own org, whose webhook secret the attacker knows) but `repository.full_name = "victim-org/victim-repo"`, `pull_request.labels` set to trigger `archive?`/`unarchive?` for the victim repo's actual provisioning-behavior configuration, signed with org C's `webhook_secret`.

Existing guards checked and found insufficient: `verify_signature` only authenticates that *some* known org's secret was used, not that it matches the repository being mutated; `drop_unhandled_event` and `check_if_ping` are irrelevant; the `ExplicitParameters` schema validates types/presence but not cross-field consistency; `Repository#owner`/`Stack` model validations don't check request provenance; `require_permission!`/`User#authorized?`/`stacks` scope are not on the webhook path at all (webhooks bypass session/API-token auth entirely by design, relying solely on `verify_signature`).

### Impact Explanation
An attacker who administers any single organization onboarded to a multi-org Shipit instance (and thus knows that org's `webhook_secret`) can archive or unarchive review stacks — and, via the sibling `OpenedHandler`/`ReopenedHandler`, create/unarchive review stacks — belonging to any other organization/repository tracked by the same Shipit instance, without ever authenticating against that victim org's secret. This is a payload for one repository (the attacker's) mutating another repository's (the victim's) `Stack`/task state, matching the stated Critical impact category. It is repeatable against any repository name the attacker can guess or enumerate (repository full names are not secret), and it affects every tenant sharing the Shipit instance, not just one.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment where `Shipit.github_organizations` lists more than one organization (each with its own `webhook_secret`) — a supported, documented configuration (`lib/shipit.rb:170-200`); (2) the attacker legitimately administers at least one such org and thus knows its `webhook_secret` (no Shipit secret, session, or API token needed — consistent with the stated attacker capabilities); (3) the victim repository has `review_stacks_enabled` and a `provisioning_behavior` configured (`allow_with_label`/`prevent_with_label`) — a default/common feature for review-stack repositories. No knowledge of the victim's webhook secret, GitHub token, or Shipit credentials is needed, only the victim's public repository name and provisioning label. This is fully attacker-controlled and repeatable per request.

### Recommendation
In `WebhooksController` (or in `Shipit::Webhooks::Handlers::Handler`), enforce that the organization used for signature verification matches the owner embedded in `repository.full_name` before dispatching to handlers — e.g., derive `repository_owner` consistently from `full_name.split('/').first` and reject (422) if it disagrees with `repository.owner.login`/`organization.login`. Additionally, harden `Handler`/`LabeledHandler`/`OpenedHandler`/`UnlabeledHandler`/`ReopenedHandler` to verify that the resolved `Repository#owner` matches the organization whose secret validated the request, independent of controller-level checks, so a compromised or misrouted webhook cannot mutate a different tenant's stack.

### Proof of Concept
Minitest plan (multi-org secrets fixture, e.g. `test/dummy/config/secrets_double_github_app.yml` already used in `test/unit/shipit_test.rb`):
1. Configure two orgs, `orgone` and `victim-org`, each with distinct `webhook_secret`s via the double-github-app secrets fixture.
2. Create `shipit_repositories(:victim)` with `full_name = "victim-org/victim-repo"`, `review_stacks_enabled: true`, `provisioning_behavior: allow_with_label`, `provisioning_label_name: "deploy-me"`, and an existing active `ReviewStack` for PR number `N` (not archived).
3. Build a `pull_request`/`labeled` payload: `repository: { owner: { login: 'orgone' }, full_name: 'victim-org/victim-repo' }`, `pull_request: { number: N, head: { ref: ... }, labels: [] }` (label absent to trigger `archive?`), `sender: { login: 'attacker' }`.
4. Compute `X-Hub-Signature` using `orgone`'s `webhook_secret` (the one the "attacker" legitimately controls) and set `X-Github-Event: pull_request`.
5. `assert_response :ok` on `post :create` and `assert Repository.find_by(full_name: 'victim-org/victim-repo').review_stacks.find_by(...).reload.archived?`, proving the victim's stack was archived under a signature that never involved `victim-org`'s webhook secret. Assert additionally that `Shipit.github(organization: 'orgone')` (not `'victim-org'`) is the client whose `verify_webhook_signature` returned true, demonstrating the owner-of-signature ≠ owner-of-mutation divergence explicitly. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L41-68)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

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
