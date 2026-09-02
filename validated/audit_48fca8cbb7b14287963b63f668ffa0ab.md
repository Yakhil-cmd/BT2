### Title
Webhook signing-organization is decoupled from the target `repository.full_name` used to mutate a stack, allowing cross-org review-stack unarchive via `ReopenedHandler#process` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate a payload against using `repository_owner`, which is read from the attacker-supplied JSON body (`params.dig('repository','owner','login')`), not from any authenticated source. `ReopenedHandler#repository` independently resolves the actual `Shipit::Repository`/stack to mutate from a *different* attacker-supplied field, `params.repository.full_name`. Nothing anywhere ties these two fields together, so a request that "verifies" under one organization's key can name and mutate a completely unrelated org's repository/stack.

### Finding Description
The broken binding is: `organization_used_for_signature_verification (params.dig('repository','owner','login'))` == `organization_owning_repository.full_name (params.repository.full_name)`. This equality is never checked.

Code path:
1. `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` comes straight from the untrusted body: [1](#0-0) [2](#0-1) 
2. `Shipit.github` supports a per-organization config schema, each with its own independent `webhook_secret`: [3](#0-2) 
3. `GitHubApp#verify_webhook_signature` returns `true` unconditionally if that organization's `webhook_secret` is blank, and otherwise only checks the HMAC against that one org's secret — it never checks anything about the `full_name` of the target repository: [4](#0-3) 
4. Once `verify_signature` passes, `create` dispatches to handlers using the raw JSON body, independent of which org's key verified it: [5](#0-4) 
5. `ReopenedHandler#repository` and `#stack` resolve the target purely from `params.repository.full_name`, with no reference at all to `repository.owner.login` or to which org's key verified the request: [6](#0-5) 
6. `unarchive?` is evaluated purely against the resolved (victim) repository's `provisioning_behavior_*` settings and the attacker-controlled `pull_request.labels`: [7](#0-6) 
7. `ReviewStackAdapter#unarchive!` re-queues provisioning and calls `stack.unarchive!` on the victim's stack, which schedules `GithubSyncJob`/deploys: [8](#0-7) 

Exploit: the attacker crafts a JSON body with `repository.owner.login` set to an organization for which they either (a) know the configured `webhook_secret` (e.g. an org they legitimately administer/onboarded on a multi-tenant Shipit install), or (b) which has no `webhook_secret` configured at all (a supported, documented configuration — see `config/secrets.development.example.yml`), while setting `repository.full_name` to the victim's `"victim-org/victim-repo"` and choosing `pull_request.labels` to satisfy `unarchive?` against the victim repository's real provisioning config. `verify_signature` succeeds against the attacker's own (or secret-less) org, and `ReopenedHandler#process` proceeds to unarchive the victim's stack.

Existing guards do not prevent this: `verify_signature` only proves the request was signed with *some* configured org's secret — it never checks that org matches the repository named in the payload. The `ExplicitParameters` schema on `ReopenedHandler` only requires `repository.full_name` to be a `String`; it enforces no relationship to `repository.owner.login` (which isn't even part of the handler's schema). `drop_unhandled_event` and `check_if_ping` are unrelated to this check. No model validation on `Repository`/`Stack` re-derives or checks organization provenance at mutation time.

### Impact Explanation
A successful request causes `Shipit::Stack#unarchive!` to run for a repository the request never actually authenticated for, re-queuing it for provisioning and enqueuing `GithubSyncJob` (and, depending on stack config, subsequent deploy scheduling) — a write to another tenant's stack driven by a payload that only proved possession of a different (or absent) organization's secret. This is a payload for one organization/repository mutating another's stack/deploy pipeline, matching the Critical category explicitly listed in the rules ("a payload for one repository mutating another's stack... or an unauthorized deploy"). The attack is repeatable against any archived review stack in any repository tracked by the shared Shipit instance, as long as the attacker can get any `verify_signature` pass (via their own configured org or a secret-less org), since `repository.full_name` is entirely free-form afterward.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment configuring more than one GitHub organization (`github: org_a: ...` / `org_b: ...` schema), which is a documented, supported configuration; (2) the victim repository has `review_stacks_enabled` and a matching `provisioning_behavior_*`/label config, and an existing archived review stack for the targeted PR number — both realistic given the scenario states these as preconditions; (3) the attacker either legitimately administers one of the onboarded orgs (and thus knows its own `webhook_secret`, which is not one of the disallowed victim/operator secrets) or targets an org configured with no `webhook_secret` (`verify_webhook_signature` returns `true` unconditionally in that case, requiring no secret knowledge at all). Given these are realistic, documented configurations rather than exotic ones, and the attack requires only a single crafted HTTP POST, likelihood is high wherever multi-org configuration or a secret-less org exists.

### Recommendation
Bind the verified organization to the resolved target repository before any handler runs: after `verify_signature`, re-derive `repository.full_name`'s owner segment and assert it equals the `repository_owner` used to select the signing key (reject with 422 on mismatch). Alternatively/additionally, resolve the `Shipit::Repository` inside `verify_signature` and confirm its stored owner/org matches the org whose secret verified the signature, rather than trusting `repository.owner.login` and `repository.full_name` as independent, unauthenticated fields from the same untrusted body.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or a new test), no live GitHub:

1. Fixture setup: configure two orgs in `Shipit.stubs(:github)` — `attacker-org` with `webhook_secret: nil` (or a known test secret), and `victim-org` (owning `shipit_repositories(:shipit)`, full_name `"victim-org/victim-repo"`) with `review_stacks_enabled: true` and `provisioning_behavior: :allow_with_label`, `provisioning_label_name: "pull-requests-label"`.
2. Create and archive a review stack for PR #1234 under `victim-org/victim-repo` (`stack.archive!`), record `archived_at`.
3. Build a `pull_request`/`reopened` JSON payload: `repository.owner.login = "attacker-org"`, `repository.full_name = "victim-org/victim-repo"`, `number = 1234`, `pull_request.labels = [{ "name" => "pull-requests-label" }]`.
4. Assert binding before: `payload.dig('repository','owner','login') != payload['repository']['full_name'].split('/').first` (i.e., `"attacker-org" != "victim-org"`).
5. POST to `/webhooks` with `X-Github-Event: pull_request`, no signature header (or a signature valid for `attacker-org`'s config).
6. Assert `response.status == 200`.
7. Assert `stack.reload.archived_at.nil?` (victim stack unarchived) and `assert_enqueued_with(job: GithubSyncJob)`.
8. Assert binding after: still `"attacker-org" != "victim-org"` — mismatch persisted through the mutation, proving the org that authenticated the payload is not the org owning the mutated stack.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-59)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-83)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
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
