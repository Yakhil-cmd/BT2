### Title
Cross-organization webhook payload confusion allows ORG_A's signature to authorize `unarchive!` on ORG_B's `ReviewStack` - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to verify against using `repository.owner.login` from the untrusted JSON body, while `ReopenedHandler#repository` resolves the actual target `Repository` using the independent `repository.full_name` field from the same body. Because nothing binds these two fields together, an attacker who controls (or knows) ORG_A's webhook secret can forge a payload that passes signature verification as ORG_A but targets ORG_B's repository/stack, causing `ReopenedHandler#process` to call `stack.unarchive!` on ORG_B's `ReviewStack`.

### Finding Description
Broken binding (stated as equality that the code assumes but never enforces):
`repository_owner` (org whose secret verifies the signature) == `owner(params.repository.full_name)` (org whose `ReviewStack` is mutated).

Code path:
1. `Shipit::WebhooksController#verify_signature` computes `repository_owner` solely from `params.dig('repository', 'owner', 'login')` [1](#0-0) [2](#0-1) , then fetches `Shipit.github(organization: repository_owner)` and verifies `X-Hub-Signature` against `request.raw_post` using that org's `webhook_secret`.
2. `Shipit.github` looks up a per-organization config (multi-tenant setups configure a distinct `webhook_secret` per org, e.g. `OrgOne`/`OrgTwo` in `test/dummy/config/secrets_double_github_app.yml`) [3](#0-2) .
3. Once the signature is accepted, `ReopenedHandler#repository` resolves the target repository from a *different* field, `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name` [4](#0-3) .
4. `process` then unconditionally calls `stack.unarchive!` if `respond_to_pull_request_reopened?` (action == "reopened" and the resolved repository's provisioning settings allow it) [5](#0-4) [6](#0-5) , which delegates to `ReviewStackAdapter#unarchive!`, re-queueing provisioning and calling `stack.unarchive!` on the resolved, previously archived `ReviewStack` [7](#0-6) .

The `ExplicitParameters` schema for this handler only requires `repository.full_name`; it never requires or cross-checks `repository.owner.login` against it [8](#0-7) . Root cause: signature verification authenticates "a request signed by the org named in one JSON field" while the business logic trusts "the repository named in a completely different JSON field" — these two fields are never required to agree.

Attacker's exact request: attacker who administers ORG_A's own GitHub webhook integration into Shipit (and therefore legitimately possesses ORG_A's `webhook_secret`, as would any tenant admin in this documented multi-tenant `github:` config) crafts a raw POST body for event `pull_request`, `action: "reopened"`, with `repository.owner.login = "org_a"` (so `verify_signature` selects and validates against ORG_A's secret) but `repository.full_name = "org_b/victim-repo"` and a `number`/`pull_request` referencing an existing, previously-archived review stack PR under ORG_B. They compute a valid `X-Hub-Signature` with ORG_A's secret and POST it to `/webhooks`.

Why existing guards fail: `verify_signature` succeeds because it is checking the correct secret for whatever org is claimed in `repository.owner.login`, which the attacker set to their own org. `drop_unhandled_event`/`check_if_ping` don't apply (event is handled). The `ExplicitParameters` schema validates types/presence, not cross-field consistency. `respond_to_pull_request_reopened?` only checks ORG_B's (the real target's) `review_stacks_enabled`/`provisioning_behavior_allow_all?`, which is a precondition of the victim's configuration, not an attacker-side control, and does nothing to verify that the request was authorized by ORG_B.

### Impact Explanation
A successful request re-provisions/unarchives ORG_B's `ReviewStack` — a record write and provisioning-queue action (`Shipit::ReviewStackProvisioningQueue.add(stack)` then deploy/build re-triggering) performed for a repository that never authenticated the request. This is a cross-tenant/cross-repository stack-state mutation triggered by a party with no relationship to ORG_B, matching the Critical category "a payload for one repository mutating another's stack." It is repeatable against any archived `ReviewStack` in any other tenant repository configured with `provisioning_behavior_allow_all?` (or satisfying the label-based provisioning rules) and `review_stacks_enabled`, as long as the attacker knows the PR number and repo full name (both public/discoverable information). The blast radius spans every other tenant org hosted on the same multi-tenant Shipit instance.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment configuring more than one GitHub org under `secrets.github` (documented/supported configuration, see `test/dummy/config/secrets_double_github_app.yml`), (2) attacker legitimately holding a webhook secret for at least one configured org (e.g., as that org's own admin), and (3) the victim org's repository having `review_stacks_enabled` and a permissive `provisioning_behavior` plus an existing archived review stack for a guessable/known PR number. Attacker cost is low — a single crafted HTTP POST with a valid HMAC computed from a secret they already possess. No GitHub, Shipit or victim-org secrets are needed beyond the attacker's own org's secret. The attack is fully repeatable and does not require live interaction with GitHub.

### Recommendation
In `Shipit::WebhooksController#verify_signature` (or upstream before handler dispatch), require that `repository.owner.login` (used to select the signing org) matches the owner portion of `repository.full_name` used by handlers, rejecting the request (422) on mismatch. Alternatively, derive the org used for repository resolution from the same verified `repository_owner` value rather than trusting `repository.full_name` independently in each handler (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `AssignedHandler`, `EditedHandler`, etc., all share this pattern via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`).

### Proof of Concept
Minitest plan (controller-level, no live GitHub, using existing multi-tenant secrets fixture):
1. Configure test app with two orgs, `org_a` and `org_b`, each with a distinct `webhook_secret` (mirroring `test/dummy/config/secrets_double_github_app.yml`).
2. Create `org_b`'s `Shipit::Repository` with `review_stacks_enabled: true`, `provisioning_behavior: :allow_all`, and an archived `ReviewStack`/`PullRequest` for a known PR number.
3. Build a `pull_request` `reopened` JSON body where `repository.owner.login = "org_a"` and `repository.full_name = "org_b/victim-repo"`, `number`/`pull_request.number` matching the archived stack's PR.
4. Compute `X-Hub-Signature` using `org_a`'s `webhook_secret` over the raw JSON body.
5. POST to `/webhooks` with `X-Github-Event: pull_request` and the computed signature header.
6. Assert response is `:ok` (not `:unprocessable_entity`), and assert the ORG_B `ReviewStack.reload.archived?` is `false` (i.e., `unarchive!` was invoked) — demonstrating that a signature valid only for ORG_A caused a state change on ORG_B's stack, violating the `repository_owner == owning org of mutated stack` binding.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L8-39)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L65-75)
```ruby
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
