### Title
Webhook signature scoped to one GitHub organization is accepted for `pull_request` payloads whose `repository.full_name` names a repository owned by a different organization, letting an attacker create/mutate `ReviewStack`s under an unrelated tenant - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` used for HMAC verification via `repository_owner`, which reads `params.dig('repository','owner','login')`. `OpenedHandler#repository` independently reads `params.repository.full_name` from the same JSON body to resolve the `Shipit::Repository` to provision a `ReviewStack` against. Nothing binds these two reads together, so an attacker who legitimately controls one organization's `webhook_secret` can forge a payload whose `repository.owner.login` matches their own org (so the signature check passes) while `repository.full_name` names a victim organization's repository.

### Finding Description
The broken binding, stated as an equality that the code never enforces:

`organization_verifying_signature (params.dig('repository','owner','login'))` == `organization_owning(Shipit::Repository.from_github_repo_name(params.repository.full_name))`

Trace:
- `WebhooksController#verify_signature` computes `repository_owner` from the raw JSON body and picks `Shipit.github(organization: repository_owner)` to verify `X-Hub-Signature` [1](#0-0) , with `repository_owner` defined purely from `params.dig('repository','owner','login')` [2](#0-1) .
- `Shipit.github(organization:)` looks up per-organization config (`app_id`, `webhook_secret`, etc.) via `github_app_config(organization)`, confirming this engine supports multi-tenant configurations with independent `webhook_secret`s per organization [3](#0-2) .
- Once the signature validates for `repository_owner`, `WebhooksController#create` dispatches the same raw payload to handlers with no further scoping [4](#0-3) .
- `OpenedHandler#repository` resolves the target repository from `params.repository.full_name` alone, with no reference to `repository_owner` [5](#0-4) . `Repository.from_github_repo_name` just splits `owner/name` and does a DB lookup [6](#0-5) .
- If `respond_to_pull_request_opened?` (`review_stacks_enabled && provisioning_behavior_allow_all?`) is true for the resolved repository [7](#0-6) , `ReviewStackAdapter#create!` writes a `ReviewStack` scoped to that repository using attacker-supplied `branch`, PR number/labels, etc. [8](#0-7) .

Attacker request: attacker legitimately administers org `orgX` in a multi-org Shipit deployment and therefore knows `orgX`'s `webhook_secret`. They POST to `/webhooks` with header `X-Github-Event: pull_request` and a body where `repository.owner.login == "orgX"` (so `repository_owner` resolves to `orgX` and the HMAC computed with `orgX`'s secret validates) but `repository.full_name == "victim-org/victim-repo"`. Because `full_name` and `owner.login` are two independent JSON fields inside a body the attacker fully controls, nothing forces them to agree.

Existing guards do not catch this: `verify_signature` only checks the HMAC against whatever secret is selected using `repository_owner`; it never compares `repository_owner` to `repository.full_name`'s owner segment. `drop_unhandled_event` and the `ExplicitParameters` schema only validate the shape of the payload, not cross-field consistency. `respond_to_pull_request_opened?` only checks the resolved (victim) repository's own provisioning settings, which is exactly the setting an attacker is trying to abuse.

### Impact Explanation
A single forged webhook request causes Shipit to write a `ReviewStack` (and its provisioning queue entry / downstream `Task`) scoped to a repository belonging to an organization the attacker never authenticated against - a payload signed for tenant A mutates tenant B's stack/task state, matching the "payload for one repository mutating another's stack, commit, task or team" Critical category. Because the created `ReviewStack`'s `branch` is attacker-controlled (`params.pull_request.head.ref`), this seeds the pipeline for the victim repo's `shipit.yml`/checks to run against attacker-influenced input once provisioning proceeds, and the attack is repeatable against any repository whose `provisioning_behavior_allow_all?` is enabled, and is also reachable via the sibling `closed_handler.rb`, `labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`, `assigned_handler.rb`, `edited_handler.rb` which all resolve the target repository the same way [9](#0-8) .

### Likelihood Explanation
This requires: (1) a Shipit deployment configured with more than one GitHub organization, each with its own `webhook_secret` (a supported, documented configuration per `github_app_config`/`TOP_LEVEL_GH_KEYS` in `lib/shipit.rb`); (2) the attacker legitimately controls one such organization and thus its `webhook_secret` (this is exactly the "attacker owns org X's webhook_secret" precondition given in the prompt - it is a normal, low-privilege capability for any tenant admin in a multi-tenant install, not a secret leak); (3) the victim repository has `review_stacks_enabled` and `provisioning_behavior_allow_all?`. Given these (stated as preconditions by the prompt), constructing the forged payload is trivial - just craft a JSON body and HMAC-sign it with a secret the attacker already knows - and it is fully repeatable against any victim repository name known to the attacker.

### Recommendation
In `WebhooksController#verify_signature` (or in a shared handler pre-check), after resolving the repository referenced by the payload (`params.dig('repository','full_name')`), verify that its owner segment equals `repository_owner` before dispatching to handlers; reject the request (e.g., `head(422)`) on mismatch. Alternatively, have handlers resolve the `Shipit::Repository` by both `owner` and `name` and additionally assert `repository.owner == repository_owner` (the value used for signature verification) before creating/mutating any `ReviewStack`, `Stack`, or `Task`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`, `test/models/shipit/webhooks/handlers/pull_request/...`), no live GitHub:
1. Configure `Shipit.github` in test with two orgs, `org-x` and `victim-org`, each with a distinct `webhook_secret`.
2. Create `Shipit::Repository` fixture `victim-org/victim-repo` with `review_stacks_enabled: true`, `provisioning_behavior: 'allow_all'`.
3. Build a `pull_request` `opened` JSON body with `repository.owner.login = "org-x"`, `repository.full_name = "victim-org/victim-repo"`, and a valid `pull_request.head.ref`.
4. Compute `X-Hub-Signature` using `org-x`'s `webhook_secret` over the raw body and POST to `/webhooks` with `X-Github-Event: pull_request`.
5. Assert the response is `200 OK` (signature accepted, i.e. `repository_owner == "org-x"` passed verification).
6. Assert `Shipit::ReviewStack.where(repository: Shipit::Repository.find_by(owner: "victim-org", name: "victim-repo")).count == 1`, proving a record was written for `victim-org/victim-repo` despite the signature only authenticating `org-x`.
7. Negative control: repeat with `repository.owner.login = "victim-org"` (i.e., matching), confirm identical acceptance/record creation - demonstrating the two code paths (signature org vs. resolved repository org) are never compared.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-70)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L1-2)
```ruby
# frozen_string_literal: true

```
