### Title
Webhook signature verification is bound to `repository.owner.login`, not to the `repository.full_name` that handlers act on, allowing cross-organization/cross-repository writes — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the request signature against using `params.dig('repository', 'owner', 'login')` (or `organization.login`) taken directly from the untrusted JSON payload. Once the signature check passes, every registered handler (`Shipit::Webhooks::Handlers::Handler#repository_name`, `PushHandler`, and the `PullRequest::*` handlers via `ReviewStackAdapter`) independently reads a *different* field of the same attacker-supplied payload — `repository.full_name` — to decide which `Shipit::Repository`/`Stack` to mutate. Nothing ties these two fields together. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
Shipit supports multiple GitHub organizations each with their own App installation and `webhook_secret`, resolved via `Shipit.github(organization:)` / `Shipit.github_app_config` in `lib/shipit.rb`. [4](#0-3) 

`WebhooksController#verify_signature` picks the secret to verify against using the *owner* field of the `repository` (or `organization`) object in the raw JSON body: [5](#0-4) 

This is the entire authentication boundary: it establishes "the HMAC is valid for organization X." However, the handlers that subsequently execute never re-derive or cross-check that binding — they instead trust the sibling field `repository.full_name` from the very same body to pick the `Repository`/`Stack` to operate on: [2](#0-1) [6](#0-5) [7](#0-6) 

Because `repository.owner.login` and `repository.full_name` are two independent, attacker-controlled strings inside the same self-authored JSON body, an attacker who legitimately controls a GitHub App installation for their own organization ("attacker-org", and therefore genuinely knows that org's `webhook_secret` as configured in Shipit) can forge a POST to the webhook endpoint where:
- `repository.owner.login` = `"attacker-org"` (used only to select which secret verifies the HMAC — attacker computes a valid signature with their own secret), and
- `repository.full_name` = `"victim-org/victim-repo"` (used by every handler to locate the actual `Repository`/`Stack` to mutate).

This is exactly analogous to the reported bug class: a preliminary validation step (here, HMAC verification tied to `owner.login`) passes and the code proceeds to treat unrelated, uninitialized/uncorrelated data (here, `full_name` pointing at a different repository) as trustworthy, ultimately mutating state that the validation never actually covered — breaking the binding "organization that authenticated == repository that is written."

### Impact Explanation
This breaks the organization/repository trust boundary and enables cross-repository writes without any privileged Shipit credential:
- `pull_request` `opened`/`reopened` events reaching `ReviewStackAdapter#create!` create a `ReviewStack` scoped to the victim repository and immediately enqueue it for provisioning (`Shipit::ReviewStackProvisioningQueue.add(stack)`), triggering deploy/provisioning tasks defined by the victim repository's own `shipit.yml`, using the app's real GitHub credentials for the victim org. [8](#0-7) 
- `pull_request` `closed` events reaching `ReviewStackAdapter#archive!` deprovision and archive an existing review stack belonging to the victim repository. [9](#0-8) 
- `push` events reaching `PushHandler#process` invoke `stack.sync_github(expected_head_sha: params.after)` against a victim `Stack` for a branch/sha of the attacker's choosing. [10](#0-9) 

This meets the Critical/High bar: unauthorized deploy/provisioning and cross-repository writes triggered purely by an unprivileged party who controls only their own, unrelated organization's webhook secret.

### Likelihood Explanation
Requires: (1) Shipit configured with more than one organization (each with its own `webhook_secret`), which is an explicitly supported, documented configuration (`docs/setup.md`, `lib/shipit.rb#github_organizations`); (2) the attacker legitimately administers one of those configured organizations/App installations (so they know their own org's `webhook_secret`, without needing any Shipit session, API token, or the victim's secret); (3) the target repository is already tracked as a `Stack`/`ReviewStack` under a different org in the same Shipit instance. This is a realistic scenario for any shared/multi-tenant Shipit deployment servicing several GitHub organizations, and requires no interaction from the victim.

### Recommendation
When verifying and processing a webhook, require that the organization implied by the verified `webhook_secret` matches the organization portion of `repository.full_name` used by the handlers (and by `Handler#repository_name`) before dispatching to any handler. Reject the request if they diverge, and ensure `Handler#stacks`/`repository_name` derive the owner from the same already-authenticated `repository_owner` rather than independently re-parsing the payload.

### Proof of Concept
1. Configure two organizations in Shipit, `attacker-org` and `victim-org`, each with distinct `webhook_secret`s (a legitimate multi-tenant setup). Attacker legitimately knows `attacker-org`'s secret from their own App installation.
2. Victim has an existing tracked `Stack`/`Repository` for `victim-org/victim-repo`.
3. Attacker crafts a `pull_request` "opened" webhook JSON body:
```json
{
  "action": "opened",
  "number": 999,
  "pull_request": { "...": "attacker-controlled fields, e.g. head.sha of attacker's fork" },
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  },
  "sender": { "login": "attacker" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, raw_body)` and POSTs to `/github_authentication/../webhooks` (webhook endpoint).
5. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and successfully verifies the signature using the attacker's own known secret.
6. `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler` reads `params.repository.full_name` = `"victim-org/victim-repo"`, resolves the victim's `Repository`, and creates/provisions a `ReviewStack` under it — an action the attacker has no legitimate authority to trigger for `victim-org`. [11](#0-10) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L63-66)
```ruby

          def repo_name
            params.repository["full_name"]
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

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
