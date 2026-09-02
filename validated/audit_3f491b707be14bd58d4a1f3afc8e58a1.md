### Title
Webhook organization used for signature selection is never bound to the repository/team the event acts on, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/`webhook_secret` to validate a webhook against using `repository_owner`, a value read straight out of the attacker-controlled JSON body (`repository.owner.login` or `organization.login`). The HMAC signature only proves the payload was signed with *that* organization's secret — it never constrains the *other* fields inside the same JSON body (`repository.full_name`, `organization.login` used later, team/member data, etc.) that the downstream webhook handlers actually act on to identify which repository/stack/team to mutate.

### Finding Description [1](#0-0) 

`verify_signature` resolves `repository_owner` from the payload itself: [2](#0-1) 

and uses it to select the GitHub App config/secret via `Shipit.github(organization: repository_owner)`: [3](#0-2) 

This only proves the HMAC was computed with the secret belonging to whatever organization `repository_owner` names — in a multi-org configuration (`config/secrets.*.yml` supports one `webhook_secret` per organization, per `lib/shipit.rb:196-200`), any org admin who knows their own organization's `webhook_secret` can freely construct an arbitrary JSON body and sign it correctly, because the signature check never verifies that the *rest* of the payload (in particular `repository.full_name`) is consistent with the organization used to select the secret.

Every webhook handler ignores `repository_owner` entirely and instead re-derives the target repository from `repository.full_name` in the same, attacker-controlled body: [4](#0-3) 

For example the push handler triggers syncs on whatever stacks match that repository: [5](#0-4) 

and PR handlers resolve the acted-upon repository the same way: [6](#0-5) 

This reproduces the exact class of bug in the report: a field that is *acted upon* (`repository.full_name`, driving which stack/repo gets synced, archived, etc.) is never part of the binding that the cryptographic check actually enforces (`repository_owner` → secret selection). The equality that should hold is:

`organization whose secret authenticated the request == owner of the repository the handler mutates`

but nothing enforces `repository.owner.login == repository.full_name.split('/').first`, nor that the org used for signature selection matches the repository actually processed.

### Impact Explanation
In a deployment with more than one GitHub organization configured (the documented multi-org `secrets.yml` schema), an attacker who controls (or is an admin of) one onboarded organization — and therefore legitimately knows that organization's `webhook_secret` — can forge a signed webhook body whose `repository.owner.login`/`organization.login` matches their own org (so the HMAC check passes) while `repository.full_name` (or, in `membership` events, `organization.login`/`team`/`member`) references a *different* organization/repository tracked by the same Shipit instance. This lets the attacker:
- Trigger `GithubSyncJob` / archive or unarchive review stacks belonging to a repository they do not own.
- Forge `membership` events (which create `Team`/`Membership` records purely from payload data with no GitHub API cross-check) to grant themselves membership in a `Team` object used by `Shipit.github_teams` for `current_user.authorized?` checks, escalating into application-wide authorization.

This matches the explicitly in-scope High-impact class: "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Requires the deployment to use the multi-organization GitHub App configuration (each org with its own `webhook_secret`) and for the attacker to control or administer at least one of the onboarded organizations — a realistic scenario for shared/multi-tenant Shipit installations. No repository write access, Shipit session, or `ApiClient` token is needed; only knowledge of one organization's own configured `webhook_secret`, which that organization's own admins legitimately possess.

### Recommendation
After signature verification succeeds, cross-check that every organization/repository-identifying field actually used by the handlers (`repository.owner.login`, `repository.full_name`'s owner segment, `organization.login`) is consistent with the `repository_owner` value used to select the verifying secret. Reject the webhook if they diverge, and additionally validate against the `Repository` record's own configured owner (from `Shipit.github(organization:)`) before dispatching to handlers, rather than trusting the raw payload for both signing-org selection and target-repo resolution.

### Proof of Concept
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with its own `webhook_secret` (per the documented multi-org `secrets.yml` schema).
2. As an admin of `orgA` (who legitimately knows `orgA`'s `webhook_secret`), craft a `membership` (or `push`) webhook JSON body where `organization.login`/`repository.owner.login` = `orgA` but `member.login`/`team` (or `repository.full_name`) reference a team/repository that belongs to `orgB`.
3. Compute `X-Hub-Signature` using `orgA`'s `webhook_secret` over the raw body.
4. POST to `/webhooks` with `X-Github-Event: membership` (or `push`). `verify_signature` resolves `repository_owner`/`organization` = `orgA`, fetches `orgA`'s `GitHubApp`, and validates the signature successfully.
5. The `MembershipHandler`/`PushHandler` then processes the payload's team/member or repository data — which targets `orgB`'s team or repository — even though the request was only ever authenticated against `orgA`'s secret.

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

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
