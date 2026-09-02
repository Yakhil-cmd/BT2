## Title
Webhook signature verified against org selected by unverified payload, but events applied to a different repository's Stack (cross-tenant write) - (File: app/controllers/shipit/webhooks_controller.rb)

## Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) directly out of the still-unverified JSON body. Once the signature check passes, `create` re-parses that same body and dispatches it to event handlers that locate the target `Stack`/`Repository` using a *different* field of the payload — `repository.full_name`. Nothing binds the two fields together, so a caller who controls the webhook secret of any one organization configured in Shipit's multi-org setup can forge a signature that verifies for their own org while directing the payload's mutating side effects at any other repository/stack tracked by the instance.

## Finding Description
`verify_signature` picks the verification key like this: [1](#0-0) 
`repository_owner` is taken straight from the raw, not-yet-verified request body: [2](#0-1) 

`Shipit.github(organization:)` supports a genuine multi-tenant configuration where each organization has its own `webhook_secret`: [3](#0-2) 

After the signature check passes, `create` dispatches the same JSON body to handlers: [4](#0-3) 

Every handler resolves the actual `Repository`/`Stack` to mutate using `repository.full_name`, a field never checked against `repository_owner`: [5](#0-4) 

Concrete mutating handlers keyed only by `full_name`: [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by verify_signature` **≠** `repository targeted by the handler via repository.full_name`.

Before the attacker's request: for a legitimate webhook, `repository.owner.login` and `repository.full_name`'s owner segment necessarily match (GitHub always sends both from the same real event), so the two identities are implicitly equal and no cross-tenant write is possible.

After the attacker's forged request: the attacker sets `repository.owner.login`/`organization.login` to an org whose `webhook_secret` they know (e.g., their own org's GitHub App installed against this shared Shipit instance) so `verify_signature` succeeds, while setting `repository.full_name` to `victim-org/victim-repo`. `verify_signature` never inspects `full_name`, and the handler never inspects `owner.login`, so the equality is broken and the mutating handler is invoked against the victim's `Stack`.

## Impact Explanation
This breaks the trust boundary between separately-authenticated GitHub organizations hosted on the same Shipit instance, enabling cross-repository writes: forcing `GithubSyncJob`/`sync_github` on an unrelated stack, injecting fabricated commit statuses (`StatusHandler`) that can influence deploy-gating checks, or archiving/unarchiving another org's review stacks (`PullRequest::ClosedHandler`, `ReopenedHandler`). Per the scan rules, unauthorized cross-repository writes are a Critical-severity outcome.

## Likelihood Explanation
Exploitability requires the attacker to legitimately control a GitHub App/webhook secret for at least one organization configured in Shipit's multi-org secrets (`config/secrets.*.yml` `github: <org>: webhook_secret:`), which is a realistic, low-privilege position for any org admin onboarded to a shared Shipit deployment — no Shipit session, API token, or repository write access on the victim repo is required. The `/github/webhooks` endpoint is public and unauthenticated except for this per-org signature check.

## Recommendation
- Short term: After signature verification, re-validate that the organization used to select the `webhook_secret` (`repository_owner`) matches the owner embedded in `repository.full_name` (and `organization.login` for org-scoped events) before dispatching to handlers; reject on mismatch.
- Long term: Resolve the target `Repository`/`Stack` and its owning organization first, verify the signature using that resolved organization's secret specifically (not a value pulled from the untrusted body), and add regression tests covering forged cross-organization payloads for each handler.

## Proof of Concept
1. Shipit is configured with `config/secrets.yml` in the multi-org schema, e.g. orgs `attacker-org` and `victim-org`, each with its own `webhook_secret`.
2. Attacker knows `attacker-org`'s `webhook_secret` (they administer that org's GitHub App).
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<hmac(attacker-org's webhook_secret, raw_body)>` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature using the attacker's known secret.
6. `create` dispatches the body to `PushHandler`, which resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` [10](#0-9)  and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack — a write the attacker was never authorized to trigger.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
