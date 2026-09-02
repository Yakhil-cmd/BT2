### Title
Webhook signature verification uses an organization derived from unverified payload fields, decoupling the authenticated organization from the repository actually written - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate a webhook's HMAC against by reading `repository.owner.login` (or `organization.login`) straight out of the still-unverified JSON body, then hands the *entire* raw body — including an independent `repository.full_name` field — to every registered handler without ever checking that the two fields agree. [1](#0-0)  Handlers such as `PushHandler`, the `PullRequest` family, and `StatusHandler` resolve the target `Stack`/`Repository` solely from `repository.full_name` in the payload, with no reference back to the organization that was used for signature verification. [2](#0-1) [3](#0-2) 

### Finding Description
The verification binding that should hold is:
`organization whose webhook_secret authenticates the request == organization that owns the repository the handlers act on`

In `verify_signature`, `repository_owner` is taken from the JSON body before the signature is checked, and used to look up a `GitHubApp` (and therefore a `webhook_secret`) via `Shipit.github(organization: repository_owner)`: [4](#0-3) [5](#0-4) 

`GitHubApp#verify_webhook_signature` will trivially return `true` — accepting the request unconditionally, signature or not — whenever the resolved organization's configuration has no `webhook_secret` set: [6](#0-5) 

`Shipit.github_app_config` supports a fully multi-tenant configuration keyed per organization (`secrets.github[<org>]`), so it is a supported, documented deployment shape for some organizations in `secrets.github` to be configured without a `webhook_secret` (or misconfigured with one blank/nil), while others have one: [7](#0-6) 

Once `verify_signature` passes (because the org derived from `repository.owner.login`/`organization.login` has no secret configured, or is otherwise weakly bound), the controller dispatches the *full, unauthenticated-content* payload to handlers: [8](#0-7) 

Those handlers never re-check `repository.owner.login` (the field the signature check keyed off of) against `repository.full_name` (the field that actually selects the `Stack`/`Repository` to mutate): [9](#0-8) [10](#0-9) 

This is precisely the "authenticated organization vs. repository actually written" binding break called out in the rules: the field that gates authentication (`repository.owner.login` / `organization.login`) is not the same field, nor cryptographically bound to the same field, that determines which repository's state is mutated (`repository.full_name`). GitHub's real deliveries always keep these consistent, but nothing in this engine enforces that invariant on the untrusted side — the check is "does *some* configured org's secret verify (or lack) match", not "does this specific repository belong to that org".

### Impact Explanation
Where an operator runs a multi-organization deployment (multiple entries under `secrets.github`, as directly supported by `github_app_config`) and any one configured organization lacks a `webhook_secret` (a valid, documented configuration since `webhook_secret` is merely `.presence`-checked and optional per-org), an unauthenticated attacker can:
1. Send a POST to `/github/webhooks` with `repository.owner.login` (or `organization.login`) set to that unsecured organization, satisfying `verify_signature` unconditionally.
2. Set `repository.full_name` in the same payload to any *other* tracked repository/stack in the installation (belonging to a fully-secured, unrelated organization), since handlers only look up state via `repository.full_name`.
3. Trigger handler side effects against that unrelated stack: e.g. `PushHandler` calls `stack.sync_github(expected_head_sha:)` on stacks matching the forged branch/repo [11](#0-10) , `PullRequest::OpenedHandler`/`ClosedHandler` create or archive review-stacks [12](#0-11) , and `MembershipHandler`/`StatusHandler` create teams/users or commit statuses used elsewhere for deploy gating.

For stacks with continuous deployment enabled, forcing an unauthenticated `sync_github` and status updates can advance/trigger deploy eligibility checks earlier or under attacker timing, which crosses into "unauthorized deploy" territory as defined in scope. This satisfies the High/Critical bar of an unauthenticated actor achieving state changes and deploy-adjacent effects on a repository they were never authenticated for.

### Likelihood Explanation
Exploitability is entirely conditioned on deployment configuration: it requires (a) multi-org GitHub App configuration and (b) at least one configured organization missing a `webhook_secret`. This is a realistic but not universal misconfiguration — the per-organization secret is optional in code (`@webhook_secret = @config[:webhook_secret].presence`, `return true unless webhook_secret`), so any operator who forgets to set it for one tenant (or intentionally leaves an internal/low-risk org unsecured) silently degrades the security boundary for *all* other repositories in the installation, not just that org's own repository. No credentials, tokens, or GitHub App keys are needed by the attacker — only network access to the webhook endpoint and knowledge of an unsecured organization's login and a target repository's `full_name`, both of which are not secret.

### Recommendation
- Do not select the verification secret using an unverified field from the same payload being verified. Bind webhook signature verification to the specific `Stack`/`Repository` being targeted (derived from `repository.full_name`), not to an org name pulled out of the yet-unauthenticated JSON body.
- Make `webhook_secret` mandatory for every configured organization; refuse to boot / fail closed (return `false`, not `true`) when a matched organization has no secret configured, rather than treating "no secret" as "verified".
- After signature verification, re-validate that `repository.owner.login` (or `organization.login`) used for the signature actually owns the repository named in `repository.full_name` before invoking handlers, closing the gap between the authenticated organization and the repository that gets written.

### Proof of Concept
Preconditions: `secrets.github` configured with at least two orgs, e.g. `orgA` (no `webhook_secret` set) and `orgB` (has `webhook_secret`, owns tracked stack `orgB/prod-app`).

```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=0000000000000000000000000000000000000000   # arbitrary/garbage

{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/prod-app"
  }
}
```

Trace:
1. `WebhooksController#repository_owner` reads `"orgA"` from `params.dig('repository','owner','login')`. [5](#0-4) 
2. `Shipit.github(organization: "orgA")` resolves `orgA`'s `GitHubApp`, whose `webhook_secret` is unset. [13](#0-12) 
3. `verify_webhook_signature` returns `true` immediately (`return true unless webhook_secret`), regardless of the bogus `X-Hub-Signature`. [6](#0-5) 
4. `create` dispatches the full payload to `PushHandler`, which looks up stacks via `repository.full_name` = `"orgB/prod-app"`, matching the real, secured `orgB` stack, and calls `stack.sync_github(expected_head_sha: "deadbeef")` on it — a write triggered by an attacker who never had `orgB`'s webhook secret. [14](#0-13) 

Note: I was not able to execute this against a running instance to confirm the downstream effect of `sync_github` under continuous-delivery configurations within the available tool access; this is stated as a limitation rather than a confirmed end-to-end deploy trigger.

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
