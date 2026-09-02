This confirms Shipit supports a genuine multi-organization configuration (`Shipit.github_organizations`, `github_app_config(organization)`), where each configured GitHub organization has its own independent `webhook_secret` [1](#0-0) . This is the multi-tenant setup where the binding-break becomes exploitable.

### Title
Webhook signature is verified against `repository.owner.login`'s organization while the actual stack acted upon is selected by the attacker-controlled `repository.full_name` field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`, taken from the payload's `repository.owner.login` (or `organization.login`) field [2](#0-1) . Once the signature check passes, every webhook `Handler` resolves the actual `Repository`/`Stack` to act on using a *different* field, `repository.full_name`, via `Handler#repository_name` (`payload.dig('repository', 'full_name')`) [3](#0-2) . In a multi-organization Shipit deployment (`Shipit.github_organizations`, `github_app_config(organization)`), each organization can have its own independently configured `webhook_secret` [4](#0-3) . Nothing ties the field used for authentication (`repository.owner.login`) to the field used for authorization/action (`repository.full_name`); the controller only checks that the raw body's HMAC matches whichever org's secret is named by `repository.owner.login`, then passes the full, attacker-supplied JSON body to the handlers unmodified [5](#0-4) .

### Finding Description
The equality that should hold is:
`organization whose webhook_secret authenticated the request == organization/repository that the handler mutates`

Concretely:
1. `repository_owner` (used to pick the `GithubApp`/secret for verification) = `params.dig('repository','owner','login') || params.dig('organization','login')` [6](#0-5) .
2. `repository_name` (used by every `Handler` subclass to look up the actual `Repository`/`Stack`) = `payload.dig('repository', 'full_name')` [7](#0-6) .

Both values are read straight from the same untrusted, attacker-supplied JSON body, but only the raw bytes of the whole body are covered by the HMAC — the *specific field used for org selection* is not cryptographically bound to the *specific field used for repository selection*. An attacker who legitimately controls a GitHub organization/App-installation that is configured in this Shipit instance (and therefore genuinely knows or can trigger delivery of that org's correctly-signed `webhook_secret`) can submit a POST to `/github/webhooks` where:
- `repository.owner.login` = their own organization (so `verify_signature` picks their own org's `GithubApp`/`webhook_secret` and the HMAC validates), while
- `repository.full_name` = a completely different organization/repository that is also hosted on the same shared Shipit instance.

Because `verify_webhook_signature` only checks the byte-for-byte HMAC of the body against the secret resolved from `repository.owner.login`, and does not verify that `repository.full_name` belongs to the same organization, the handler layer (`PushHandler`, `StatusHandler`, `MembershipHandler`, `PullRequest::*Handler`, etc., all inheriting `Handler#stacks`/`#repository_name`) will act on the victim organization's `Repository`/`Stack` records [8](#0-7) . For example, `PushHandler#process` triggers `stack.sync_github(expected_head_sha: params.after)` on stacks matching the victim's `repository.full_name` and branch [9](#0-8) , and `MembershipHandler`/`PullRequest` handlers similarly create/mutate teams, memberships, review-stack archival/unarchival, and PR label state for the victim repository — all cross-organization, cross-tenant writes triggered by an attacker who only authenticated as their own, unrelated organization.

### Impact Explanation
This crosses exactly the "organization that authenticated versus the repository that is written" trust boundary called out in scope. In a multi-tenant Shipit install (the only setup where `Shipit.github_organizations`/`github_app_config` is meaningful), an org-A operator can forge webhook events that are accepted as legitimate (because they pass HMAC verification against org A's own secret) but that mutate org B's stacks: triggering GitHub syncs, archiving/unarchiving review stacks, injecting Team/Membership records, or writing fabricated commit statuses (`StatusHandler`) for repositories they do not own or administer. This is a cross-repository/cross-tenant write achieved without ever needing org B's `webhook_secret`, `GITHUB_TOKEN`, or any Shipit session/API token — satisfying the High-severity bar ("unauthenticated read/write of stack state" / cross-tenant data corruption) for this class of finding.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (i.e., `secrets.github` configured with multiple named organizations rather than the single flat top-level config) — a documented, supported configuration path in this engine, not an undocumented deployment. Within that configuration, exploitation only requires the attacker to know their *own* organization's webhook secret (which they legitimately possess by definition of being a Shipit tenant/customer with a configured GitHub App/installation for their own org) and to freely craft the JSON body of a POST to the public `/github/webhooks` endpoint — no interaction with, or credentials for, the victim organization are needed.

### Recommendation
Bind organization identity to repository identity before dispatching to handlers: after resolving `repository_owner` for signature verification, validate that `payload.dig('repository', 'full_name')` (and `organization.login` if present) actually belongs to that same verified organization before invoking `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. Alternatively, resolve the target `Repository`/`Stack` first, derive its owning organization from the Shipit-side `Repository` record, and use that authoritative organization (not attacker-supplied JSON) to select the `webhook_secret` for verification.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `secrets.github: { org-a: {webhook_secret: SECRET_A, ...}, org-b: {webhook_secret: SECRET_B, ...} }` (per `Shipit.github_app_config`) [10](#0-9) , each hosting stacks for their own repositories.
2. Attacker, who administers org-a (and therefore controls/knows `SECRET_A` via their own genuine GitHub App installation), crafts a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. POST this body to `/github/webhooks` with header `X-Github-Event: push` and `X-Hub-Signature` computed as `sha1=HMAC(SECRET_A, body)`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"org-a"`, fetches `Shipit.github(organization: "org-a")`, and successfully verifies the signature against `SECRET_A` [11](#0-10) .
5. `PushHandler#process` is invoked with the full payload; `Handler#repository_name` returns `"org-b/victim-repo"` and looks up `Repository.from_github_repo_name("org-b/victim-repo")`'s stacks, then calls `stack.sync_github(expected_head_sha: "deadbeef")` for org B's stack — a write triggered entirely by org A's credentials against org B's data [3](#0-2) , [9](#0-8) .

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
