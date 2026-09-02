### Title
Cross-organization webhook forgery via `repository.owner.login` (signature-verified) vs `repository.full_name` (target-repository, unverified) mismatch - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
In a multi-organization Shipit deployment (`secrets.github` keyed by organization, per `lib/shipit.rb`), the webhook signature is verified against the `webhook_secret` of the organization derived from `repository.owner.login` (or `organization.login`), while the handlers that actually act on the payload (e.g. `PushHandler`, PR handlers) select the target `Stack`/`Repository` using `repository.full_name` — a separate field in the same JSON body. An administrator of *any* configured organization can craft an arbitrary raw POST body (not necessarily produced by GitHub) whose `repository.owner.login` matches their own org (so it passes HMAC verification with their own known `webhook_secret`) while `repository.full_name` names a completely different organization's repository, causing Shipit to act on a stack it does not own.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to verify against using: [1](#0-0) [2](#0-1) 

`repository_owner` is resolved purely from the request body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), and `Shipit.github(organization: repository_owner)` looks up a per-organization `webhook_secret` from `secrets.github`: [3](#0-2) 

Once the signature is verified as valid for *that* organization, `handler.call(params)` is invoked for every registered handler, and each `Handler` resolves the repository/stack to operate on using an entirely different field of the same payload — `repository.full_name` — with no cross-check against the organization that was actually authenticated: [4](#0-3) 

`PushHandler`, for example, uses this `stacks` helper to trigger `stack.sync_github(expected_head_sha: ...)` for every matching, non-archived stack on the resolved repository/branch: [5](#0-4) 

Because the HMAC signature only proves "this request was signed with organization X's webhook secret," and X is derived from `repository.owner.login`, but the object actually acted upon is derived from the independent `repository.full_name` field, an operator who legitimately controls one configured organization (and therefore knows/receives that organization's `webhook_secret`) can set `repository.owner.login` to their own org (to pass verification) while setting `repository.full_name` to `"other-org/victim-repo"` in a directly-crafted POST to the webhook endpoint. This breaks the intended binding: *the organization whose credential authenticated the request* should equal *the organization whose repository is written to/acted upon*, but the code never enforces that equality.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary explicitly called out as in-scope. A caller with a foreign organization's webhook secret cannot forge this on their own (GitHub always keeps `repository.owner.login` and `repository.full_name` consistent), but this engine does not require the caller to go through GitHub — it accepts any POST to the webhook endpoint that matches a configured HMAC secret, and does not confirm internal consistency. Since any operator running a multi-org Shipit instance controls their own org's `webhook_secret` legitimately, they can point crafted push/PR/check-suite events at *another tenant organization's* stacks, causing unauthorized `GithubSyncJob` triggers, spurious `commit` status/check-run refresh, or review-stack provisioning/archival (`PullRequest::OpenedHandler`, `ReopenedHandler`, `ClosedHandler`) for repositories the attacker does not own. This does not directly grant RCE or exfiltrate `GITHUB_TOKEN` by itself, but it does allow a cross-organization write into another tenant's stack state (sync jobs, review-stack lifecycle mutation) — a violation of the intended per-organization isolation of multi-tenant webhook secrets.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (`secrets.github` keyed by org names, as documented in `config/secrets.development.example.yml`) where the attacker legitimately administers or has access to the webhook secret of at least one configured organization — a realistic scenario for shared/hosted Shipit instances serving multiple tenants. No GitHub App private key, session, or `ApiClient` token is required; only knowledge of one org's `webhook_secret`, which by design that org's administrators possess.

### Recommendation
In `Shipit::Webhooks::Handlers::Handler` (or `WebhooksController`), thread through the organization that was actually verified during `verify_signature` and require that `payload.dig('repository','owner','login')` (or `organization.login`) used for verification equals the owner segment of `repository.full_name` used for repository resolution, rejecting the webhook (422) on mismatch instead of allowing handlers to resolve an independent, unchecked repository field.

### Proof of Concept
1. Deploy Shipit configured for two organizations, e.g. `secrets.github: { orga: { webhook_secret: "secretA", ... }, orgb: { webhook_secret: "secretB", ... } }`, each with a tracked stack, e.g. `orgb/victim-repo`.
2. As an administrator of `orga` (who legitimately knows `secretA`), craft a JSON push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(secretA, body)>` and POST it directly to `/github/webhooks` (bypassing GitHub) with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner == "orga"`, fetches `secretA`, and the signature verifies successfully. [6](#0-5) 
5. `PushHandler#process` resolves the target repository via `payload.dig('repository','full_name') == "orgb/victim-repo"` and triggers `sync_github` on `orgb`'s stack — despite the request only having been authenticated for `orga`. [4](#0-3) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
