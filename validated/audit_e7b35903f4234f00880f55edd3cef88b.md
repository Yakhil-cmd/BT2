### Title
Cross-organization webhook forgery via signature-key selection on unverified payload field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/organization config (and therefore the HMAC `webhook_secret`) used to validate an inbound webhook from an attacker-controlled field inside the very payload being verified, `repository.owner.login` (falling back to `organization.login`). Handlers then resolve the actual `Repository`/`Stack` to mutate using a *different* field from the same unverified JSON body, `repository.full_name`. In a multi-organization Shipit deployment (explicitly supported, each org configured with its own `webhook_secret`), this breaks the binding "organization that authenticated == repository that is written": an attacker who legitimately controls (or knows) the `webhook_secret` for Org A can sign a payload whose `repository.owner.login` is `"orgA"` but whose `repository.full_name` is `"orgB/some-repo"`, and the request will pass signature verification yet be processed against Org B's stack.

### Finding Description
`verify_signature` computes the verification key from the payload itself before trusting anything in it: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a distinct `GitHubApp` (and distinct `webhook_secret`) per organization when the multi-org secrets schema is used: [3](#0-2) 

`verify_webhook_signature` only checks the HMAC against whatever `webhook_secret` was selected — it has no way to know whether that secret's organization actually matches the repository the payload claims to describe: [4](#0-3) 

After signature verification succeeds, every handler independently re-reads `repository.full_name` from the same untrusted payload to locate the `Repository`/`Stack` to act on, with no cross-check against `repository_owner` used earlier: [5](#0-4) [6](#0-5) 

This is the direct analog of the reported bug class: a parameter (the organization/secret selector) is trusted implicitly because it's "part of the constructor input" (here, part of the same signed JSON body) without any invariant tying it to the value that is actually acted upon (`repository.full_name`). Just as the missing `require(addr != address(0))` let an attacker supply an unchecked value that a downstream operation blindly trusted, here the missing invariant "the org whose secret validated this payload must equal the org that owns the repository referenced in this payload" lets an attacker's own valid secret be replayed to target any other organization's repository configured on the same Shipit instance.

### Impact Explanation
An attacker who is a legitimate administrator/operator of a repository/organization onboarded onto a shared, multi-tenant Shipit instance (and thus knows or controls that org's `webhook_secret`, which per `docs/setup.md` is a value the org owner sets themselves when creating the GitHub App) can forge `push`, `status`, `pull_request`, `check_suite`, or `membership` events attributed to any other organization/repository hosted on the same instance, without ever having credentials for that other org. Depending on handler, this can:
- Trigger `GithubSyncJob` and merge/status processing for a foreign stack (`PushHandler`, `StatusHandler`).
- Create/close/relabel review stacks and toggle provisioning/deprovisioning for a foreign repository (`PullRequest::*Handler`).
- Create arbitrary `Team`/`User`/`Membership` records via the `membership` event.

This crosses the "unauthorized deploy/rollback/merge" / "escalation into `Shipit.github_teams` authorization" bar described in scope, because it lets an attacker who authenticates as one tenant act on another tenant's stack state.

### Likelihood Explanation
Requires: (1) a Shipit instance configured with the multi-organization `github:` secrets schema (documented and supported), and (2) the attacker to be a legitimate operator of at least one onboarded organization (i.e., they know that org's `webhook_secret`, which they themselves provision when connecting their org's GitHub App per `docs/setup.md`). No GitHub App private key, `GITHUB_TOKEN`, or Shipit session is needed — only the webhook HTTP endpoint and a JSON body they craft and sign with their own known secret. This is a realistic misuse path in any shared/multi-tenant deployment, which is the deployment model the multi-org config exists to support.

### Recommendation
After signature verification succeeds, re-derive the organization from the same field that determines which config validated the signature and enforce that it matches the organization implied by `repository.full_name` (or `organization.login`) before dispatching to handlers — e.g., reject the event if `repository.full_name.split('/').first` doesn't match the verified `repository_owner`/organization. Alternatively, pass the verified organization down into handler resolution so `Repository.from_github_repo_name` only considers repositories under the organization whose secret validated the request.

### Proof of Concept
Given a Shipit instance configured with:
```yaml
github:
  orgA:
    webhook_secret: "orgA-secret"   # known to attacker, an admin of orgA
  orgB:
    webhook_secret: "orgB-secret"   # unknown to attacker
    # orgB hosts a stack for "orgB/private-repo"
```
1. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/private-repo" }
}
```
2. Attacker computes `X-Hub-Signature: sha1=HMAC(orgA-secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
3. `verify_signature` computes `repository_owner = "orgA"` [2](#0-1) , fetches `orgA`'s `webhook_secret`, and the HMAC check passes because the attacker signed with the secret they legitimately know.
4. `PushHandler` then resolves the repo via `payload.dig('repository', 'full_name')` = `"orgB/private-repo"` [7](#0-6)  and triggers `stack.sync_github(...)` for Org B's stack [8](#0-7) , despite the attacker never having authenticated against Org B.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
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
```
