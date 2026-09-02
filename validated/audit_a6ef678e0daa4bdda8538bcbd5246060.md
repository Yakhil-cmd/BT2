### Title
Cross-organization webhook authentication bypass via mismatched `repository.owner.login` vs `repository.full_name` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the HMAC signature against by reading `repository.owner.login` (or `organization.login`) from the **unverified** JSON body, then verifies the signature using that organization's `webhook_secret`. The handlers that actually act on the payload (e.g. `PushHandler`) resolve the target repository/stack from a **different** field of the same unverified body: `repository.full_name`. Nothing binds these two fields together, so an attacker who legitimately controls (and knows the `webhook_secret` of) one onboarded GitHub organization on a multi-tenant Shipit instance can forge a payload whose `repository.owner.login` matches their own org (so the signature check passes with their known secret) while `repository.full_name` points at a completely different organization/repository tracked by the same Shipit instance, causing the engine to act (e.g. trigger a sync/deploy) on that other repository's stack.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) 
The organization used to select the verifying `GitHubApp`/secret is derived purely from the request body itself: [2](#0-1) 

`Shipit.github(organization: ...)` looks up the per-organization config (and its `webhook_secret`) keyed by that attacker-supplied login: [3](#0-2) 

Signature verification is a plain HMAC over the raw body using whichever organization's secret was selected: [4](#0-3) 

Once verification passes, `WebhooksController#create` dispatches the full raw payload to the registered handlers: [5](#0-4) 

Handlers, however, resolve the target repository/stack from a *different* JSON path in the same body — `repository.full_name` — with no cross-check against `repository.owner.login` used for signature selection: [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` simply splits `full_name` on `/` and does a direct lookup, with no relation to the organization that was authenticated: [8](#0-7) 

**The broken binding (equality that should hold but doesn't):**
`repository_owner` used to select the verifying secret (`params.dig('repository','owner','login')`) must equal the owner encoded in `repository.full_name` used to pick the target `Repository`/`Stack`. The controller/handler pipeline never asserts this equality — an attacker fully controls the JSON body and can set these two fields independently.

Before the attacker's payload: a legitimate webhook payload from GitHub always has `repository.owner.login` consistent with `repository.full_name`'s owner segment, because GitHub itself generates and signs that JSON.

After the attacker's crafted request: the attacker (who administers a GitHub organization "OrgA" that is legitimately configured in this multi-tenant Shipit instance, and therefore knows OrgA's `webhook_secret`) POSTs directly to `/webhooks` (bypassing GitHub) with:
```json
{
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/target-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-controlled-sha>"
}
```
signed with `sha1=HMAC(OrgA_webhook_secret, raw_body)`. `verify_signature` picks `Shipit.github(organization: "orga")`, verifies successfully with OrgA's real secret, and `create` then hands the whole body to `Webhooks::Handlers::PushHandler`, which resolves the stack via `full_name = "orgb/target-repo"` — an organization/repository the attacker has no legitimate access to — and calls `stack.sync_github(expected_head_sha: ...)`.

### Impact Explanation
This breaks the cross-repository/cross-organization trust boundary of a single Shipit instance shared by multiple GitHub organizations (a supported configuration per `docs/setup.md`'s "Using Multiple Github Applications" section). An attacker who is a legitimate admin of one onboarded org (and thus holds that org's real `webhook_secret`, not a Shipit credential, `GITHUB_TOKEN`, or `ApiClient` token) can forge webhook events that are authenticated as their own org but that act on a completely different org/repository's stacks — triggering unauthorized syncs and downstream deploy/rollback flows for repositories they do not control. This is a cross-repository write / unauthorized-action vector that matches the "Critical: cross-repository writes / unauthorized deploy" impact category.

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured for multiple GitHub organizations (an explicitly documented, supported setup), and (2) the attacker to be a legitimate administrator/owner of at least one of those organizations (able to read/know that org's own `webhook_secret`, which they configured themselves when installing the GitHub App — this is not a Shipit credential and requires no compromise of Shipit or GitHub itself). Given those preconditions, exploitation is trivial: a single crafted HTTP POST with a valid HMAC for their own org but a mismatched `repository.full_name`.

### Recommendation
Bind the two identities together explicitly: after selecting the organization used for signature verification, require that `repository.full_name`'s owner segment (and/or `repository.owner.login`) equals the verified `repository_owner`, and reject (422) any payload where they differ. Equivalently, resolve the target `Repository`/`Stack` using the same `repository_owner` value that was authenticated, rather than independently re-deriving it from `repository.full_name` inside each handler.

### Proof of Concept
1. Configure Shipit with two organizations, `orga` and `orgb`, each with a distinct `webhook_secret` (per `docs/setup.md` multi-org example).
2. As an attacker who administers `orga` (and thus knows `orga`'s `webhook_secret`), compute `sha1=HMAC-SHA1(orga_webhook_secret, body)` for the body below.
3. POST directly to the Shipit `/webhooks` endpoint with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/target-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
4. `WebhooksController#verify_signature` selects `Shipit.github(organization: "orga")` and successfully verifies the signature against `orga`'s secret.
5. `PushHandler` resolves `Repository.from_github_repo_name("orgb/target-repo")` and calls `stack.sync_github(expected_head_sha:)` on `orgb`'s stack — an action the attacker has no legitimate authority over.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
