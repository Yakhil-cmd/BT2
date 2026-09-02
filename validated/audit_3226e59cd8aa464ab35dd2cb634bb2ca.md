## Title
Webhook signature is verified against the organization named in `repository.owner.login`, while event handlers act on the unrelated `repository.full_name` from the same untrusted payload — cross-organization forged webhook events - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate `X-Hub-Signature` against using an organization name pulled straight out of the unauthenticated JSON body. Every webhook handler then independently re-parses the same body's `repository.full_name` to decide which `Repository`/`Stack` gets mutated. Nothing forces these two attacker-controlled fields to agree, so a signature that is valid for Org A can be attached to a payload whose `repository.full_name` points at Org B, letting the request act on Org B's stacks without ever knowing Org B's secret.

### Finding Description
`verify_signature` derives the authenticating organization purely from request body fields: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` (or `organization.login`) — both are values the requester fully controls inside the JSON body, not header/URL data. `Shipit.github(organization: repository_owner)` then looks up that organization's own `webhook_secret` and `verify_webhook_signature` checks the header against it: [3](#0-2) 

Meanwhile every state-changing handler (`PushHandler`, the `PullRequest::*Handler`s, etc.) resolves the actual `Repository`/`Stack` to act on from a *different* field of the *same* body — `repository.full_name` — completely independent of `repository.owner.login`: [4](#0-3) [5](#0-4) [6](#0-5) 

Shipit explicitly supports hosting multiple GitHub organizations from one instance, each with its own independently-configured `webhook_secret`: [7](#0-6) [8](#0-7) 

This is the exact bug class from the report: a value used to satisfy a validating condition (`reward`/`balance` comparison in the original report; here, the organization used to pick the verifying secret) is not the same value that is actually acted upon (the `eUSDShare` transferred; here, the `repository.full_name` that gets synced/archived/unarchived). The equality that should hold — `organization_that_authenticated == owner(repository_that_is_written)` — is never enforced.

### Impact Explanation
An attacker who controls (or is a legitimate installer for) any single organization configured on the Shipit instance — call it Org A — can sign a payload with Org A's `webhook_secret`, satisfying `verify_signature`, while setting `repository.full_name` to `"OrgB/some-repo"`. The `PushHandler` (or PR handlers) will then locate and mutate Org B's `Stack`/`ReviewStack` — enqueuing `GithubSyncJob`, archiving/unarchiving review stacks, or creating review stacks — even though the attacker never possessed Org B's `webhook_secret`. Depending on stack configuration (e.g. continuous deployment), a forged `push` event can trigger a real deploy pipeline for a repository/organization the attacker has no legitimate access to. This is an unauthorized cross-organization write/deploy trigger, breaking the isolation multi-org Shipit installations are supposed to provide.

### Likelihood Explanation
Any actor who is a legitimate (even low-privilege) GitHub App installer/admin for *one* organization on a multi-org Shipit deployment, or who obtains any single org's `webhook_secret` (which per `docs/setup.md` is optional and may be unset for some orgs, in which case `verify_webhook_signature` returns `true` unconditionally), can immediately forge signed-looking requests targeting any *other* configured organization's repositories with a single crafted HTTP POST to `/webhooks`. No additional session, token, or GitHub write access to the victim organization is required.

### Recommendation
Bind signature verification to the same repository identity used for authorization: derive the verifying organization from `repository.full_name`'s owner segment (not a separate `owner.login`/`organization.login` field), or explicitly assert `repository.owner.login == repository.full_name.split('/').first` before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`: `OrgA` (attacker-known `webhook_secret`) and `OrgB` (victim, stacks tracking `OrgB/prod-repo`).
2. Craft a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/prod-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac(OrgA_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, validates successfully against OrgA's secret.
5. `PushHandler#process` resolves `Repository.from_github_repo_name("OrgB/prod-repo")` and calls `stack.sync_github(expected_head_sha: after)` on OrgB's stack — a write the attacker was never authorized to trigger.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
