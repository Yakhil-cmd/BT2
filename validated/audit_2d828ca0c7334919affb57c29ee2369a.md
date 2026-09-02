Confirmed: `Handler#repository_name` (used by all handlers, e.g. `PushHandler`, `StatusHandler`, `MembershipHandler`) resolves the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')`, while `WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to authenticate the request against using a *different* field, `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Webhook signature is verified against an org selected from an unverified field, decoupled from the repository the payload actually mutates - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment (`config/secrets.yml` `github:` keyed by org, as documented and tested), `WebhooksController#verify_signature` picks the `GitHubApp`/`webhook_secret` used to authenticate the inbound webhook from `repository_owner`, which is read straight out of the *unverified* JSON body (`repository.owner.login` or `organization.login`). Every event handler, however, resolves the actual `Repository`/`Stack` to mutate from a different field in the same unverified body: `repository.full_name` (`Handler#repository_name`). These two fields are never cross-checked against each other, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever the selected organization has no `webhook_secret` configured (`webhook_secret` is documented as "optional").

### Finding Description
`Shipit.github(organization:)` supports per-organization GitHub Apps, each with its own `webhook_secret`, `app_id`, etc. [4](#0-3)  `docs/setup.md` and `config/secrets.development.shopify.yml`/`secrets_double_github_app.yml` show this is a first-class, tested configuration (`Shipit.github(organization: 'OrgOne')` vs `Shipit.github(organization: 'OrgTwo')`, potentially with differing/absent secrets). [5](#0-4) 

`WebhooksController#verify_signature` computes `repository_owner` from the raw, not-yet-authenticated request body, and immediately uses it to fetch the app/secret that is supposed to authenticate that very body:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [1](#0-0) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` when no `webhook_secret` is configured for that organization:
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [6](#0-5) 

Once verification passes (or is bypassed), `WebhooksController#create` dispatches the *entire, still-untrusted-as-a-whole* payload to handlers:
```
Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
``` [7](#0-6) 

All handlers (`PushHandler`, `StatusHandler`, `MembershipHandler`, PR handlers, etc.) look up the target repository/stack via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')`—an entirely separate JSON field from the one used to pick the verifying secret:
```
def repository_name
  payload.dig('repository', 'full_name')
end
``` [8](#0-7) 

Because the field used to choose the *authenticating organization* (`repository.owner.login`) and the field used to choose the *repository actually written to* (`repository.full_name`) are two independent, attacker-influenced fields inside the same JSON body, an attacker who can get a payload authenticated against a "weak" org config (one with no `webhook_secret`, or whose secret they otherwise possess) can set `repository.full_name` to point at a repository/stack belonging to a completely different, properly-secured organization also configured in the same Shipit instance. The verification step never re-checks that the org used to authenticate matches the org that owns the repository being acted upon. This is exactly the class of bug described in the referenced report: an ID/identity used for a trust decision (there, `engine.nft`; here, the authenticating organization) is not bound to the entity the state-changing operation actually targets (there, the CDP owner; here, the target `Stack`/`Repository`).

### Impact Explanation
This breaks the equality that should hold: `organization authenticated == organization owning the repository written`. If any org configured in a multi-tenant Shipit instance has no `webhook_secret` set (an explicitly supported/optional configuration per `docs/setup.md` and the example secrets files), an attacker can send a completely unsigned/forged webhook request that is "verified" against that org (bypass via `return true unless webhook_secret`), while `repository.full_name` names a stack owned by a different, secured organization. This lets an unauthenticated attacker: trigger `PushHandler` to enqueue `GithubSyncJob` and mutate deployment state for another org's stack; inject fabricated commit `status` entries via `StatusHandler` (potentially bypassing CI gating for deploys); or invoke `MembershipHandler`/PR handlers to create teams, add/remove members, or otherwise manipulate cross-org state — all without ever possessing the target org's real webhook secret. This is a cross-repository/cross-organization write achieved purely by exploiting the mismatch between the authentication-selecting field and the mutation-selecting field.

### Likelihood Explanation
Requires the operator to run Shipit against more than one GitHub organization (a supported and documented configuration) with at least one of the organizations lacking a `webhook_secret` (explicitly called out as "optional" in `docs/setup.md`). Given that setup, exploitation requires no credentials whatsoever — only crafting an HTTP POST to the public `/webhooks` endpoint with a `repository.owner.login`/`organization.login` set to the secret-less org and a `repository.full_name` pointing at the victim org's repo. No `ApiClient` token, session, or GitHub App key is needed, satisfying the unprivileged-attacker requirement.

### Recommendation
Bind the field used to select the verifying organization to the field used to determine the acted-upon repository: derive both from the same, single source (`repository.full_name`'s owner segment), or, after verifying, assert that the resolved `Repository#owner` for `repository.full_name` matches `repository_owner`/the app the signature was checked against, rejecting the request otherwise. Additionally, treat a missing per-organization `webhook_secret` as a hard misconfiguration for multi-org setups rather than an automatic "verified" pass, or require an explicit opt-in flag to accept unsigned webhooks for a given org.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.yml`: `SecureOrg` (has stacks and a real `webhook_secret`) and `OpenOrg` (also configured, but with `webhook_secret` left blank/unset, as the docs mark it "optional").
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "OpenOrg" },
    "full_name": "SecureOrg/victim-repo"
  }
}
```
No `X-Hub-Signature` header (or an arbitrary one) is required.
3. `verify_signature` computes `repository_owner == "OpenOrg"`, calls `Shipit.github(organization: "OpenOrg")`, whose `verify_webhook_signature` returns `true` unconditionally because `OpenOrg` has no `webhook_secret` — request passes. [9](#0-8) 
4. `PushHandler` resolves `Repository.from_github_repo_name("SecureOrg/victim-repo")` via `Handler#repository_name` and enqueues `GithubSyncJob`/mutates the `SecureOrg` stack — an attacker with no relationship to `SecureOrg` has forced state changes on it. [10](#0-9)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** test/unit/shipit_test.rb (L11-22)
```ruby
    test ".github uses indifferent access to search through the Github applications" do
      secrets = ActiveSupport::OrderedOptions.new
      secrets.merge!(YAML.load_file('test/dummy/config/secrets_double_github_app.yml'))
      secrets.deep_symbolize_keys!
      Shipit.stubs(:secrets).returns(secrets)
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'OrgOne'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgOne))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'orgone'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :orgone))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgTwo))
      Shipit.unstub(:secrets)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
