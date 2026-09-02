### Title
Webhook signature verification is keyed on `repository.owner.login` while event handlers act on `repository.full_name`, allowing cross-organization stack writes when any configured GitHub organization has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which HMAC secret) to validate the inbound webhook against based solely on `repository.owner.login` (or `organization.login`) taken from the attacker-supplied JSON body itself. The actual event handlers (`PushHandler`, `pull_request/*` handlers) then act on a completely independent field from the very same body, `repository.full_name`, to resolve the `Repository`/`Stack` that gets mutated. Because these two fields are never cross-checked, and because `GitHubApp#verify_webhook_signature` returns `true` (i.e., skips verification entirely) whenever the resolved organization has no `webhook_secret` configured, an attacker can pick an organization with no configured secret for the "authenticating" field while pointing `full_name` at a completely different, secret-protected organization's repository.

### Finding Description
The controller resolves the org used for signature verification like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the untrusted JSON body (`params.dig('repository', 'owner', 'login')`), and is used to pick the `GitHubApp` instance: [3](#0-2) 

Signature verification for that org is then performed as: [4](#0-3) 

Note `return true unless webhook_secret` — if the organization resolved from `repository.owner.login` has no `webhook_secret` configured (a supported, non-error configuration state per `github_app_config`), signature verification is bypassed unconditionally for the whole request.

Meanwhile, the event handlers that actually mutate state resolve the target repository from a *different* field of the same JSON body — `repository.full_name` — with no relation enforced back to `repository.owner.login`: [5](#0-4) [6](#0-5) [7](#0-6) 

The binding that should hold is:
`organization used to select/verify the webhook secret == organization that owns the repository being written`

Nothing in the code enforces `repository.full_name.split('/').first == repository.owner.login`. An attacker who knows the JSON shape can set `repository.owner.login` (and thus `organization` used by `Shipit.github`) to an organization that has no `webhook_secret` configured in `Shipit.secrets.github`, while setting `repository.full_name` to `"other-org/target-repo"` for a *different*, protected organization whose stacks actually exist in the Shipit instance. `verify_signature` will resolve `Shipit.github(organization: "org-with-no-secret")`, call `verify_webhook_signature`, which immediately returns `true` because `webhook_secret` is blank for that org — no HMAC check ever touches the real target organization's secret. The request then proceeds to `WebhooksController#create`, and `PushHandler`/pull-request handlers look up the stack using `repository.full_name`, i.e., the *other* organization's repository, and execute `stack.sync_github`, archive/unarchive review stacks, update pull requests, etc. against a repository the attacker never proved control of.

This is directly analogous to the reported bug class: two values derived from the same input are supposed to be consistent by construction (fee vs. finalGrant; grant.value/100 vs. remainder), but the code trusts an implicit invariant between two independently-read fields instead of validating it, and an attacker can break that invariant by supplying inconsistent values.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary explicitly called out as in-scope. If any organization configured on the Shipit instance lacks a `webhook_secret` (a legitimate, documented configuration path via `github_app_config`), an unauthenticated, unprivileged attacker can forge webhook deliveries that are accepted with zero valid signature and cause writes (deploy/rollback triggering `sync_github`, review-stack archive/unarchive, pull-request state changes) against stacks belonging to a different, secret-protected organization. This qualifies as an unauthorized cross-repository/cross-organization mutation of Shipit state driven entirely by attacker-controlled input with no valid credential presented for the targeted organization.

### Likelihood Explanation
Exploitability depends entirely on deployment configuration: it requires that at least two GitHub organizations/apps be configured on the same Shipit instance (`github_organizations` returning more than one entry) and that at least one of them has no `webhook_secret` set. Single-organization deployments (`github_default_organization` nil, using the legacy top-level `secrets.github` schema) are not affected because there is only one org to pick from. This is a plausible but non-default multi-tenant configuration, so likelihood is moderate rather than certain, and full confirmation would require checking a concrete instance's `secrets.github` layout, which is outside what the static index can show.

### Recommendation
Do not select the signature-verification organization from attacker-controlled JSON fields that are also used later to resolve the write target without validating consistency between them. At minimum: (1) require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`), and (2) after determining `repository_owner` for signature verification, assert that it matches the owner segment of `repository.full_name` before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
Given a Shipit instance configured with two GitHub orgs in `secrets.github`: `no_secret_org` (no `webhook_secret` key) and `victim_org` (has stacks tracking `victim_org/real-repo`):

```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything   # ignored, verification short-circuits

{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "no_secret_org" },
    "full_name": "victim_org/real-repo"
  }
}
```

`repository_owner` resolves to `"no_secret_org"` [2](#0-1) , `Shipit.github(organization: "no_secret_org")` returns a `GitHubApp` with blank `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally [4](#0-3) . The request passes through to `PushHandler`, which resolves `Repository.from_github_repo_name("victim_org/real-repo")` [5](#0-4)  and enqueues `stack.sync_github(expected_head_sha: "deadbeef")` for `victim_org`'s stacks, with no valid signature ever checked against `victim_org`'s secret.

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
