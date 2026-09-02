### Title
Webhook signature is verified against `repository.owner.login`, while the repository actually mutated is looked up from the unauthenticated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This mirrors the code-423n4 report's bug class: a value that gates access ("mintable" limit read from a hardcoded field / one binding) diverges from the value that is actually enforced/acted upon elsewhere ("staking limit" for the same knot). In `shipit-engine`, the field used to select *which* GitHub App/organization's `webhook_secret` authenticates a webhook (`repository.owner.login`) is not the same field used by every event handler to decide *which* `Stack`/`Repository` gets mutated (`repository.full_name`). Both fields live in the same attacker-suppliable JSON body, so the "authenticated organization" and the "repository that is written" are two independent, unauthenticated inputs that are never checked against each other.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App configuration (and thus the HMAC secret) using `repository_owner`, itself computed as: [1](#0-0) 

```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

That value is fed into `Shipit.github(organization: repository_owner)`, and the resulting app's `webhook_secret` verifies `X-Hub-Signature` over the raw body: [2](#0-1) 

Meanwhile, every webhook handler (`PushHandler`, `PullRequest::*Handler`, etc.) resolves the target `Repository`/`Stack` from a *different* field of the same payload, `repository.full_name`: [3](#0-2) [4](#0-3) 

`repository.owner.login` and the owner segment of `repository.full_name` are two independent JSON leaves. Nothing in the controller or the handlers cross-checks that `repository.full_name` actually starts with `repository.owner.login`. GitHub itself always keeps them consistent, but an attacker forging a request body controls both fields freely.

`Shipit.github` resolves the app config per-organization from `secrets.github`, and if that org is configured with a blank `webhook_secret`, `GithubApp#verify_webhook_signature` short-circuits to `true`: [5](#0-4) [6](#0-5) 

So the binding that should hold is:
`organization whose secret authenticated the request == organization that owns the repository being mutated`

If a multi-org Shipit deployment has *any* configured organization with a blank/absent `webhook_secret` (a supported, documented configuration - see `config/secrets.development.shopify.yml`, which ships `webhook_secret:` as `nil`), an attacker can set `repository.owner.login`/`organization.login` to that unauthenticated org (making `verify_signature` pass unconditionally) while setting `repository.full_name` to `victim-org/victim-repo`, an entirely different, properly configured organization's repository. The handler will act on `victim-org/victim-repo` using data from a request that was never actually verified for that organization. [7](#0-6) 

### Impact Explanation
This breaks the authentication boundary the whole webhook pipeline relies on: an attacker with no GitHub credentials for `victim-org` can inject fabricated `push`, `pull_request`, `status`, or `check_suite` events for that org's stacks by picking a "helper" organization whose webhook secret is unset. Depending on the event type, this can trigger `sync_github` against arbitrary commits, alter `PullRequest`/`MergeRequest` state (`ReviewStackAdapter#find_or_create!`, `archive!`, label handling), or inject fabricated commit statuses — all without ever supplying a valid signature for `victim-org`. This crosses the "unauthorized...deploy" / "read of stack state" classes called out as in-scope impact, since forged push/status events can influence which commit is considered deployable and drive `trigger_continuous_delivery`.

### Likelihood Explanation
Exploitability is entirely conditioned on operational configuration: it requires the multi-org `secrets.github` schema to be in use (documented and supported) with at least one configured organization whose `webhook_secret` is blank/unset — which is exactly what the shipped `config/secrets.development.shopify.yml` template shows (`webhook_secret: # nil`) and is plausible in real deployments during app setup/rotation. Given that dependency, the exploit path itself requires no privileges (any internet client can POST to the public webhooks endpoint). This is a realistic but configuration-dependent likelihood, hence Medium rather than Critical-by-default.

### Recommendation
Do not select the verifying organization from unauthenticated payload fields that differ from the field used to determine the mutated resource. Concretely:
- Derive `repository_owner` (used for `Shipit.github(organization:)`) from the same field the handlers use to resolve the target repository (`repository.full_name`'s owner segment), or better, verify the signature against **every** configured organization's secret that could plausibly own the resolved repository, and reject if none match.
- Treat a blank/absent `webhook_secret` for any organization as a hard misconfiguration (raise/alert) rather than silently auto-passing verification (`return true unless webhook_secret` in `GithubApp#verify_webhook_signature`).
- After verification, assert that `repository.owner.login`/`organization.login` and the owner segment of `repository.full_name` agree; reject the webhook otherwise.

### Proof of Concept
Given a `secrets.yml` with two orgs configured, e.g.:
```yaml
github:
  helper-org:
    app_id: 1
    installation_id: 1
    webhook_secret:        # blank/unset
  victim-org:
    app_id: 2
    installation_id: 2
    webhook_secret: real-secret
```
An attacker sends:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything
Body:
{
  "organization": { "login": "helper-org" },
  "repository": { "owner": { "login": "helper-org" }, "full_name": "victim-org/some-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
`verify_signature` calls `Shipit.github(organization: 'helper-org')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (bogus) `X-Hub-Signature`. `PushHandler#stacks` then resolves `Repository.from_github_repo_name('victim-org/some-repo')` and processes the forged push against the real `victim-org` stack, even though the request was never verified against `victim-org`'s real webhook secret.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** docs/setup.md (L181-209)
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
