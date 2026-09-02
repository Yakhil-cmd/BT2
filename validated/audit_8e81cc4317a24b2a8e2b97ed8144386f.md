### Title
Webhook signature verification binds to attacker-controlled `repository.owner.login`, not to the `repository.full_name` the handler actually acts on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment, `WebhooksController#verify_signature` picks the HMAC secret to validate a webhook against using `repository_owner`, a value read straight out of the same untrusted JSON body it is about to verify. The event handlers, however, resolve the `Repository`/`Stack` to mutate using a *different* field from the same body: `repository.full_name`. Because nothing binds these two fields together, a party who legitimately controls the webhook secret for **one** organization configured on the instance can forge a validly-signed webhook whose `repository.owner.login` matches their own org (so it passes signature verification) while `repository.full_name` points at a stack belonging to a **different** organization, causing Shipit to act on that victim repository's data.

### Finding Description
`WebhooksController#verify_signature` does: [1](#0-0) 

`repository_owner` is derived purely from the incoming, not-yet-verified payload: [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up a per-organization config block (`secrets.github[organization]`) and builds a `GitHubApp` scoped to that organization's own `webhook_secret`: [3](#0-2) 

The signature check itself is a straightforward HMAC compare of the secret **selected by `repository_owner`** against the raw body: [4](#0-3) 

Once verification passes, event handlers (e.g. `PushHandler`) resolve the actual `Repository`/`Stack` to act on using a *different* field from the same body — `repository.full_name` — with no re-check that its owner matches the organization whose secret was used to verify the request: [5](#0-4) [6](#0-5) [7](#0-6) 

This breaks the equality that should hold: `organization authenticated by signature == organization owning the repository being written`. Because `repository.owner.login` (used for key selection) and `repository.full_name` (used for target resolution) are independent, attacker-controlled fields inside the same signed blob, a valid signature from organization A's secret does not guarantee the payload actually concerns organization A's repository.

### Impact Explanation
On a Shipit instance configured for multiple GitHub organizations (the `secrets.github` keyed-by-org schema explicitly supported by `Shipit.github_app_config`), anyone who legitimately controls a webhook secret for *one* onboarded organization (e.g., an org admin who created their own GitHub App and set its `webhook_secret`, which is normal, unprivileged setup for that org) can:
1. Set `repository.owner.login` = their own org (so `verify_signature` selects their known secret and passes).
2. Set `repository.full_name` = `victim-org/victim-repo` (so `PushHandler`/`Repository.from_github_repo_name` resolves and acts on the victim's `Stack`).
3. Sign the resulting body with their own secret and POST it to `/webhooks`.

This lets the attacker enqueue `stack.sync_github(expected_head_sha: ...)` (and equivalent operations in other handlers such as `status`, `check_suite`, `pull_request`) against a stack they do not own, on an arbitrary attacker-chosen `expected_head_sha`. On stacks with continuous deployment enabled, a forced sync to a chosen SHA can trigger an unauthorized deploy of that SHA once the corresponding commit is deemed deployable, i.e. cross-organization interference with another tenant's deploy pipeline without ever having credentials scoped to that tenant.

### Likelihood Explanation
This requires a Shipit deployment that hosts **multiple** organizations under the `github:` multi-org config schema, and requires the attacker to already control a valid webhook secret for at least one of those organizations (which is a normal, low-privilege configuration step for any onboarded org, not a Shipit credential). Given those two preconditions — both realistic in a shared/multi-tenant Shipit install — the exploit itself needs no special access: any observer who knows one org's webhook secret can forge the cross-org payload.

### Recommendation
After verifying the HMAC signature, re-derive the organization the payload is allowed to reference and enforce that `repository.full_name`'s owner segment equals the `repository_owner` used to select the verification key (or, equivalently, verify using the key associated with the *target* repository's actual owner rather than the attacker-supplied `repository.owner.login`/`organization.login`). Handlers resolving `Repository.from_github_repo_name(...)` should additionally assert that the resolved repository's `owner` matches the authenticated `repository_owner` from `verify_signature`.

### Proof of Concept
Given a Shipit instance configured with:
```yaml
github:
  attacker-org:
    webhook_secret: "known-to-attacker"
    ...
  victim-org:
    webhook_secret: "unknown-to-attacker"
    ...
```
1. Attacker builds a JSON push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1("known-to-attacker", raw_body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository_owner`), successfully verifies the signature against the attacker's own secret, and proceeds.
4. `PushHandler#process` resolves the target via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack — an action the attacker was never authorized to trigger.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
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
