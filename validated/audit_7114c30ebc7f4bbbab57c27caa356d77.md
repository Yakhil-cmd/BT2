### Title
Webhook signature is verified against the `repository.owner.login` organization while every handler acts on the independently-attacker-controlled `repository.full_name` field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken straight from the unauthenticated JSON body. [1](#0-0) [2](#0-1)  Every event handler, however, resolves the repository/stack that actually gets mutated from a different field of the same body: `repository.full_name`. [3](#0-2)  These two attacker-controlled fields are never cross-validated against each other, exactly analogous to the referenced report's pattern where the field that gates a check (`ex`/`tokensBought`) is different from the field that is actually acted upon (`tokenIds`).

### Finding Description
`Shipit::GithubApp#verify_webhook_signature` short-circuits to `true` whenever the selected organization's `webhook_secret` is blank:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [4](#0-3) 
which org's config (and therefore whether its `webhook_secret` is even set) is chosen solely by `repository_owner`, itself read from the unverified JSON payload:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

Shipit is explicitly designed to be multi-tenant: the sample configuration shows multiple organizations independently configured, each with its own optional `webhook_secret`:
```yaml
github:
  somegithuborg:
    webhook_secret: # nil
  someothergithuborg:
    webhook_secret: # nil
``` [5](#0-4) 

Once `verify_signature` passes, `WebhooksController#create` dispatches to `Shipit::Webhooks.for_event(event)` handlers with the raw, still-attacker-controlled `params`. [6](#0-5)  Every handler resolves the target repository independently:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the mutated stack) are two independent, attacker-supplied keys in the same JSON body, an attacker can craft a payload where:
- `repository.owner.login` = the name of any tenant organization on the instance that happens to have no `webhook_secret` configured (a documented, supported configuration state, as shown by the sample secrets file), causing `verify_webhook_signature` to unconditionally return `true`, and
- `repository.full_name` = a fully different, securely-configured organization's tracked repository.

The signature check therefore validates nothing meaningful about the repository actually being acted upon; the trust binding "organization whose secret authenticated this request" == "repository being written to" is broken.

### Impact Explanation
With this decoupling, an unauthenticated attacker can drive any handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`, `PullRequest` handlers, etc.) against a repository/stack belonging to an organization whose webhook_secret is properly configured, as long as any other organization on the same Shipit instance is configured without one:
- `PushHandler` forces `sync_github` on stacks of the targeted repository. [7](#0-6) 
- Other handlers (membership, pull request status, check suite) mutate `Team`, `User`, `Commit`/`Status`, and `MergeRequest` state without any legitimate GitHub-signed proof tying the request to the real repository's GitHub App.

This is a High-severity issue under the rules: unauthenticated forgery of repository/stack state via the webhook path, using the engine's own multi-tenant credential-selection logic against itself.

### Likelihood Explanation
Exploitability is conditioned on the deployment hosting at least two GitHub organizations where one has no `webhook_secret` configured — a state the shipped sample configuration explicitly supports and does not warn against. Any instance serving more than one org where one tenant skips webhook secret setup is immediately exposed for every other, properly-configured, tenant's repositories.

### Recommendation
Bind signature verification to the same repository identity the handlers use, not just to the owner/org field:
- Verify the payload against `repository.full_name` (or require `repository.owner.login` and `repository.full_name`'s owner segment to match) rather than trusting `repository.owner.login` alone.
- Reject webhooks for organizations without a configured `webhook_secret` instead of treating an absent secret as automatically "verified" (`return true unless webhook_secret`), or scope verification per-repository instead of per-organization based purely on an untrusted body field.

### Proof of Concept
1. Configure Shipit with two orgs: `victim-org` (has a `webhook_secret`) and `no-secret-org` (no `webhook_secret`), both mountable via `Shipit.github`.
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "no-secret-org" },
    "full_name": "victim-org/tracked-repo"
  }
}
```
without any valid `X-Hub-Signature` (or an arbitrary one).
3. `verify_signature` resolves `Shipit.github(organization: "no-secret-org")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally. [8](#0-7) 
4. `PushHandler` then looks up stacks for `victim-org/tracked-repo` via `repository.full_name` and triggers `sync_github`, even though the request was never authenticated by `victim-org`'s GitHub App. [7](#0-6)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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
