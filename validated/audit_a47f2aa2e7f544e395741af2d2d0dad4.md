This confirms the mechanism: each configured GitHub organization has its own independent `webhook_secret` in `TOP_LEVEL_GH_KEYS` [1](#0-0) , and `Shipit.github(organization:)` selects the app config per-org [2](#0-1) . Multi-org configuration is a supported deployment mode (`test/dummy/config/secrets_double_github_app.yml`).

### Title
Cross-organization webhook confusion — signature is verified against `repository.owner.login`'s secret but handlers act on `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, derived from `params.dig('repository','owner','login')` (or `params.dig('organization','login')` as fallback) [3](#0-2) [4](#0-3) . But the downstream `Handler` base class, used by every webhook handler (push, status, check_suite, pull_request, membership, etc.), resolves the affected repository/stacks from a *different* field of the same untrusted JSON body: `payload.dig('repository', 'full_name')` [5](#0-4) . Nothing cross-checks that the owner used to select the verification secret matches the owner embedded in `full_name`.

### Finding Description
In a Shipit installation configured with multiple GitHub organizations (a supported topology, evidenced by `TOP_LEVEL_GH_KEYS` including per-org `webhook_secret`, `private_key`, `oauth` [1](#0-0)  and the fixture `test/dummy/config/secrets_double_github_app.yml`), each org authenticates independently: `verify_webhook_signature` HMACs the raw body with that org's own `webhook_secret` [6](#0-5) .

The binding that should hold is:
`organization whose secret authenticated the request == organization that owns the repository the handler mutates`

The controller computes the left side from `repository.owner.login` and picks the app/secret for that org. The handler computes the right side independently from `repository.full_name`, then does `Repository.from_github_repo_name(repository_name)` to look up `stacks` to act on [7](#0-6)  and `app/models/shipit/repository.rb" start="53" end="56" />. Since these are two separately-read fields of the same attacker-influenced JSON body, and the code never asserts `full_name.split('/').first == repository_owner`, a party who legitimately controls the webhook delivery for *any one* configured organization (i.e., knows/controls that org's `webhook_secret`, e.g. because they are an admin of a repository/org that this Shipit instance is also integrated with) can produce a request whose signature validates under "Org A" while `repository.full_name` names a repository belonging to "Org B" tracked by the same Shipit instance. The handler will then act on Org B's stack (e.g. queue a `GithubSyncJob`, create commits/statuses, mark PRs, add team members via the `membership` handler) despite the request never having been authenticated by GitHub for Org B.

### Impact Explanation
This breaks the authentication-boundary invariant that a webhook event can only affect the organization/repository it was actually signed for. Depending on which handler is triggered by the crafted event type, an attacker could inject spoofed CI `status` events for a foreign stack, force sync jobs (`GithubSyncJob`) on foreign repositories, or manipulate `membership`/`pull_request` handling for teams and stacks that belong to organizations the attacker has no relationship with — effectively an authentication bypass allowing writes into a repository/stack the attacker was never authorized against. This matches the "authentication bypass" / "cross-repository writes" impact bar for this engine.

### Likelihood Explanation
Requires (a) a multi-org Shipit deployment, and (b) the attacker controlling a genuine webhook secret for at least one of the configured organizations (e.g. because they legitimately administer a repo/org that is also wired into the same Shipit instance, or because Shipit permits organizations without `webhook_secret` set at all — `verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank [8](#0-7) , which is exactly the config shown in `secrets_double_github_app.yml` where `webhook_secret` is left nil for both orgs). In that documented/tested configuration, signature verification is a no-op for any organization whose `webhook_secret` is unset, while `repository.full_name` can point at a *different*, secured organization's repository — letting an unauthenticated caller act on a protected org's stacks simply by omitting a secret for one org entry.

### Recommendation
After successful signature verification, assert that the resolved `repository_owner` matches the owner embedded in `payload.dig('repository', 'full_name')` (and in `payload.dig('organization','login')` if present) before dispatching to handlers; reject the event otherwise. Additionally, disallow organizations with a blank `webhook_secret` from coexisting with organizations that have one configured, or require `webhook_secret` to be mandatory in multi-org setups.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgOne` (no `webhook_secret`, as allowed by `secrets_double_github_app.yml`) and `OrgTwo` (real repos Shipit tracks, with or without secret).
2. POST to `/webhooks` with header `X-Github-Event: push`, `X-Hub-Signature` set to anything (or omitted), and a body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgOne" },
    "full_name": "OrgTwo/victim-repo"
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: "OrgOne")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally [8](#0-7) .
4. The `push` handler resolves `repository_name` as `"OrgTwo/victim-repo"` and enqueues a `GithubSyncJob`/updates commits for `OrgTwo`'s tracked stack [9](#0-8) , even though the request was never signed by GitHub on behalf of `OrgTwo`.

### Citations

**File:** lib/shipit.rb (L62-63)
```ruby
  GithubOrganizationUnknown = Class.new(StandardError)
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
```

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
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
