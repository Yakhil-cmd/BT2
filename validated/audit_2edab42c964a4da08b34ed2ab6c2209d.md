### Title
Webhook signature verification is keyed on the wrong organization, allowing forged push/webhook events against a different (secured) repository — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
The bug class in the report is a mismatch between what a security check actually authorizes and what the subsequent code acts on (`transferFrom` checked the wrong `from`/allowance instead of the actual transfer target). The analog in `shipit-engine` is in `WebhooksController#verify_signature`: it selects which GitHub App/webhook secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`), but the handlers that actually act on the payload (`Shipit::Webhooks::Handlers::Handler#repository_name`, used by `PushHandler`) resolve the target `Repository`/`Stack` from a *different* field of the same attacker-controlled JSON body: `repository.full_name`. Nothing ties these two fields together, so the "organization whose secret authenticated the request" and "the repository that is actually written to/synced" can be made to diverge.

### Finding Description
`WebhooksController#verify_signature` computes the signing organization purely from the untrusted request body: [1](#0-0) [2](#0-1) 

It then fetches the `GitHubApp` config for that organization and calls `verify_webhook_signature`: [3](#0-2) 

Critically, `return true unless webhook_secret` (line 77) means that if **any** configured GitHub organization in a multi-org Shipit installation has no `webhook_secret` set — which the setup docs explicitly call optional — every request whose computed `repository_owner` matches that organization is treated as verified, signature or not.

Meanwhile, the actual event processing resolves the target repository from a *different* JSON field, `repository.full_name`, not from `repository.owner.login`: [4](#0-3) [5](#0-4) 

`Repository.from_github_repo_name` just splits `owner/name` out of that string and looks up the `Repository`/`Stack` by it: [6](#0-5) 

Because the raw JSON body is fully attacker-controlled (this is a public, unauthenticated HTTP endpoint gated only by the HMAC check), an attacker can set `repository.owner.login` to the organization lacking a `webhook_secret` (so verification trivially passes) while setting `repository.full_name` to `victim-org/victim-repo`, an entirely different, secured organization's repository. The equality that should hold — "the organization whose secret authenticated this payload" == "the repository the payload is allowed to act on" — is never enforced.

### Impact Explanation
In a multi-organization Shipit deployment (documented under "Using Multiple GitHub Applications" in `docs/setup.md`), if at least one configured organization omits `webhook_secret` (explicitly described as optional), an unprivileged attacker can forge a `push` (or other handled) webhook event that is accepted as "verified" for that unsecured organization, while the embedded `repository.full_name` points at a stack belonging to a different, properly-secured organization. `PushHandler#process` will then call `stack.sync_github(expected_head_sha: params.after)` for that victim stack using attacker-chosen `ref`/`after` values, causing Shipit to treat an unauthenticated request as a trusted GitHub webhook for a repository/organization it was never signed for. This crosses the organization-authentication boundary the signature check exists to enforce, and can drive stack sync/deploy-adjacent behavior (`sync_github`) for a repository the attacker does not control and was not the signer of.

### Likelihood Explanation
Likelihood is moderate and configuration-dependent: it requires a multi-organization Shipit deployment where at least one configured GitHub organization has no `webhook_secret` set (a state the official docs present as a normal, supported, optional configuration). Given that, exploitation requires no credentials, no repository access, and no GitHub App private key — only crafting an HTTP POST with a controlled JSON body to the public `/webhooks` endpoint.

### Recommendation
Bind the organization used to select the verifying `GitHubApp`/secret to the *same* field the handlers use to resolve the acted-upon repository (`repository.full_name`'s owner segment), and require that they be consistent. Additionally, do not implicitly treat a missing `webhook_secret` as "verification passes" for organizations that are part of a multi-org configuration where sibling organizations do have secrets configured — require an explicit opt-in for unauthenticated webhooks, or refuse to process events whose declared repository owner does not match the repository actually resolved from `full_name`.

### Proof of Concept
Given a Shipit config with two orgs:
```yaml
github:
  unsecured-org:
    app_id: 1
    installation_id: 1
    webhook_secret: # left blank, per docs "optional"
  victim-org:
    app_id: 2
    installation_id: 2
    webhook_secret: real-secret
```
An attacker sends (no `X-Hub-Signature` needed):
```
POST /webhooks
X-Github-Event: push

{
  "repository": {
    "owner": {"login": "unsecured-org"},
    "full_name": "victim-org/victim-repo"
  },
  "ref": "refs/heads/main",
  "after": "deadbeef..."
}
```
`repository_owner` resolves to `unsecured-org` → `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`) → request passes verification → `PushHandler` resolves the target stack via `repository.full_name` = `victim-org/victim-repo` → `stack.sync_github(expected_head_sha: "deadbeef...")` is invoked for the victim organization's stack, despite the request never having been signed by `victim-org`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
