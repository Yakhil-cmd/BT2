### Title
Cross-tenant webhook spoofing: signature is verified against `repository.owner.login`, but the write target is selected from the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/secret to validate a webhook against using `repository.owner.login` (or `organization.login`) taken straight from the untrusted JSON body, while every webhook handler resolves the actual `Stack`/`Repository` to act on using a *different* attacker-controlled field, `repository.full_name`. Nothing enforces that these two fields refer to the same organization, so a payload can be legitimately signed for organization A yet target a stack belonging to organization B.

### Finding Description
`repository_owner` (used to select the verification secret) is read as: [1](#0-0) [2](#0-1) 

That value is used only to look up `Shipit.github(organization: repository_owner)` and its `webhook_secret` for HMAC verification via `verify_webhook_signature`: [3](#0-2) 

Note also that if the resolved organization has no `webhook_secret` configured, verification is skipped entirely (`return true unless webhook_secret`), and the docs explicitly describe the webhook secret as **optional** per-organization: [4](#0-3) , and Shipit supports hosting multiple independent GitHub organizations from one instance: [5](#0-4) .

However, every event handler (`PushHandler`, `CheckSuiteHandler`, `StatusHandler`, the `pull_request/*` handlers) determines which repository/stack to mutate using a completely independent field, `repository.full_name`, via the shared `Handler#stacks` helper: [6](#0-5) 

`PushHandler` then directly triggers a sync against whatever stack that lookup resolves to: [7](#0-6) 

The broken binding is: **organization authenticated (`repository.owner.login`, used to choose the verifying secret) ≠ repository that is written (`repository.full_name`, used to choose the target stack)**. Both fields live in the same unauthenticated-until-verified JSON body and are never cross-checked against each other.

### Impact Explanation
On a shared Shipit deployment tracking multiple GitHub organizations/repositories (the documented multi-org configuration), anyone who can produce a validly-signed (or unsigned, if that org left `webhook_secret` blank, which is explicitly optional) payload for **any one** configured organization can forge a webhook event whose `repository.full_name` names an entirely different, unrelated stack tracked by the same instance. This lets an attacker force `GithubSyncJob` runs, write forged commit statuses (`StatusHandler`), forge `check_suite` results, or drive pull-request/review-stack state machines against a victim repository/stack they have no legitimate relationship with — a cross-repository/cross-tenant write achieved purely by exploiting the weakest-secret organization on the instance. This matches the "cross-repository writes" Critical-impact category.

### Likelihood Explanation
Requires: (a) the Shipit instance to serve more than one GitHub organization (documented supported configuration), and (b) the attacker to be able to produce a signature valid for at least one of those organizations — which is trivially true if that organization has no `webhook_secret` configured (documented as optional) or if the attacker is a legitimate, low-privileged member/integrator of any one of the hosted organizations. No privileged Shipit session, `ApiClient` token, or `GITHUB_TOKEN` is required — only network access to `POST /webhooks`.

### Recommendation
Bind the two fields together: derive the verification secret (and the "owning organization" context) from `repository.full_name`'s owner instead of (or in addition to, with equality enforcement) `repository.owner.login`/`organization.login`, or reject any payload where the two disagree. Also consider making `webhook_secret` mandatory for any deployment tracking more than one GitHub organization.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `attacker-org` (no `webhook_secret` set, or one known to the attacker) and `victim-org` (tracked stack `victim-org/victim-repo`), per the multi-org config format in `config/secrets.development.example.yml`.
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"},
  "ref": "refs/heads/main",
  "after": "<sha>"
}
```
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and, since no secret is configured for it, `verify_webhook_signature` returns `true` unconditionally (`app/controllers/shipit/webhooks_controller.rb` lines 24-30, `lib/shipit/github_app.rb` lines 76-83).
4. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb` lines 32-38) and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack (`app/models/shipit/webhooks/handlers/push_handler.rb` lines 12-17), even though the request was only "authenticated" for `attacker-org`.

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

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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
