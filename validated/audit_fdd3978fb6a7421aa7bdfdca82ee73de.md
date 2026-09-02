### Title
Webhook signature verification is bound to the payload's claimed organization, not the repository the handler actually writes to, allowing cross-organization/cross-repository forged events - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to verify a webhook against using the attacker-controlled `repository.owner.login`/`organization.login` field of the JSON payload. Once that check passes, the actual event handlers determine which tracked repository/stack to mutate using a *different*, independently-controlled field: `repository.full_name`. These two fields are never checked for consistency, and `GitHubApp#verify_webhook_signature` treats an org with no configured `webhook_secret` as automatically verified. This breaks the implicit trust equality "organization whose secret authenticated this request" == "repository the request is allowed to affect."

### Finding Description
`verify_signature` picks the GitHub App/secret to validate against from the payload itself: [1](#0-0) [2](#0-1) 

The verification itself is a no-op whenever the selected organization's App config has no `webhook_secret` set: [3](#0-2) 

Shipit explicitly supports multiple GitHub App/organization configurations in one instance, and per-org `webhook_secret` is optional/nilable, as shown in the dummy multi-app fixture (`OrgTwo` has `webhook_secret: # nil`): [4](#0-3) 

After `verify_signature` passes, every event handler resolves the target repository purely from `repository.full_name` in the payload — a field never checked against the organization used for signature selection: [5](#0-4) [6](#0-5) 

Because `repository.owner.login`/`organization.login` (used only for secret selection) and `repository.full_name` (used only for identifying the write target) are two separate, independently attacker-controlled JSON fields with no cross-validation, an attacker can:
1. Set `repository.owner.login`/`organization.login` to any organization configured on the instance whose App config has a blank `webhook_secret` (a supported, documented configuration state).
2. Set `repository.full_name` to any *other* tracked repository belonging to a different, properly-secured organization in the same Shipit install.

`verify_webhook_signature` returns `true` unconditionally for the blank-secret org, and processing proceeds against the attacker-chosen `repository.full_name`, e.g. `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` on stacks belonging to the unrelated, secured repository/org.

### Impact Explanation
This lets an unauthenticated, unprivileged internet client forge webhook events (push, pull_request, status, check_suite, membership, etc.) against repositories/organizations they have no relationship to, as long as any one organization configured on the shared Shipit instance has no `webhook_secret`. Depending on the event handler reached, this can force git-sync of arbitrary tracked stacks, and — combined with `continuous_deployment` — can trigger unauthorized deploys, archive/unarchive review stacks, or mutate pull-request/commit-status state for repositories the attacker does not own, without ever needing a session, `ApiClient` token, or a GitHub App private key. This matches the "unauthorized deploy" / cross-repository-write impact tier.

### Likelihood Explanation
Any Shipit deployment that tracks more than one GitHub organization/App (a natively supported configuration, as shown by the multi-app fixtures) and has even one organization without a webhook secret configured is exploitable with a single unauthenticated HTTP POST — no reconnaissance beyond knowing which orgs/repos are tracked (which is often discoverable from the public Shipit UI). No credential, secret, or repository access is required.

### Recommendation
Never let attacker-supplied payload fields select which secret verifies the request separately from which resource the request will act on. `verify_signature` should either: (a) require a non-blank `webhook_secret` for every configured GitHub App/organization (reject rather than pass-through when unset), and/or (b) validate the `repository.owner.login`/`organization.login` value against the organization that actually owns `repository.full_name` (or better, sign/scope webhooks per-repository via GitHub Hook secrets, as already supported by `Shipit::Hook::DeliverySigner`) before dispatching to handlers.

### Proof of Concept
1. Configure a Shipit instance tracking two orgs, e.g. `SecureOrg` (has `webhook_secret`) and `OpenOrg` (no `webhook_secret`), each with tracked repositories.
2. As an anonymous attacker, POST to `/github/webhooks` with:
   - `X-Github-Event: push`
   - Body: `{"repository": {"owner": {"login": "OpenOrg"}, "full_name": "SecureOrg/target-repo"}, "ref": "refs/heads/master", "after": "<attacker-chosen sha>"}`
   - No valid `X-Hub-Signature` header (or any arbitrary value).
3. `verify_signature` resolves `repository_owner` to `"OpenOrg"`, calls `Shipit.github(organization: "OpenOrg").verify_webhook_signature`, which returns `true` because `OpenOrg`'s `webhook_secret` is blank.
4. `PushHandler` resolves `repository_name` from `repository.full_name` = `"SecureOrg/target-repo"`, finds matching stacks, and calls `stack.sync_github(expected_head_sha: ...)` — an unauthorized, unauthenticated action on `SecureOrg`'s tracked repository despite never presenting a valid signature for `SecureOrg`.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
