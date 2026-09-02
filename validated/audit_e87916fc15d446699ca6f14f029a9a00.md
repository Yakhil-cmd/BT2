### Title
Webhook organization used for signature verification is never bound to the repository/commit the handler mutates, allowing cross-organization status/push forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to use for HMAC verification based on a single field extracted from the attacker-supplied JSON body — `repository.owner.login` (or `organization.login`) — but the handlers invoked afterwards act on an entirely independent binding: `Handler#repository_name` (`repository.full_name`) for `PushHandler`/`CheckSuiteHandler`, or, worse, no repository binding at all for `StatusHandler`. Because `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the selected organization has no `webhook_secret` configured — a state the engine's own docs and sample config explicitly support — an unauthenticated attacker who knows the name of any org configured in `Shipit.github` without a secret can post a raw HTTP request to `/webhooks` that passes verification for that org while the payload's `repository`/`sha` fields target a completely different, unrelated organization's stacks and commits.

### Finding Description
`verify_signature` resolves the authenticating organization purely from the payload: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` bypasses HMAC checking entirely when no secret is configured for that resolved organization: [3](#0-2) 

The engine's own setup documentation and shipped sample secrets file document `webhook_secret` as optional, i.e., a supported, documented configuration state, not a host misconfiguration outside the documented setup: [4](#0-3) [5](#0-4) 

Once past `verify_signature`, the handlers resolve *what to act on* from separate, unchecked fields of the same attacker-controlled body. `Handler#repository_name` pulls `repository.full_name` (independent of `repository.owner.login` used above) to scope `PushHandler`/`CheckSuiteHandler`: [6](#0-5) 

Worse, `StatusHandler#process` performs **no repository/organization scoping whatsoever** — it matches any `Commit` in the entire database by raw SHA and writes a status onto it: [7](#0-6) 

This breaks the trust binding **"organization authenticated == repository/commit written."** The organization used to pick (or bypass) the signature check is never required to equal the organization that owns the repository/commit the handler subsequently mutates.

### Impact Explanation
An unauthenticated internet requester (no Shipit session, no `ApiClient` token, no GitHub App key) who only needs to know: (a) the name of one Shipit-configured GitHub organization that lacks a `webhook_secret`, and (b) a target commit SHA belonging to any stack tracked by the Shipit instance (SHAs are public, visible on GitHub), can:
- Forge a `status` webhook where `repository.owner.login` = the no-secret org (bypassing HMAC verification) and `sha` = a commit belonging to a *different*, properly-secured organization's stack, injecting a fabricated passing/failing CI status via `Commit#create_status_from_github!` — a cross-repository write that can unblock merge/deploy gating logic that depends on GitHub status checks.
- Similarly forge `push`/`check_suite` events by setting `repository.owner.login` to the no-secret org while `repository.full_name` names a protected org's repository, causing `stack.sync_github(expected_head_sha:)` or `schedule_refresh_check_runs!` to run against a stack outside the "authenticated" organization.

This is a cross-organization write achieved without any credential, matching the Critical impact bar for cross-repository writes / unauthorized deploy gating bypass.

### Likelihood Explanation
Requires only that the Shipit deployment has at least two configured GitHub organizations (a documented, supported multi-tenant setup) where at least one lacks a `webhook_secret` — an explicitly optional, documented field. No privileged access, no leaked secret, and no social engineering is required; the attacker interacts only with the public `/webhooks` endpoint.

### Recommendation
- Reject the request in `WebhooksController#verify_signature` unless `webhook_secret` is present and valid for the resolved organization; do not treat an absent secret as "verified."
- Cross-check that the organization used for signature resolution equals the owner embedded in `repository.full_name` (and any org referenced by handlers) before dispatching to handlers.
- In `StatusHandler` (and any handler lacking one), scope lookups by the verified repository/organization instead of matching commits globally by SHA.

### Proof of Concept
1. Shipit instance configures two organizations: `secured-org` (with `webhook_secret`) and `open-org` (with `webhook_secret` left blank, per documented optional setting).
2. Attacker sends, unauthenticated:
```
POST /webhooks HTTP/1.1
X-Github-Event: status

{
  "repository": {"owner": {"login": "open-org"}, "full_name": "secured-org/private-repo"},
  "sha": "<known sha of a commit tracked by a secured-org stack>",
  "state": "success",
  "context": "required-ci-check"
}
```
3. `verify_signature` resolves `repository_owner` = `open-org`, loads its GitHub App config, and `verify_webhook_signature` returns `true` unconditionally because `open-org` has no `webhook_secret` [8](#0-7) .
4. `StatusHandler#process` finds the commit by raw `sha` — with no check that it belongs to `open-org` — and records the forged status [7](#0-6) , affecting `secured-org/private-repo` despite the attacker never having a credential for `secured-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```

**File:** config/secrets.development.shopify.yml (L5-14)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
