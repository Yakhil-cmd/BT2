### Title
Webhook signature verification is bound to the attacker-supplied `repository.owner.login`/`organization.login` field while event handlers act on the independently attacker-supplied `repository.full_name` field, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, itself parsed straight out of the untrusted JSON body (`repository.owner.login`, falling back to `organization.login`). Every downstream `Shipit::Webhooks::Handlers::Handler` subclass, however, determines *which* `Repository`/`Stack` to mutate using a completely different field of the same untrusted body: `repository.full_name` (`Handler#repository_name`). These two values are never checked for consistency, so the organization whose credentials authenticated the request is not bound to the repository that the handler actually writes to.

### Finding Description [1](#0-0) 
`verify_signature` builds `github_app = Shipit.github(organization: repository_owner)` and verifies the signature using that organization's `webhook_secret`, where: [2](#0-1) 
`repository_owner` reads `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — fully attacker-controlled JSON fields, unauthenticated at this point.

The actual signature check delegates to `GitHubApp#verify_webhook_signature`: [3](#0-2) 
Critically, `return true unless webhook_secret` — if the resolved organization has no `webhook_secret` configured, verification is a no-op and always succeeds.

Meanwhile every registered handler (`PushHandler`, `StatusHandler`, `MembershipHandler`, PR handlers, etc.) resolves the target `Repository`/`Stack`/`Team` from a *different* JSON field: [4](#0-3) 
`stacks` is derived from `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')`.

`PushHandler#process` then directly triggers a GitHub sync on any stack matching that repository/branch: [5](#0-4) 

The binding that should hold is: **organization authenticated (`repository_owner` → resolved `webhook_secret`) == organization that owns the repository being written (`repository.full_name`'s owner)**. Because both values come from the same untrusted request body and are never cross-validated, an attacker can decouple them: supply a `repository.owner.login`/`organization.login` for an organization that Shipit has configured *without* a `webhook_secret` (or one whose secret the attacker otherwise knows), while setting `repository.full_name` to an entirely different, victim-owned repository that is actually tracked in Shipit with real stacks.

This is a direct structural analog of the PoolTogether bug: there, the code computed "shares to redeem" from one quantity (`previewWithdraw`) but transferred assets based on a different, unchecked outcome (actual shares redeemed), letting the two diverge. Here, the code authenticates based on one payload field (`repository.owner.login`) but performs the actual write based on a different, independently-controlled payload field (`repository.full_name`), letting the two diverge.

### Impact Explanation
Any organization configured in Shipit without a `webhook_secret` (a supported, documented configuration — `webhook_secret` is optional per the `GitHubApp` constructor) becomes an authentication bypass vector for **every other organization's repositories**. An attacker who can reach the public `/webhooks` endpoint (no auth required by design — it's meant for GitHub) can:
- Forge a `push` event naming `repository.owner.login` = the secret-less org, but `repository.full_name` = a victim stack's real repo, causing `Stack#sync_github` to run with an attacker-chosen `expected_head_sha`, corrupting the tracked commit history/deploy state for a repository the attacker does not control.
- Forge a `membership` event to create/manipulate `Team` records and add/remove members from teams via `MembershipHandler`, which feeds directly into `Shipit.github_teams` authorization (`User#authorized?`), a documented High-impact target ("escalation into `Shipit.github_teams` authorization").
- Forge `status` events to inject/alter commit statuses (`StatusHandler`) that gate merge/deploy eligibility for stacks belonging to organizations other than the one whose (absent or known) secret was used to pass verification.

This crosses the "organization authenticated versus the repository that is written" trust boundary explicitly called out as in-scope, and lands on the "escalation into `Shipit.github_teams` authorization" / cross-repository-writes impact tier.

### Likelihood Explanation
Exploitability is fully unprivileged from the perspective of Shipit's application logic (the webhook endpoint has no session/API-token requirement — that's its entire purpose), but is conditioned on deployment configuration: it requires at least one configured GitHub organization in `secrets.github` lacking a `webhook_secret` (or an org whose secret is otherwise known/leaked), while other organizations' real stacks exist in the same Shipit instance. This is a realistic multi-tenant Shipit deployment pattern (the code explicitly supports per-organization configs via `github_app_config`/`TOP_LEVEL_GH_KEYS`), and nothing in the engine prevents or warns against an org omitting `webhook_secret`. Given that, the forgery itself requires no credentials at all — only knowledge of a target repository's `full_name`, which is public.

### Recommendation
Bind authentication to the resource being written:
1. In `WebhooksController#verify_signature`, do not resolve the GitHub App/secret solely from `repository.owner.login`/`organization.login`. Instead, resolve (or additionally validate) using the `Repository`/`Stack` actually referenced by `repository.full_name`, and confirm that repository's registered owner/organization matches `repository_owner` before dispatching.
2. Do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank for organizations that also host stacks reachable by other, secret-protected organizations' identifiers — either require `webhook_secret` for all configured organizations or fail closed (`head 422`) when it is absent rather than treating it as "verification passed."
3. Add an explicit check in `Shipit::Webhooks::Handlers::Handler` (or in the controller before dispatch) asserting that the repository resolved for signature verification and the repository resolved for processing are the same repository.

### Proof of Concept
Given a Shipit deployment with `secrets.github` containing:
```yaml
github:
  attacker_org:            # no webhook_secret configured
    app_id: ...
    installation_id: ...
  victim_org:
    app_id: ...
    installation_id: ...
    webhook_secret: "s3cr3t"
```
and a real stack tracked for `victim_org/victim-repo`:

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything   # ignored, since attacker_org has no webhook_secret

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker_org" },   // used only for verify_signature
    "full_name": "victim_org/victim-repo"   // used by PushHandler to pick the real stack
  }
}
```

`verify_signature` calls `Shipit.github(organization: "attacker_org")`, which has no `webhook_secret`, so `verify_webhook_signature` returns `true` unconditionally — the request is accepted. `Shipit::Webhooks.for_event('push')` then runs `PushHandler`, which resolves `Repository.from_github_repo_name("victim_org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the real victim stack, despite the request never having been authenticated for `victim_org` at all.

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
