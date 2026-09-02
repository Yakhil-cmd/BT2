### Title
Unauthenticated webhook forgery via unconditional signature bypass when `webhook_secret` is unset - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` whenever no `webhook_secret` is configured for the organization resolved from the *unverified* JSON body, allowing an unauthenticated attacker to submit arbitrary, unsigned webhook payloads that `Shipit::WebhooksController#create` will dispatch to handlers that write repository/stack state (push syncs, status updates, pull-request/review-stack provisioning, membership/team creation) based purely on attacker-controlled `repository.full_name`.

### Finding Description
`WebhooksController#verify_signature` (a `before_action`) determines which `GitHubApp` config to use for signature validation by reading `repository_owner`, itself parsed straight out of the unauthenticated request body: [1](#0-0) [2](#0-1) 

It then calls `GitHubApp#verify_webhook_signature`: [3](#0-2) 

The first line, `return true unless webhook_secret`, is the exact analog of the `ecrecover` bug in the report: a "no-signature" / "signer is nil" condition is treated as a valid signature instead of as "signature could not be verified, reject". This is functionally identical to the GolomTrader flaw where `ecrecover` returning `0` (i.e., "no valid signer") is not distinguished from an intentionally-verified `0`-signer, causing the check to be bypassed.

Once the signature check is bypassed, `create` parses the *same* untrusted body and dispatches it to registered handlers: [4](#0-3) 

Those handlers resolve which `Stack`/`Repository` to mutate using `payload.dig('repository', 'full_name')` — a field that is never itself checked against the organization used for the (bypassed) signature verification: [5](#0-4) 

This produces the broken binding: **`repository.owner.login` used to select the signing secret (and possibly belonging to an org with no `webhook_secret` configured) ≠ `repository.full_name` used to select which tracked repository/stack is actually written to.** An attacker can pick any `owner.login` that resolves to a configured GitHub organization lacking a `webhook_secret`, while setting `repository.full_name` to point at an entirely different, victim repository/stack tracked by the same Shipit instance. Because `verify_webhook_signature` unconditionally returns `true` for the org with no secret, the forged payload sails through, and the handler (e.g. `PushHandler`, `StatusHandler`, pull-request handlers) acts on the victim repository using fields taken from the unsigned body (commit SHAs, CI status, PR labels/state, etc.).

### Impact Explanation
This allows an unauthenticated network attacker to inject arbitrary GitHub events (fake `push`, `status`, `pull_request`, `membership`) for any repository/stack tracked by the Shipit instance, as long as one configured GitHub organization has no `webhook_secret` set (which the setup docs explicitly present as an optional/valid configuration, not a misconfiguration against documented behavior). Consequences include: forged commit-status updates that unblock/allow deploys (`Handlers::StatusHandler` writing `CommitStatus`), forged `push` events queuing `GithubSyncJob` against a stack's expected head SHA, and forged `membership`/`pull_request` events creating teams/users or manipulating review-stack provisioning — i.e., an avenue toward an unauthorized deploy/rollback via injected commit statuses, satisfying the "unauthorized deploy" impact bar.

### Likelihood Explanation
Reachable by any unauthenticated actor who can reach `/github/webhooks` (or configured route) — no session, API token, or GitHub credentials required. Requires only that at least one configured GitHub App organization in `secrets.yml` has `webhook_secret` blank, which is an explicitly supported configuration state in `docs/setup.md` and `config/secrets.development.example.yml` (webhook_secret shown as optional/`# nil`), not a deviation from documented deployment.

### Recommendation
Do not treat "no configured secret" as "signature valid." `verify_webhook_signature` should fail closed (return `false`/reject) when `webhook_secret` is blank rather than short-circuiting to `true`, or the engine should require `webhook_secret` to be present for every configured organization at boot. Additionally, bind the repository/organization used to select the verification secret to the repository actually mutated by handlers (e.g., re-validate that `repository.full_name`'s owner matches the `repository_owner` used for signature verification) so a payload can't claim one org for signing purposes while writing to a different tracked repository.

### Proof of Concept
1. Configure Shipit with multiple GitHub orgs (`Shipit.github(organization: ...)`), where `OrgA` has a `webhook_secret` set and `OrgB` does not (a supported configuration per `docs/setup.md`'s "Using Multiple Github Applications" section).
2. Attacker sends `POST /github/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature`, and JSON body:
```json
{
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/victim-repo" },
  "after": "<attacker-chosen-sha>",
  "ref": "refs/heads/main"
}
```
3. `verify_signature` resolves `Shipit.github(organization: "OrgB")`, whose `verify_webhook_signature` returns `true` unconditionally because `OrgB`'s `webhook_secret` is blank [6](#0-5) .
4. `create` dispatches the parsed body to `Handlers::PushHandler`, which resolves the target stack via `repository.full_name` = `"OrgA/victim-repo"` [7](#0-6) , causing Shipit to enqueue a sync/queue job against `OrgA`'s tracked repository using attacker-supplied SHA — despite no valid signature ever having been produced for `OrgA`.

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
