### Title
Webhook signature bypass via secret-less GitHub App config lets an attacker forge events against an unrelated victim repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to verify a webhook against using `repository_owner`, a field taken straight from the unauthenticated JSON body. All downstream event handlers, however, dispatch and mutate state based on a completely different, equally unauthenticated field: `repository.full_name`. Because `GitHubApp#verify_webhook_signature` silently skips verification entirely when the selected app config has no `webhook_secret` configured, an attacker can name an organization with a blank secret in the "owner" field (to disable verification) while pointing `repository.full_name` at a totally unrelated victim stack, causing the engine to process a forged, unauthenticated event against that victim repository.

### Finding Description
The controller picks the verifying app config from an attacker-controlled field: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the unsigned-at-request-time JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`) before any signature has been validated, and is used to fetch `Shipit.github(organization: repository_owner)`.

The verification itself is a no-op whenever the selected app has no configured secret: [3](#0-2) 

`@webhook_secret = @config[:webhook_secret].presence` means any organization entry in the multi-org `github:` config block left without a `webhook_secret` (a state explicitly shown as valid/expected in the documented config examples) causes `verify_webhook_signature` to `return true unless webhook_secret` — i.e., **any** payload is accepted for that organization, signed or not.

Crucially, none of the actual event handlers use `repository_owner` to decide what to act on. They all resolve the target stack from a separate field: [4](#0-3) 

`repository_name` is `payload.dig('repository', 'full_name')`, independent of `repository_owner`. `PushHandler`, for example, uses this to look up and act on stacks: [5](#0-4) 

This is exactly the class of bug described in the report: the code checks/authenticates one field (`repository.owner.login` / `organization.login`, used to pick the verifying secret) but acts on a different field (`repository.full_name`) that is never bound to that verification. The equality that should hold — "the organization whose signature was verified == the organization owning the repository being written to" — is broken because the two fields are read independently from the same unauthenticated body and only one of them gates verification.

### Impact Explanation
An unprivileged external attacker with no Shipit session, no `ApiClient` token, and no knowledge of any `webhook_secret` can trigger arbitrary registered webhook handlers (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc., per `Shipit::Webhooks.for_event`/`Hook::EVENTS`) against any stack/repository tracked by this Shipit instance, as long as at least one organization configured in the multi-org `github:` block has no `webhook_secret` set. This can:
- Force resynchronization of an arbitrary tracked repository/stack (`PushHandler` → `stack.sync_github`).
- Inject forged commit statuses/check-suite results for commits on a victim repository, which can flip `deployable?` state and, combined with `continuous_deployment`, cause the engine to autonomously trigger an unauthorized deploy of attacker-chosen state.
- Manipulate team/membership records tied to authorization (`membership` event), potentially affecting `Shipit.github_teams`-based authorization decisions.

This satisfies the High/Critical bar of "unauthorized deploy" and "escalation into `Shipit.github_teams` authorization" without any credential, session, or repository access.

### Likelihood Explanation
Reachability requires only that one org entry among possibly many configured GitHub Apps lacks a `webhook_secret` — a state the project's own setup docs and example config show as an accepted/valid configuration (`webhook_secret: # nil`). Any installation that onboards a low-trust or read-only organization without bothering to set a webhook secret (since events from it may seem harmless) inadvertently opens this path for spoofing events against every other repository tracked by the same Shipit instance, because the org used for verification selection is decoupled from the repository actually acted upon.

### Recommendation
Bind the two fields together before dispatch: require that the app config resolved for signature verification match the owner of `repository.full_name` (or, simpler, resolve `Shipit.github(organization:)` from the same field that handlers use for repository resolution), and refuse to fall back to "verification passed" when `webhook_secret` is blank for an org that is going to be used to authorize writes to a different repository/org. At minimum, require `webhook_secret` to be present for every configured GitHub App, or scope handler dispatch strictly to repositories owned by the verified `repository_owner`.

### Proof of Concept
1. Shipit is configured with two GitHub App entries in `github:` — org `victim-org` (has `webhook_secret` set, and owns the tracked stack `victim-org/prod-app`) and org `low-trust-org` (added without a `webhook_secret`, per documented optional config).
2. Attacker POSTs to the webhooks endpoint with header `X-Github-Event: push` and no valid `X-Hub-Signature`, with body:
```json
{
  "organization": { "login": "low-trust-org" },
  "repository": { "owner": { "login": "low-trust-org" }, "full_name": "victim-org/prod-app" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
3. `repository_owner` resolves to `low-trust-org` → `Shipit.github(organization: 'low-trust-org')` has `webhook_secret` blank → `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`) regardless of the missing/invalid signature header.
4. `PushHandler#stacks` resolves `Repository.from_github_repo_name('victim-org/prod-app')` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and calls `stack.sync_github(expected_head_sha: ...)` on the victim's tracked stack — an action fully unauthenticated with respect to `victim-org`.

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
