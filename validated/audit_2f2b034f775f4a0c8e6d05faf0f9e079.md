### Title
Webhook signature verification is keyed off a query-string-controllable organization while the actually-processed payload is read from the raw request body - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp` (and thus which `webhook_secret`) to verify the request against using `repository_owner`, which is derived from Rails' merged `params` hash [1](#0-0) . That same `params` accessor also incorporates the request's query string. `#create`, however, dispatches the actual event handlers using `JSON.parse(request.raw_post)` - the untouched body [2](#0-1) . Because Rails builds `params` as `request_parameters.merge(query_parameters)` (query string wins for colliding top-level keys), an attacker can supply a `?repository[owner][login]=OrgTheyControl` query string that overrides the `repository` key used only for org selection, while leaving the JSON body (which determines the real target repo/stack and is what handlers act on) pointing at a victim org/repo.

### Finding Description
The engine supports multiple configured GitHub orgs/apps, each with its own `webhook_secret` [3](#0-2) . Verification is org-scoped: `Shipit.github(organization: repository_owner)` looks up that org's `GitHubApp` and calls `verify_webhook_signature` [4](#0-3) . Critically, `verify_webhook_signature` trivially returns `true` when the selected org has no `webhook_secret` configured: `return true unless webhook_secret` [5](#0-4) .

`repository_owner` is computed from `params`, not from `request.raw_post`:
```
params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
``` [1](#0-0) 

Rails populates the request's `params` by merging body-parsed parameters with query-string parameters (`request_parameters.merge(query_parameters)`), so for a top-level key present in both (e.g. `repository`), the query-string value replaces the body-derived value entirely (shallow merge - it does not deep-merge nested hashes). This means an attacker who controls only the URL query string of the webhook POST (no secret required) can force `repository_owner` to resolve to an organization of their choosing - e.g., one with no `webhook_secret` set, or one for which they know the secret - causing `verify_signature` to pass, or to pass because the check short-circuits to `true`.

Once verification passes, `#create` re-parses the body from scratch: `params = JSON.parse(request.raw_post)`, which is untouched by the query string. This body is dispatched to handlers, e.g. `PushHandler#process` enqueues `stack.sync_github` for stacks matching the body's `ref`/repo [6](#0-5) , and `StatusHandler#process` writes a commit `Status` from body-supplied `state`/`context`/`sha` for commits identified purely by `sha` regardless of repository [7](#0-6) .

This is the same bug class as the referenced report: a value used to satisfy an authorization/verification check (the org that gates the signature check) is not what is actually bound and acted upon (the body that determines which repository/stack is mutated). The "sum" used to validate (`repository_owner` for signature selection) diverges from the "shares" that are actually applied (the raw-body-derived repository/commit targeted by the handler).

### Impact Explanation
If the deployment configures more than one GitHub org (as documented and tested via `test/dummy/config/secrets_double_github_app.yml`) and at least one configured org has no `webhook_secret` set (or its secret is known/guessable to the attacker, e.g., a low-security staging org), an unauthenticated attacker can forge webhook events for a *different, properly-secured* organization's repositories. Depending on which handler is triggered this can:
- Fabricate commit `Status` entries (`StatusHandler`) that satisfy CI requirements gating deploys/merges (`ci.require`, merge-queue), pushing a stack toward an unauthorized deploy.
- Trigger `GithubSyncJob`/`sync_github` calls (`PushHandler`) against arbitrary stacks.
- Manipulate team membership (`membership` handler creates/removes `Membership` records), potentially affecting `Shipit.github_teams` authorization for real users.

This crosses the "unauthorized deploy" and "escalation into `Shipit.github_teams` authorization" impact categories called out in scope.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment (a documented, supported configuration), and (2) at least one configured org without a webhook secret, or one whose secret is discoverable/weak. Given `webhook_secret` is explicitly optional per the setup docs and example config (`webhook_secret: # nil`), this is a realistic operational configuration, not a purely theoretical one. No credentials, session, or repository access are required by the attacker - only the ability to send an HTTP POST with a crafted query string and body to the public webhook endpoint.

### Recommendation
- Derive `repository_owner` (and any value used to select the verification key) from the same parsed `request.raw_post` JSON used by `#create`, not from Rails' `params`, to eliminate the query-string/body divergence.
- Reject webhook requests that include a non-empty query string, or explicitly strip/ignore query parameters when computing values used for verification.
- Consider treating an org with an unset `webhook_secret` as "verification required but impossible" (fail closed) rather than "verification not required" (`return true unless webhook_secret`), at least when multiple orgs are configured.

### Proof of Concept
1. Configure Shipit with two orgs: `SecureOrg` (has `webhook_secret` set, hosts the victim repository/stack) and `OpenOrg` (no `webhook_secret` configured), per the multi-org schema in `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker crafts a POST to `/github/webhooks` (mounted webhook endpoint) with:
   - Query string: `?repository[owner][login]=OpenOrg`
   - Header: `X-Github-Event: status`
   - Body (raw JSON, untouched by query string): `{"repository":{"owner":{"login":"SecureOrg"},"full_name":"SecureOrg/victim-repo"},"sha":"<victim commit sha>","state":"success","context":"ci/required-check"}`
3. `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')`, which resolves to `"OpenOrg"` due to query-string override, selects `Shipit.github(organization: "OpenOrg")`, and `verify_webhook_signature` returns `true` unconditionally since `OpenOrg` has no `webhook_secret`.
4. `#create` re-parses `request.raw_post`, obtaining the body targeting `SecureOrg`/`victim-repo`, and dispatches it to `StatusHandler`, which creates a forged passing `Status` on the victim commit - without ever validating a signature against `SecureOrg`'s actual `webhook_secret`.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-20)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
