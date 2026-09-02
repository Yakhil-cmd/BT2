### Title
Webhook signature is verified against an organization derived from `repository.owner.login`, while the repository actually acted upon is taken from the unauthenticated `repository.full_name` field, allowing cross-organization webhook forgery when any configured organization has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the request against using `repository_owner`, computed from the payload field `repository.owner.login` (falling back to `organization.login`). Every downstream `Webhooks::Handlers::Handler` (e.g. `PushHandler`, and the `pull_request` handlers) instead resolves the repository to act on from a *different* payload field, `repository.full_name`, via `Handler#repository_name`. Since these two fields are never checked for consistency, and the raw body is otherwise attacker-controlled JSON (not a real GitHub request), an attacker can pick an organization with no `webhook_secret` configured to trivially satisfy signature verification, while pointing `repository.full_name` at any other repository/stack tracked by the instance - including ones belonging to a different, properly-secured organization.

### Finding Description
`verify_signature` derives the org used for signature verification purely from payload content: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever no `webhook_secret` is configured for that organization: [3](#0-2) 

Shipit's multi-organization config schema explicitly allows a per-organization `webhook_secret` that can be left blank/`nil`, as shown in every example/dummy config (`webhook_secret: # nil`): [4](#0-3) 

Once signature verification passes (trivially, because the chosen org has no secret), the raw JSON body is handed unchanged to the event handlers: [5](#0-4) 

But the handlers determine *which repository/stack* to operate on from a completely different, independently-attacker-controlled field of the same payload: [6](#0-5) 

For example `PushHandler` uses `stacks` (built from `repository_name` = `repository.full_name`) plus attacker-supplied `ref`/`after` to trigger `stack.sync_github`: [7](#0-6) 

The binding broken is: **organization that authenticated (`repository.owner.login`, checked against that org's `webhook_secret`) ≠ repository that is written/acted upon (`repository.full_name`, used to select the `Stack`/`Repository` for handler processing)**. Because nothing forces `repository.full_name` to belong to the org named in `repository.owner.login`/`organization.login`, an attacker only needs to know (or guess) that at least one configured GitHub organization on the Shipit instance has no webhook secret set (a common/default state per the shipped example configs) to bypass HMAC verification entirely for webhooks targeting *any other* tracked repository.

### Impact Explanation
This allows an unprivileged, unauthenticated network attacker (no GitHub App credentials, no webhook secret, no Shipit session) to forge webhook events for repositories/stacks belonging to organizations whose webhook secret **is** properly configured, as long as any other configured organization on the same instance lacks a secret. Reachable handler side effects include forcing `Stack#sync_github` (push events), team/user creation (`membership`), and pull-request/review-stack state changes for arbitrary tracked stacks. This is a cross-organization/cross-repository state manipulation, matching the "cross-repository writes" impact bucket, since the trust boundary (per-org webhook secret) can be routed around by referencing repositories outside the compromised org.

### Likelihood Explanation
Likelihood is elevated by the fact that Shipit's own shipped example configurations (`config/secrets.development.example.yml`, `test/dummy/config/secrets_double_github_app.yml`) show `webhook_secret` commented out/nil by default for each organization block, and multi-org support is a first-class documented feature (`Shipit.github_organizations`, `TOP_LEVEL_GH_KEYS`). Any real-world deployment that onboards a new/test organization without immediately setting a `webhook_secret` — while other organizations do have one set — becomes exploitable for cross-org payload injection with no attacker credentials required, only knowledge of the unsecured org's login/domain (which is often public, e.g. visible in repository URLs or org names).

### Recommendation
- Do not select the verification organization purely from unauthenticated payload content. Verify the signature against every organization's configured secret (or require an explicit, fixed mapping such as by URL path/subdomain) rather than trusting `repository.owner.login`/`organization.login` from the body.
- After signature verification succeeds for organization `X`, enforce that `repository.full_name`'s owner segment matches organization `X` before dispatching to any handler; reject the request otherwise.
- Treat a missing `webhook_secret` as a hard misconfiguration in multi-org mode (raise/log a critical warning, or refuse to process webhooks for that org) rather than silently returning `true` from `verify_webhook_signature`.

### Proof of Concept
Assume Shipit is configured with two organizations: `SecureOrg` (has `webhook_secret` set) and `OpenOrg` (no `webhook_secret`, e.g. left as the default `# nil` from the example config), and Shipit tracks a stack for `SecureOrg/prod-repo`.

1. Attacker sends, without any valid HMAC signature:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything

{
  "repository": {
    "owner": { "login": "OpenOrg" },
    "full_name": "SecureOrg/prod-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
2. `WebhooksController#verify_signature` computes `repository_owner` = `"OpenOrg"` (`app/controllers/shipit/webhooks_controller.rb:59-62`), fetches `Shipit.github(organization: "OpenOrg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`) — no valid signature required at all.
3. Request proceeds to `Webhooks.for_event('push')` → `PushHandler.call(params)`, which resolves `repository_name` from `payload.dig('repository','full_name')` = `"SecureOrg/prod-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`), and triggers `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on `SecureOrg`'s tracked stack — despite `SecureOrg`'s own webhook secret never being checked.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
