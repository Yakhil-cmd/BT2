This is important: the `StatusHandler#process` matches purely on `Commit.where(sha: params.sha)` — **without any repository/organization scoping at all**. This is even more direct than the push-handler case I was tracing.

### Title
Webhook signature is verified against `repository.owner.login`, but event processing acts on unrelated fields (`repository.full_name`, or no repository scope at all) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook using the GitHub App/secret associated with the organization named in `repository.owner.login` (or `organization.login`), but the handlers that subsequently act on the same JSON body derive their target from a **different, unverified field** — `repository.full_name` for repository-scoped handlers, and *no repository field at all* for `StatusHandler`. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
`verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` and fetches the GitHub App configuration for *that* value to check the HMAC signature: [4](#0-3) . This binds "the org whose secret validated the request" to a field the attacker fully controls in the JSON body, while the **actual mutation target** is resolved independently:

- `Handler#stacks` looks up `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, an entirely separate JSON field from `repository.owner.login` used for auth. [2](#0-1) 
- `StatusHandler#process` doesn't even consult the repository at all — it matches records purely by `sha`, globally across every stack/repository configured in the instance: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [3](#0-2) 

The intended equality is:
```
organization_that_signed_the_payload  ==  repository/commit_that_is_mutated
```
but nothing in the code enforces `repository.full_name.split('/').first == repository.owner.login`, and `StatusHandler` enforces no relationship whatsoever between the authenticating org and the commit whose CI status gets written.

`verify_webhook_signature` also short-circuits entirely when no secret is configured for that org: `return true unless webhook_secret`, and the setup docs explicitly describe the webhook secret as **optional**. [5](#0-4) [6](#0-5) 

In a multi-organization Shipit install (explicitly supported, `config/secrets.development.example.yml:18-38`), if any one configured organization has no webhook secret set, an unauthenticated internet requester can hit `/webhooks` with `X-Github-Event: status`, set `repository.owner.login` to that unsecured org (so `verify_signature` trivially passes with no signature needed), and set `sha`/`state`/`context` to target any commit `sha` that exists in any *other* stack in the same instance — regardless of which org or repository the payload nominally claims to belong to. `Commit#create_status_from_github!` will write that fabricated CI status onto the real commit, with no cross-check against which repository actually owns that commit's stack. [7](#0-6) 

### Impact Explanation
If a stack has `continuous_deployment: true` and relies on GitHub commit statuses/CI gating (`ci.require`, `deployment_checks_passed?`), forging a "success" status for an arbitrary commit sha via this unauthenticated/mis-scoped path can make `Stack#deployable?` return true for a commit that never actually passed CI, letting `trigger_continuous_delivery` (or a subsequent legitimate manual deploy) ship that commit — an unauthorized deploy driven entirely by a spoofed webhook. Because `StatusHandler` performs zero repository binding check, this is reachable even without needing to guess `repository.full_name` values correctly for a target stack — only a `sha` that exists somewhere in the instance's commit table is required, which can be observed from any public GitHub repository already tracked by Shipit.

### Likelihood Explanation
Requires: (1) a multi-tenant/multi-org Shipit deployment (explicitly documented/supported configuration shape), and (2) at least one configured organization without a webhook secret, which the setup documentation explicitly calls optional. Given the secret is described as optional and this is a supported deployment topology, the precondition is plausible in real installs, and no attacker credential (session, ApiClient token, GitHub token, private key) is required — only knowledge of a target commit `sha` already visible on GitHub.

### Recommendation
Bind webhook signature verification and event dispatch to the same, single, verified identifier: derive the target repository/commit scope strictly from the org/repo whose secret validated the signature, and reject (or explicitly cross-check) any handler logic that resolves a repository or commit independently of that verified value. Specifically, `StatusHandler` (and any other handler using `Commit.where(sha:)` without repository scoping) should scope lookups through the repository verified during signature validation rather than a global `sha` match, and `Handler#repository_name` should be reconciled against `repository_owner` used in `verify_signature` rather than trusted independently.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.yml`: `OrgA` (no `webhook_secret` set) and `OrgB` (has a real stack with `continuous_deployment: true` and CI-gated deploys).
2. As an unauthenticated attacker, `POST /webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "OrgA" } },
  "sha": "<sha of a real undeployed commit belonging to an OrgB stack>",
  "state": "success",
  "context": "ci/required-check"
}
```
No `X-Hub-Signature` needed since `OrgA` has no secret configured, so `verify_webhook_signature` returns `true` unconditionally.
3. `StatusHandler#process` matches `Commit.where(sha: params.sha)` against the real commit belonging to `OrgB`'s stack (no ownership check performed) and calls `create_status_from_github!`, marking the required CI check green.
4. If `OrgB`'s stack has continuous deployment enabled, Shipit's own scheduler deploys that now-"green" commit using Shipit's legitimate GitHub credentials — an unauthorized deploy triggered without any credential belonging to `OrgB`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```
