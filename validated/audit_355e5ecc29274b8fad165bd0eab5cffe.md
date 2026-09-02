## Title
Cross-organization webhook signature confusion allows CI status forgery / cross-tenant stack manipulation - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports multi-organization deployments where each GitHub organization has its own GitHub App and its own `webhook_secret` (`test/dummy/config/secrets_double_github_app.yml`) [1](#0-0) . The `WebhooksController#verify_signature` selects *which* org's secret to validate the HMAC signature against using `repository_owner`, read from `params.dig('repository', 'owner', 'login')` (or the fallback `organization.login`) [2](#0-1) . This is exactly the same class of bug as the referenced TwapOracle finding: one field of attacker-supplied input is used to select/verify a scaling value (here, the signing secret/org), while a *different* field of the same payload is what the downstream logic actually acts on — the two are never checked for consistency.

### Finding Description
The webhook endpoint is unauthenticated except for the per-organization HMAC signature. Because it is a plain HTTP endpoint, nothing stops an attacker who legitimately owns/administers one onboarded GitHub organization (and therefore knows *that* organization's `webhook_secret`, which they themselves configured when creating their GitHub App per `docs/setup.md`) from POSTing an arbitrary, hand-crafted JSON body directly to `/webhooks`, self-signing it with their own known secret [3](#0-2) .

`verify_signature` only checks that the signature matches the secret belonging to whatever `repository.owner.login` says [4](#0-3) . It never confirms that this same owner corresponds to the repository the handlers subsequently operate on. Handlers instead use `repository.full_name` (`Handler#repository_name`) or, in the worst case, no repository scoping at all [5](#0-4) .

The most severe instance is `StatusHandler`, which resolves target commits purely `Commit.where(sha: params.sha)` with **no repository/organization scoping whatsoever** [6](#0-5) . Since commit SHAs are not namespaced per tenant in this lookup, an attacker who controls Org B (and its own legitimate webhook secret) can:
1. Sign an arbitrary `status` event payload with Org B's secret, satisfying `verify_signature` (which only checks that `repository.owner.login == "OrgB"` maps to a valid secret).
2. Set `sha` to a commit SHA belonging to a stack/repository under a completely unrelated Org A.
3. Have `commit.create_status_from_github!(params)` inject a forged CI status (e.g. `state: success`) onto that Org A commit.

This forged status feeds directly into `Commit#deployable?`, which gates deploys on `success? && !blocked?` [7](#0-6) , and into `required_statuses`/`blocking_statuses` checks defined in Org A's own `shipit.yml` [8](#0-7) . A commit that was previously blocked by a missing/failing required CI check can be made to appear "green" by an attacker who has no access to Org A whatsoever — no Shipit session, no `ApiClient` token, no GitHub App private key, no repository write access on Org A — only knowledge of their own unrelated org's webhook secret.

The equality that is broken:
`repository.owner.login` (verified by the HMAC/secret lookup) `==` `repository.full_name`'s owner / the commit's actual owning stack (what is actually acted upon) — the code never enforces this equality.

### Impact Explanation
This is an authorization-boundary crossing that lets a party with only a foreign, legitimately-owned org's webhook secret write into another org's deploy-safety state (fabricate a "success" CI status), which can enable an unauthorized deploy of a commit that should have been blocked (missing/failing required or blocking status contexts). This matches the "unauthorized deploy" and "escalation into `Shipit.github_teams` authorization" impact classes: it is a genuine cross-tenant integrity violation reachable purely by controlling one tenant's own signing secret, no privileged Shipit credential required.

### Likelihood Explanation
Requires the deployment to be multi-tenant (multiple GitHub orgs configured, as explicitly supported and documented — `secrets_double_github_app.yml`), and requires the attacker to be an admin/owner of one of those orgs (who legitimately possesses that org's own webhook secret because they created the GitHub App). Given Shipit explicitly ships support and test fixtures for exactly this multi-org topology, this is a realistic configuration, not a contrived one. The attacker needs only to know or guess a target commit SHA in another org's stack, which is often public information (commit SHAs are visible on GitHub).

### Recommendation
Bind the verified signing organization to the entity actually acted upon at every step:
- In `Handler#repository_name`, cross-check that the repository resolved for processing belongs to the same organization that was used to select/verify the webhook secret (pass the verified organization down into each handler and assert equality).
- In `StatusHandler#process`, scope the `Commit` lookup by the repository/stack derived from the verified organization instead of a bare, unscoped `Commit.where(sha: params.sha)`.
- More generally, treat `repository_owner` used for signature verification as untrusted until corroborated by the payload's own `repository.full_name`/`organization.login`, and reject the payload if they disagree, rather than trusting whichever field a given handler happens to read.

### Proof of Concept
1. Deploy Shipit configured with two orgs, `OrgA` and `OrgB`, each with its own GitHub App and webhook secret (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As the administrator of `OrgB` (attacker), obtain `OrgB`'s webhook secret (they created it).
3. Identify a commit SHA belonging to a stack under `OrgA` whose deploy is blocked by a missing/failing required status (e.g. `ci/circleci`).
4. Craft a JSON body for a GitHub `status` event: `{"repository": {"owner": {"login": "OrgB"}, "full_name": "OrgB/whatever"}, "sha": "<OrgA commit sha>", "state": "success", "context": "ci/circleci"}`.
5. Compute `X-Hub-Signature` as `sha1=HMAC(OrgB_webhook_secret, raw_body)` and POST to `/webhooks` with header `X-Github-Event: status`.
6. `verify_signature` resolves the app via `repository_owner` = `"OrgB"`, verifies successfully against `OrgB`'s secret [9](#0-8) .
7. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — matches the `OrgA` commit regardless of `OrgB` in the payload — and calls `commit.create_status_from_github!(params)`, injecting a forged `success` status for `ci/circleci` on the `OrgA` commit [6](#0-5) .
8. The `OrgA` commit now satisfies `required_statuses`/`deployable?` and can be deployed by any authorized `OrgA` user, even though the check was never legitimately passed.

### Citations

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

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

**File:** docs/setup.md (L20-30)
```markdown
## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/deploy_spec.rb (L190-204)
```ruby
    def hidden_statuses
      Array.wrap(config('ci', 'hide')) + [release_status_context].compact
    end

    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```
