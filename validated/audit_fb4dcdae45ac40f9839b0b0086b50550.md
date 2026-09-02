### Title
Webhook signature verification is bypassed for GitHub organizations without a `webhook_secret`, letting an attacker forge push/status events for a different, secret-protected repository - ([File: lib/shipit/github_app.rb](lib/shipit/github_app.rb))

### Finding Description
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to validate the incoming payload against using the **organization taken directly from the unauthenticated payload**: [1](#0-0) [2](#0-1) 

That verification then delegates to `GitHubApp#verify_webhook_signature`, which unconditionally returns `true` — i.e., skips verification entirely — whenever the resolved app's `webhook_secret` is blank/unset: [3](#0-2) 

`webhook_secret` is documented as **optional** per organization (multi-org configuration explicitly ships with `webhook_secret: # nil`): [4](#0-3) [5](#0-4) 

Meanwhile, the actual repository/stack that a handler acts upon is resolved from a **different field of the same attacker-controlled JSON body**: `payload.dig('repository', 'full_name')`, used by every handler via `Handler#repository_name`/`#stacks`: [6](#0-5) 

and consumed for example by the push handler to enqueue `sync_github`: [7](#0-6) 

This creates exactly the trust-binding break the report's bug class describes: the field used to authenticate the request (`repository.owner.login`, used to pick the org's secret) is not the same field used to determine what gets written/acted on (`repository.full_name`). An attacker can craft a payload where:
- `repository.owner.login` = an organization configured in `Shipit.github` **without** a `webhook_secret` (skips signature check entirely, per `verify_webhook_signature`'s early `return true unless webhook_secret`), while
- `repository.full_name` = the full name of a real, unrelated stack/repository hosted under a **different**, secret-protected organization.

Because signature verification never inspects `repository.full_name`, the forged payload is accepted and dispatched to `Shipit::Webhooks.for_event(event)` handlers, which act on the targeted repository using only `full_name`.

### Impact Explanation
This is an authentication-bypass on the webhook trust boundary that lets an unauthenticated attacker trigger the same code paths that legitimate GitHub webhooks trigger for a repository they don't control, e.g.:
- Forged `push` events that enqueue `GithubSyncJob` / `stack.sync_github` for a targeted stack, influencing which commits Shipit treats as the deployable head.
- Forged `status`/`check_suite` events, which affect commit statuses/merge-queue eligibility used to gate deploys and the merge queue.

Given this can affect which ref is treated as validated/deployable for a real production stack, it maps to the "unauthorized deploy/rollback/merge" or "unauthenticated read/execution influence over stack state" impact tier.

### Likelihood Explanation
Exploitability strictly depends on the deployment having at least one configured GitHub organization/app in `Shipit.github` with no `webhook_secret` set — which is explicitly supported and shown as the default/example configuration (including the multi-org example and dummy test config), and is not flagged anywhere as insecure. Any installation using the documented "optional" webhook secret for any one org exposes every other org/repository configured on the same Shipit instance to this cross-organization forgery, since the webhook endpoint is shared and dispatch is payload-driven.

### Recommendation
- Do not select the verification secret from `repository.owner.login`/`organization.login` in the incoming payload when any configured org lacks a secret; instead, verify the signature against **the config matching the same field that handlers use to resolve the target repository** (`repository.full_name`), or reject payloads whose owner/full_name mismatch.
- Make `webhook_secret` mandatory (or at minimum, when unset, reject/quarantine the request rather than treating it as verified) so `verify_webhook_signature` cannot silently return `true`.
- Add a check that the resolved `GitHubApp` organization matches the owner segment of `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two GitHub orgs: `OrgA` (no `webhook_secret` set) and `OrgB` (secret set), each with at least one repository/stack tracked by Shipit, per the multi-org config format in `docs/setup.md`.
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/production-repo"
  },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required.
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — the request passes verification.
4. `PushHandler#process` resolves the stack via `payload.dig('repository', 'full_name')` = `"OrgB/production-repo"` and enqueues `GithubSyncJob`/`sync_github` for that stack, even though the request was never validated against `OrgB`'s webhook secret.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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
