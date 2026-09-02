This confirms the analog: the webhook signature in `WebhooksController#verify_signature` is checked against the GitHub App configured for `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (or falls back to `params.dig('organization', 'login')`) [1](#0-0) . That value is used solely to select which per-organization `webhook_secret` verifies the HMAC signature [2](#0-1) . But every handler that acts on the payload (e.g. `PushHandler`) resolves the target `Repository`/`Stack` from a **different, unverified field**: `payload.dig('repository', 'full_name')` [3](#0-2) , which is parsed independently via `Repository.from_github_repo_name` by splitting on `/` [4](#0-3) . Since `repository.owner.login` and `repository.full_name` are two independent, attacker-controlled JSON fields in the same webhook payload, and the HMAC only covers the payload as a byte string (not a semantic binding between these two fields), this is close to the "organization that authenticated versus the repository that is written" analog called out in the rules.

However, I could not push this to a concrete cross-organization write: `verify_webhook_signature` HMACs the **entire raw payload body** [5](#0-4) , so an attacker cannot change `repository.full_name` after the fact without invalidating the signature — the signature does cryptographically cover the whole raw JSON, including `full_name`. The only way to exploit the mismatch would be to hold a **valid webhook secret for organization A** and then craft a payload where `repository.owner.login == A` (so the correct secret is selected and verifies) while `repository.full_name == "B/some-repo"` (so the handler acts on org B's stack). This requires GitHub itself to allow such a payload shape, which it does not — GitHub always sets `repository.owner.login` consistently with `repository.full_name` for real webhook deliveries. Exploiting this requires the attacker to already control the webhook secret used to sign an arbitrary payload of their choosing (i.e., they'd need to install their own GitHub App/webhook against org A, whose secret they know, and manually POST a forged payload with mismatched owner/full_name fields directly to Shipit's `/webhooks` endpoint, bypassing GitHub entirely). That is plausible since `WebhooksController` only validates the signature against raw bytes, not against GitHub's own delivery guarantees — so a possessor of *any* configured `webhook_secret` (which could be for an org they legitimately administer) could sign a completely fabricated payload naming a *different* repository owner in `full_name`, causing Shipit to trigger `GithubSyncJob`/`sync_github` for a stack belonging to another organization's repository, using only the credentials for their own org's webhook secret.

This satisfies "cross-repository writes" if it triggers `Stack#sync_github`, which pulls GitHub state and can write status/commits for a repository the attacker does not own and never authenticated against, using only their own org's webhook secret.

### Title
Webhook signature verified against `repository.owner.login`, but handlers act on the independently-controlled `repository.full_name` field, enabling cross-repository triggering with a foreign org's webhook secret - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the HMAC signature using `repository.owner.login` (falling back to `organization.login`) from the JSON payload [6](#0-5) . Once the signature check passes, `WebhooksController#create` dispatches the **entire raw payload** to registered handlers [7](#0-6) , and those handlers resolve the target repository/stack from a **separate** field, `repository.full_name` [3](#0-2) . Nothing in the engine asserts that `repository.owner.login` (the value that selected the signing secret) is a prefix of `repository.full_name` (the value that determines which repository is acted upon).

### Finding Description
The binding that should hold is: `organization authenticated by webhook_secret == organization of the repository being written to`. Concretely:
- Signature verification: `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, where `repository_owner` comes from `params.dig('repository', 'owner', 'login')` [6](#0-5) .
- Repository resolution for effects: `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, which independently splits `full_name` on `/` into `repo_owner`/`repo_name` [4](#0-3) , [3](#0-2) .

Because the `X-Hub-Signature` HMAC is computed over the raw request body using `OpenSSL::HMAC.hexdigest` [5](#0-4) , anyone who knows a valid `webhook_secret` for *any* organization configured in `Shipit.github` can sign an arbitrary JSON body of their own construction (not one relayed unmodified by GitHub) and set `repository.owner.login` to match that organization while setting `repository.full_name` to reference an entirely different organization/repository that is also onboarded to this Shipit instance. Shipit only checks that "some configured org's secret signed this exact byte string" — it never checks that the org whose secret validated is the same org named in `full_name`.

### Impact Explanation
If exploited, `PushHandler#process` invokes `stack.sync_github(expected_head_sha: params.after)` for stacks under `repository.full_name` [8](#0-7) , and other handlers (status, check_suite, pull_request, membership) similarly key off attacker-supplied payload fields for a repository the attacker's org has no relationship to. This can force sync/refresh operations, fabricate commit statuses, or otherwise write state for a stack/repository belonging to a different tenant on a shared multi-org Shipit deployment — a cross-repository write triggered by credentials scoped to a different, unrelated organization.

### Likelihood Explanation
Requires the attacker to control (or have legitimately been granted) a `webhook_secret` for at least one organization configured on the shared Shipit instance — a realistic scenario for any multi-tenant/multi-org Shipit deployment (see `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`, which show multiple orgs configured on one instance) [9](#0-8) . No other secret, session, or repository write access is needed; the attacker only needs network access to POST directly to `/webhooks`, bypassing GitHub's own webhook relay entirely.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), assert that `repository.owner.login` used to select the signing secret is identical to the owner segment parsed from `repository.full_name` before dispatching to handlers, rejecting payloads where they diverge.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` and `orgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an attacker who knows `orgA`'s `webhook_secret` (e.g., because they administer `orgA`'s GitHub App), craft a payload:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/private-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` selects `Shipit.github(organization: "orgA")`, and the HMAC validates successfully [2](#0-1) .
5. `PushHandler` resolves `Repository.from_github_repo_name("orgB/private-repo")` and calls `sync_github` on `orgB`'s stacks [8](#0-7) , despite the request never being authenticated by `orgB`'s webhook secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L33-38)
```ruby
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
