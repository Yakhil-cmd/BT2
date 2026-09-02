### Title
Webhook signature verification key is selected from an unverified payload field that differs from the field used to pick the target repository/stack — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController` picks which GitHub App/`webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON body, but every webhook `Handler` resolves the actual target repository/stack from a different field in the same unverified body — `repository.full_name`. Nothing cross-checks that these two attacker-controlled fields refer to the same repository, so a valid signature computed with *any* configured organization's `webhook_secret` can be replayed against a payload whose `repository.full_name` points at a completely different, victim stack.

### Finding Description
`WebhooksController#verify_signature` derives the verification key from the raw payload before any authenticity check: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the JSON body (`params.dig('repository', 'owner', 'login')`) and used only to look up which `GithubApp`/`webhook_secret` to verify against via `Shipit.github(organization: repository_owner)` and `GithubApp#verify_webhook_signature`: [3](#0-2) 

Once the HMAC check passes, the event is dispatched to a `Handler`, but the handler resolves the *actual* repository/stack to act on from a **different** field of the same body, `repository.full_name`, with no re-validation that it belongs to the organization whose secret verified the signature: [4](#0-3) [5](#0-4) 

`Repository.from_github_repo_name` splits `full_name` on `/` and looks up any repository/stack registered in Shipit by owner+name, independent of which org's key verified the request: [6](#0-5) 

This breaks the binding "organization authenticated == repository written." Since `Shipit.github(organization: ...)` supports multiple independently configured GitHub Apps/orgs (see the multi-org fixture with distinct `webhook_secret`s per org), an attacker who legitimately controls one configured organization (e.g. because they administer a GitHub App/org that is itself onboarded onto this Shipit instance, and thus knows that org's `webhook_secret`) can: [7](#0-6) 

1. Build a raw JSON body with `repository.owner.login` (or `organization.login`) = their own org "OrgA", but `repository.full_name` = `"OrgB/victim-repo"` (a stack unrelated to OrgA).
2. Sign the raw body with OrgA's known `webhook_secret` and send it directly to `/webhooks` with `X-Hub-Signature` and `X-Github-Event: push` (or `status`/`check_suite`).
3. `verify_signature` resolves `repository_owner` = "OrgA", fetches OrgA's `GithubApp`, and the signature verifies successfully (it was legitimately computed with OrgA's secret over this exact body).
4. `PushHandler#process` (or `StatusHandler`/`CheckSuiteHandler`) then acts on `Repository.from_github_repo_name("OrgB/victim-repo")`, i.e. an entirely different stack that has nothing to do with OrgA's credentials.

### Impact Explanation
This lets an attacker who is a legitimate, unprivileged owner of one configured GitHub organization forge accepted, "signed" webhook events for stacks belonging to any *other* organization/repository configured in the same Shipit instance. At minimum this triggers `GithubSyncJob`/`RefreshCheckRunsJob` against arbitrary victim stacks with attacker-chosen SHAs; if the target stack uses status/check-suite webhooks to gate `continuous_deployment` (deploy-on-green-CI), the attacker can forge a fabricated "success" CI status for an arbitrary commit on a victim stack they do not control, causing Shipit to trigger an **unauthorized deploy** — matching the Critical impact category ("an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires no Shipit session, `ApiClient` token, or GitHub write access to the victim repo — only knowledge of the `webhook_secret` for *any one* configured GitHub App/org on the instance (which the attacker legitimately possesses as the owner of that org's app), plus the ability to POST directly to the shared `/webhooks` endpoint (unauthenticated, public route). Multi-tenant/multi-org Shipit deployments (explicitly supported and tested, per `secrets_double_github_app.yml`) are directly exposed.

### Recommendation
Bind the verification key to the same repository identity that handlers act on: after HMAC verification, re-derive `repository_owner` from `repository.full_name`'s owner segment (or vice versa) and reject the request if they don't match. Alternatively, verify the signature using a secret scoped per-repository/stack rather than per-organization-claimed-in-payload, and have `Handler#repository_name`/`repository_owner` come from one single, mutually-consistent source of truth checked before dispatch.

### Proof of Concept
```
POST /webhooks HTTP/1.1
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
`verify_signature` uses `OrgA`'s `webhook_secret` (attacker-known) to validate — success. `PushHandler` then calls `sync_github` on the `OrgB/victim-repo` stack, using `Repository.from_github_repo_name("OrgB/victim-repo")`, entirely bypassing OrgB's real GitHub App/secret. [8](#0-7)

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
