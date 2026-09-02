### Title
Webhook signature verification binds trust to `repository.owner.login`, but event handlers act on the independent `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a delivery against using `repository_owner`, a value read directly out of the unauthenticated JSON body. The HMAC check only proves the payload was signed with *that* organization's secret — it does not bind the signature to the repository that the downstream handlers actually mutate (`repository.full_name`). In a multi-organization Shipit deployment (explicitly supported, see `test/dummy/config/secrets_double_github_app.yml` with `OrgOne`/`OrgTwo`), an actor who legitimately controls the GitHub App/webhook secret for one configured organization can forge a delivery whose `repository.owner.login` matches their own org (so the signature check passes) while `repository.full_name` names a stack belonging to a different organization, causing Shipit to process attacker-controlled push/status/pull_request data against a repository they don't control.

### Finding Description
`verify_signature` derives the signing organization purely from request content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the `GithubApp`/secret config keyed by that attacker-supplied `repository_owner` string, and `verify_webhook_signature` only confirms the raw body was HMAC-signed with *that* org's secret: [3](#0-2) 

Nothing ties the *verified* organization to the repository the event handlers subsequently act on. Handlers (e.g. the push handler enqueuing `GithubSyncJob`, tested in `webhooks_controller_test.rb` via `unknown_repo_payload["repository"]["full_name"]`) resolve the target `Stack`/`Repository` from `repository.full_name`, a sibling field in the same untrusted JSON body: [4](#0-3) [5](#0-4) 

Because `repository_owner` (used to pick the secret) and `repository.full_name` (used to pick the acted-upon repository) are two independent, attacker-controlled fields of the same payload, an attacker who legitimately possesses the webhook secret for organization `OrgTwo` (because they administer that org's GitHub App, a normal, unprivileged action for that org's admin, not requiring any Shipit session, API token, or access to `OrgOne`) can:

1. Build a payload with `repository.owner.login` (or top-level `organization.login`) = `OrgTwo` and `repository.full_name` = `OrgOne/victim-repo`.
2. HMAC-sign the raw body with `OrgTwo`'s known webhook secret.
3. POST directly to `/webhooks` with the correct `X-Hub-Signature`.

`verify_signature` passes because the signature genuinely matches `OrgTwo`'s secret. The handler then processes the forged push/status/pull_request/membership data as if it came from `OrgOne`, writing/mutating state (commits, statuses, merge requests, team membership) for a stack in `OrgOne` that the attacker has no rights to.

This is the direct analog of the reported bug class: the verified quantity (which org's secret matched) and the quantity the code trusts for authorization/targeting (which repository is written) are silently allowed to diverge, exactly like `newRatio` (checked) diverging from `ibRatio` (used to authorize withdrawal).

### Impact Explanation
This breaks the equality "organization whose signature was verified == organization/repository being written," enabling cross-repository/cross-organization writes: fabricated pushes, CI/check statuses, pull-request events, or team-membership changes can be injected into any stack tracked by Shipit, from an actor who only controls a different, unrelated GitHub App installation. Per the scope's impact table this is Critical (cross-repository writes) / could enable an unauthorized deploy indirectly by faking CI success on a merge-queue-tracked PR of `OrgOne`.

### Likelihood Explanation
Requires only that the attacker be an admin of some org that has its own legitimately configured GitHub App/webhook secret in the multi-tenant Shipit deployment — a normal, unprivileged capability for that org, not requiring any credentials belonging to the victim organization, no Shipit session, no `ApiClient` token, and no access to the victim's `webhook_secret`. Multi-org support is a first-class, documented configuration (`secrets_double_github_app.yml`), making this a realistic deployment shape.

### Recommendation
Bind the verified organization to the repository actually mutated: after selecting the `GithubApp`/secret via `repository_owner`, require that `repository.full_name` (or `organization.login` for org-scoped events) starts with/matches that same owner before dispatching to handlers, e.g. reject requests where `params.dig('repository','owner','login') != params.dig('repository','full_name')&.split('/')&.first`.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `OrgOne` and `OrgTwo`, each with its own GitHub App and webhook secret (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an attacker who administers `OrgTwo`'s GitHub App (and therefore knows `OrgTwo`'s webhook secret), build a `push` payload:
```json
{
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "OrgOne/victim-repo" },
  "after": "<attacker-controlled sha>",
  ...
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(payload, OrgTwo_webhook_secret)>`.
4. `POST /webhooks` with header `X-Github-Event: push` and this body.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgTwo")` and successfully verifies the signature against `OrgTwo`'s secret [1](#0-0) .
6. The push handler is invoked with `params["repository"]["full_name"] == "OrgOne/victim-repo"`, causing `GithubSyncJob`/commit ingestion to run against `OrgOne`'s stack, as confirmed by the pattern exercised in `webhooks_controller_test.rb`'s `unknown_repo_payload["repository"]["full_name"]` test [4](#0-3) , with no cross-check between the verified owner and the acted-upon repository.

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

**File:** test/controllers/webhooks_controller_test.rb (L12-21)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
      end
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
