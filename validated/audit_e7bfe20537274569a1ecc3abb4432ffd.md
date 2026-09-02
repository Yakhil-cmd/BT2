### Title
Webhook Organization/Signature Binding Never Validated Against the Repository Actually Acted Upon - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
This engine's webhook trust model verifies an HMAC signature against the GitHub App configured for `params.dig('repository','owner','login')` (or `organization.login`), but every event handler subsequently resolves the actual `Repository`/`Stack` to act on from a *different* payload field, `payload.dig('repository','full_name')`, without ever confirming the two are consistent. This breaks the required binding `verified_organization == owner_of_repository_written`, mirroring the reported bug class where a value used for validation (`ethUsdPrice`/`arbUsdPrice`) is decoupled from the value actually used downstream without a consistency/staleness check.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`: [1](#0-0) [2](#0-1) 

Meanwhile, every `Handler` subclass (`PushHandler`, the `PullRequest::*Handler`s, etc.) resolves the target repository/stack from a **separate** JSON field, `repository.full_name`, never cross-checked against `repository.owner.login`: [3](#0-2) [4](#0-3) [5](#0-4) 

Both `repository.owner.login` (used for signature-org selection) and `repository.full_name` (used for target-repository resolution) are attacker-controlled strings inside the same unauthenticated-until-verified JSON body — nothing in Shipit constrains `full_name` to actually start with `owner.login`. Additionally, `verify_webhook_signature` short-circuits to `true` whenever the resolved organization's `webhook_secret` is blank/unset: [6](#0-5) 

and the docs/config explicitly treat `webhook_secret` as optional, with multiple sample configs shipping it as `nil`: [7](#0-6) [8](#0-7) 

In a multi-organization Shipit installation (the engine explicitly supports this — see the dummy `secrets_double_github_app.yml` fixture with `OrgOne`/`OrgTwo`), if *any one* configured organization has no `webhook_secret`, an attacker who merely knows that org's login can forge a webhook request where:
- `repository.owner.login` = the org with no `webhook_secret` (or `organization.login` for events that use that fallback) → satisfies `verify_signature` (bypassed entirely since `webhook_secret` is blank) and resolves a valid, known `Shipit.github(organization:)` app,
- `repository.full_name` = `"OrgOne/some-other-tracked-repo"`, i.e., a repository belonging to a *different*, properly-secured organization that Shipit also tracks.

Because `Handler#repository_name` only reads `full_name` and never checks it against the verified `repository_owner`, the handler acts on `OrgOne`'s stack even though the signature verification path never touched `OrgOne`'s (potentially private) `webhook_secret`.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" boundary called out as in-scope. Concretely reachable, unprivileged-attacker consequences include:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` (a `GithubSyncJob`) against a stack belonging to an organization the attacker never authenticated for — an unauthorized, attacker-triggered resync/state mutation of another org's tracked stack.
- `PullRequest::OpenedHandler`/`ReopenedHandler`/`UnlabeledHandler` etc. can create, archive, or unarchive `ReviewStack` records (`stack.archive!`, `stack.unarchive!`, `ReviewStackAdapter#create!`) for a repository belonging to the unrelated, secured organization, purely by supplying a mismatched `full_name` while riding on the weakly-secured org's (or unsecured org's) signature path.

This satisfies the "cross-repository writes" / "unauthorized deploy or rollback"-class High/Critical impact bar, since state-changing actions (stack sync, review-stack provisioning/archival) are performed against a repository that was never actually authenticated for in this request.

### Likelihood Explanation
Exploitability requires only:
1. A multi-org Shipit deployment (explicitly supported and documented — `docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`).
2. At least one configured organization with no `webhook_secret` (explicitly documented as optional), or an org whose secret the attacker can otherwise obtain by controlling that org's own GitHub App webhook config (since they are independent per-org secrets by design).
3. Knowledge of another tracked organization's repository `full_name` (public information, visible in Shipit's own UI/API for any stack the target org has already added).

No repository write access, session, or `ApiClient` token is required — only the ability to POST to the public `/webhooks` endpoint with a crafted JSON body and an `X-Hub-Signature` header (which is either irrelevant, when the resolved secret is blank, or forgeable for the attacker's own low-value org where they control the real secret).

### Recommendation
Cross-validate `repository.owner.login` (used to select/verify the signing organization) against `repository.full_name`'s owner segment before dispatching to any handler, and reject the webhook if they diverge. Do not allow a globally-missing `webhook_secret` on any configured organization to implicitly authorize actions against a different organization's resources — instead resolve and verify against the organization that actually owns the resolved `Repository`/`Stack` record, not solely against the client-supplied `owner.login`/`organization.login` field.

### Proof of Concept
1. Configure Shipit with two orgs: `UnsecuredOrg` (no `webhook_secret`) and `SecuredOrg` (real `webhook_secret`), both with stacks tracked in Shipit (mirrors `test/dummy/config/secrets_double_github_app.yml`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "full_name": "SecuredOrg/target-repo",
    "owner": { "login": "UnsecuredOrg" }
  }
}
```
3. `WebhooksController#repository_owner` returns `"UnsecuredOrg"`; `Shipit.github(organization: "UnsecuredOrg")` resolves an app whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` for any/no `X-Hub-Signature` value — [9](#0-8) .
4. `PushHandler#stacks` calls `Repository.from_github_repo_name(repository_name)` where `repository_name` is `payload.dig('repository','full_name')` = `"SecuredOrg/target-repo"` — [10](#0-9) , causing `SecuredOrg`'s stack to be synced via `GithubSyncJob` despite the request never being authenticated for `SecuredOrg`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L48-54)
```ruby
          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

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
