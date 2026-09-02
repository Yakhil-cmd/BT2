### Title
Webhook signature is verified against an attacker-controlled organization while handlers act on an unrelated repository/organization field in the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against by reading `repository.owner.login` (or `organization.login`) directly out of the untrusted, not-yet-verified JSON body. Once the signature check passes, the entire raw JSON body — including `repository.full_name`, which is never cross-checked against the field used for authentication — is handed to the event handlers. In a multi-organization Shipit deployment (`Shipit.github(organization: ...)`, `secrets.github` keyed by org, as documented in `docs/setup.md` "Using Multiple Github Applications"), this breaks the equality: `organization whose secret authenticated the request == organization whose repository/stack is acted upon`.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) [2](#0-1) 

`verify_signature` picks `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` is read straight from the JSON body (`params.dig('repository','owner','login')`). It then verifies the raw body's HMAC using that org's `webhook_secret`: [3](#0-2) 

Once verification succeeds, `create` passes the **entire raw payload** — not just the field used to pick the secret — to every registered handler for the event: [4](#0-3) 

Handlers such as `PushHandler` and the `PullRequest::*` handlers resolve the target `Repository`/`Stack` using a **different** field, `repository.full_name`, which is never checked for consistency with `repository.owner.login`: [5](#0-4) [6](#0-5) 

Shipit explicitly supports multi-org configurations where each organization has its own webhook secret, generated/set by whoever administers that org's GitHub App: [7](#0-6) [8](#0-7) 

Because `webhook_secret` for organization "A" is knowable/controllable by whoever set up organization A's GitHub App (an unprivileged actor with respect to organization B), that actor can craft an arbitrary raw JSON body themselves, sign it with organization A's secret, but populate `repository.full_name` (and any other payload field) with organization B's repository. `verify_signature` will authenticate the request as legitimate (since it only checks `repository.owner.login == "A"` against A's secret) and the handler will then act on organization B's stack, because it trusts `repository.full_name` from the same unverified body without re-deriving/re-checking it against the authenticated organization.

### Impact Explanation
For `PushHandler`, this triggers `stack.sync_github(expected_head_sha: ...)` → `GithubSyncJob`, which re-fetches commits from GitHub using the app's own installation token for the *targetted* stack's real organization/repo (`stack.github_api`), so it is partially self-correcting for push events. However, the same signature-vs-payload confusion generalizes to any handler that trusts payload-derived org/repo identifiers without cross-validating them against the authenticated organization (e.g. `pull_request` handlers driving `ReviewStackAdapter.create!`/`archive!`/`unarchive!` provisioning actions on a foreign org's review stacks, keyed purely off `params.repository.full_name`). This is an authentication-boundary flaw: the entity that authenticates (org A's secret) is not the entity being acted upon (org B's repository/stack), matching the required binding break "an organization that authenticated versus the repository that is written."

### Likelihood Explanation
Exploitability requires the attacker to control (or know) the `webhook_secret` for at least one organization configured in the same Shipit instance — realistic in any multi-tenant/multi-org Shipit deployment, since org admins typically set their own GitHub App webhook secret. No Shipit session, `ApiClient` token, or `github_access_token` is required; only the ability to send a raw HTTP POST to `/webhooks` with a self-computed `X-Hub-Signature`.

### Recommendation
Bind the field used to select the verification secret to the field(s) used by every handler, or better, verify the signature is valid, then separately assert that `repository.full_name`'s owner segment matches the organization whose secret validated the signature (reject otherwise). Alternatively, derive the target stack/repository strictly from the already-authenticated organization instead of re-reading an independent field of the same untrusted body.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with distinct GitHub Apps/`webhook_secret`s (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As the administrator of OrgA's GitHub App (an unprivileged party relative to OrgB), craft a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, verifies successfully against `OrgA`'s secret.
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgB/victim-repo")` and calls `sync_github` on `OrgB`'s stack — despite the request never being authenticated by `OrgB`.

*Note: I was not able to fully trace every downstream handler (e.g., `pull_request` review-stack provisioning) to confirm whether any of them perform an unauthorized write beyond a GitHub-API resync; this would benefit from a full Devin session with a running instance to confirm the maximum practical impact (e.g., unauthorized deploy trigger via crafted `status`/`check_suite` events on a foreign stack).*

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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
