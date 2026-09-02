### Title
Cross-Organization CI Status Forgery via `StatusHandler` — Webhook Signature Binds To Attacker's Org, Not To The Commit's Repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using the `repository.owner.login` field taken from the *same, not-yet-verified* JSON body. Once the signature check passes, the event is dispatched to `Shipit::Webhooks::Handlers::StatusHandler#process`, which writes a GitHub "status" (CI result) onto any `Commit` row that matches `params.sha` — with **no check at all** that the commit belongs to the organization/repository whose secret was used to authenticate the request. In a multi-organization Shipit deployment, an attacker who administers their own GitHub App/organization (and therefore legitimately knows that org's `webhook_secret`) can sign an arbitrary JSON payload and forge a CI status for a commit sha belonging to a completely different organization's stack.

### Finding Description
Signature verification is performed in `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) 
The organization used to pick the webhook secret, `repository_owner`, is read directly out of the untrusted payload: [2](#0-1) 

`Shipit.github(organization:)` resolves per-organization configuration (each with its own `webhook_secret`) when multiple GitHub Apps are configured, as documented and tested: [3](#0-2) [4](#0-3) 

This means signature validity only proves "the sender knows the secret configured for the organization named in `repository.owner.login`" — it says nothing about the rest of the JSON body's content, including which repository/commit the event's data actually targets.

After signature verification, the full (attacker-controlled) JSON body is dispatched unmodified to the handler: [5](#0-4) 

`StatusHandler#process` writes a CI status keyed purely by commit `sha`, with no repository or organization binding whatsoever: [6](#0-5) 

Unlike other handlers (`PushHandler`, `PullRequest::*Handler`) which scope their effect through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before acting: [7](#0-6) 
`StatusHandler` performs a global `Commit.where(sha: params.sha)` lookup with no analogous scoping, and `Commit#sha` values are not namespaced per organization.

**The broken binding, stated as an equality that the code fails to enforce:**
`organization authenticated by the verified HMAC signature` **must equal** `organization that owns the repository/commit being written to`.
`StatusHandler` breaks this because the webhook-secret selection is keyed off `repository.owner.login` (attacker-controlled, but must equal the attacker's own org to pass signature check), while the actual database write is keyed off `sha` alone, with no comparison back to `repository.owner.login`, `repository.full_name`, or the org whose secret validated the request.

This directly mirrors the report's bug class: a field acted upon (`sha` → which commit/stack gets the status) is never covered/constrained by what was actually authenticated (`repository.owner.login` used only to pick the HMAC key), exactly as `makerFee` was never covered by the 0x order's cryptographic authorization even though `makerToken`/`takerToken` were checked.

### Impact Explanation
An attacker who legitimately controls a GitHub organization/App that is one of several tenants configured in a multi-org Shipit instance (`config/secrets.yml` with per-organization `github:` keys, as documented in `docs/setup.md`) knows that org's own `webhook_secret` by design (they configured it). Using that secret, they can sign and submit a forged `status` webhook event whose `sha` matches a commit belonging to a **different** tenant/organization's stack, and set `state: "success"`, `context`, etc. arbitrarily.

If that victim stack's `shipit.yml` gates deploys or continuous delivery on CI status (`require_ci`), the forged "success" status can make an otherwise-unvetted or broken commit appear deployable, potentially leading to it being auto-deployed via continuous delivery or manually deployed by a legitimate operator who trusts the (forged) green CI status. This is a cross-tenant integrity violation of Shipit's CI-gating trust model and can contribute to an unauthorized ship of unvetted code — matching the "unauthorized deploy" / "cross-repository writes" impact bar.

### Likelihood Explanation
Requires: (1) a Shipit deployment configured with the multi-organization GitHub App schema (explicitly supported/documented feature), and (2) the attacker being a legitimate admin of one of the configured, less-trusted tenant organizations — no privileged Shipit account, `ApiClient` token, or GitHub token belonging to the victim organization is needed. The commit `sha` is guessable/discoverable (commits are public git objects, often visible via the victim repo's git history), and the handler performs no repository check. This is realistically triggerable in any multi-tenant Shipit instance.

### Recommendation
In `StatusHandler` (and any other handler that does not currently scope by repository), verify that the commit(s) being mutated belong to the same repository/organization as `payload.dig('repository', 'full_name')` / the organization whose secret validated the signature, mirroring the pattern already used in `Handler#stacks` (`Repository.from_github_repo_name(repository_name)`). Additionally, `WebhooksController#verify_signature` should not use an untrusted, attacker-suppliable field to select which secret to check the signature against without subsequently re-validating that all repository-identifying fields in the payload are consistent with that same organization.

### Proof of Concept
1. Shipit is deployed with two configured GitHub App organizations, `OrgA` (attacker-administered) and `OrgB` (victim), per `docs/setup.md`'s "Using Multiple GitHub Applications" section.
2. Attacker knows `OrgA`'s `webhook_secret` because they configured `OrgA`'s GitHub App themselves.
3. Attacker crafts a JSON body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/whatever" },
  "sha": "<sha of a commit belonging to OrgB's stack>",
  "state": "success",
  "context": "ci/forged"
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POSTs to `/webhooks` with header `X-Github-Event: status`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and successfully verifies the signature using `OrgA`'s secret (`app/controllers/shipit/webhooks_controller.rb` lines 24-30).
6. `StatusHandler#process` executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, writing a forged "success" CI status onto `OrgB`'s commit — without ever checking that the commit's repository matches `OrgA`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
