### Title
Webhook Signature Verification Uses a Different Organization Field Than the Repository Field Used by Handlers, Allowing Cross-Organization Webhook Forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to use for validating the HMAC signature based on `repository.owner.login` (or `organization.login`) extracted from the JSON payload, while the actual event handlers that act on the payload (which `Stack`/`Repository` gets a status update, a PR review-stack, a fetch, etc.) resolve the target repository from the unrelated `repository.full_name` field. In a multi-organization Shipit deployment, these two fields can be made to disagree within a single signed payload, breaking the binding "organization whose secret authenticated the request == repository that gets written to."

### Finding Description
`verify_signature` picks the app/secret used for HMAC verification purely from the payload's declared owner: [1](#0-0) [2](#0-1) 

```
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization: repository_owner)` looks up per-organization config (including `webhook_secret`) via `github_app_config`: [3](#0-2) 

The HMAC itself is computed over the *entire* raw request body (`request.raw_post`), so it proves only that *some* org's registered `webhook_secret` was used to sign *this exact byte string* — it does not prove which sub-field of that payload is "authoritative."

However, every webhook handler determines the target `Stack`/`Repository` using a *different* field, `repository.full_name`, not `repository.owner.login`: [4](#0-3) 

```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

The same divergence exists in `PullRequest::OpenedHandler`, which resolves the acted-upon repository from `params.repository.full_name`: [5](#0-4) [6](#0-5) 

In a Shipit installation configured with multiple GitHub organizations (a documented and supported setup): [7](#0-6) 

each organization has its own independent `webhook_secret`, and `Shipit.github(organization:)` is chosen dynamically per-request: [8](#0-7) 

**Binding broken:** `organization authenticated by webhook_secret == organization/repository whose Stack/Repository is written`. An attacker who legitimately controls a GitHub App installation on their own organization ("org-A", with a known `webhook_secret`) can:
1. Set `repository.owner.login` (or `organization.login`) to `"org-A"` — this is only used to pick which secret verifies the signature.
2. Set `repository.full_name` to `"org-B/victim-repo"` — this is the field every handler actually uses to resolve the `Stack`.
3. Sign the crafted payload with org-A's `webhook_secret` (which the attacker legitimately knows) and POST it to `/webhooks`.

`verify_signature` succeeds (org-A's secret matches org-A's signature), yet `Handler#stacks` / `OpenedHandler#repository` act on `org-B`'s `Stack`/`Repository`, which the attacker's org-A GitHub App has no relationship to.

### Impact Explanation
Depending on the event type forged this way, the impact reaches "unauthorized deploy, rollback, or merge":
- `status` webhooks (`Handlers::StatusHandler`) set commit statuses on arbitrary commits of a victim's `Stack`, which are consumed by `ci.require` gating and the merge queue — a forged "success" status can make an otherwise-blocked commit deployable/mergeable in the victim's stack.
- `pull_request` `opened`/`labeled` webhooks can trigger provisioning of review stacks for a victim's repository (`ReviewStackAdapter#find_or_create!`).
- `push` webhooks can trigger fetches feeding into the victim's continuous-deployment pipeline.

This satisfies the required Critical impact class ("an unauthorized deploy, rollback or merge") because the write target (`Stack`/`Repository`) is fully decoupled from the credential that authenticated the request.

### Likelihood Explanation
Exploitation requires only that the attacker operate their own GitHub organization with a Shipit GitHub App installation (a normal, low-privilege scenario in any multi-tenant Shipit deployment as documented in `docs/setup.md`), plus the ability to send an arbitrary HTTP POST to the `/webhooks` endpoint (no Shipit session, `ApiClient` token, or victim-org access is needed). Crafting the payload only requires knowing that `repository.owner.login`/`organization.login` and `repository.full_name` are independent, attacker-controlled JSON keys.

### Recommendation
Verify the signature using the same organization/repository field that handlers subsequently trust, or re-derive `repository_owner` from `repository.full_name`'s owner segment (splitting on `/`) rather than a separate `owner.login`/`organization.login` field. Alternatively, after selecting the signing org, assert that `repository.full_name`'s owner segment matches the organization used for verification before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `org-a` (attacker-controlled) and `org-b` (victim), each with distinct `webhook_secret`s, per `docs/setup.md`'s multi-org format.
2. Attacker crafts a `status` (or `pull_request`) JSON payload:
```json
{
  "action": "opened",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  ...
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org-a's webhook_secret, raw_body)>` (they legitimately know org-a's secret).
4. POST to `/webhooks` with header `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner` to `"org-a"`, fetches org-a's app, and verification succeeds.
6. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, whose base `Handler#repository_name` resolves `"org-b/victim-repo"` from `full_name`, causing the status update to be applied to the victim's `Stack`, despite the request only being authenticated for `org-a`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
