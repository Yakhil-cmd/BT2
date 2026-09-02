### Title
Cross-organization webhook confused deputy: organization used to select the verification secret differs from the repository whose stacks are acted upon - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret used to authenticate an inbound GitHub webhook using an organization name taken from the *unauthenticated* JSON body itself, while the downstream `Handler#stacks` resolves which `Stack`/`Repository` the event acts on from a *different* field in the same unauthenticated body. Because these two fields are never cross-checked, an attacker who legitimately controls the webhook secret for their own configured GitHub organization in a multi-tenant Shipit deployment can forge a webhook whose signature validates under their own organization but whose payload targets a completely different, victim organization's repository/stack.

### Finding Description
`verify_signature` computes `repository_owner` straight from the parsed, not-yet-verified request body and uses it to pick which per-organization `GitHub App` config (and therefore which `webhook_secret`) is used to check the HMAC signature: [1](#0-0) [2](#0-1) 

Shipit natively supports multiple GitHub organizations each with their own secret, selected via `Shipit.github(organization:)` / `github_app_config`: [3](#0-2) 

Once the signature check passes (which only proves the raw body was HMAC-signed with *some* configured organization's secret — the one named in `repository.owner.login`), every registered handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolves the target `Stack` from a *different* field of the same body — `repository.full_name` — via the shared `Handler#stacks`/`repository_name` helpers: [4](#0-3) 

Nothing in this chain enforces that `repository.owner.login` (the organization whose secret was used to authenticate the request) matches the owner segment of `repository.full_name` (the repository whose stacks will be modified). The trust binding that should hold is:

`organization authenticated == organization owning the repository acted upon`

but the code only enforces `organization authenticated == organization named in payload["repository"]["owner"]["login"]`, which is attacker-supplied data covered by the attacker's *own* valid signature, not by any binding to `full_name`.

### Impact Explanation
In a multi-organization Shipit deployment (the officially supported `github_organizations` configuration, one webhook secret per org), any user who is an admin of *their own* configured GitHub organization — and therefore legitimately knows/controls *their own* org's `webhook_secret` — can sign a payload with `repository.owner.login = "their-org"` (so it passes `verify_signature` against their own known secret) while setting `repository.full_name = "victim-org/victim-repo"`. This request will be routed to `Repository.from_github_repo_name("victim-org/victim-repo")` and dispatched to that repository's stacks, e.g.: [5](#0-4) 

This lets a low-privilege tenant push forged `push`, `status`, and `check_suite` events against another tenant's stacks despite never having been issued credentials for that tenant's repository, breaking the organization/repository trust isolation the multi-tenant webhook design is meant to provide.

### Likelihood Explanation
This requires only being a legitimate administrator of *any one* configured GitHub organization in a multi-org Shipit deployment (i.e., knowing that organization's own `webhook_secret`, which such an admin is expected to know since they configure it) and crafting a raw HTTP POST with a mismatched `owner.login`/`full_name` pair. No Shipit session, `ApiClient` token, or GitHub App private key is required — only the ability to sign a request with one's own already-known secret, which is squarely an unprivileged-attacker capability relative to the victim organization/repository.

### Recommendation
After signature verification, validate that the organization used to select the webhook secret (`repository.owner.login` / `organization.login`) matches the owner segment parsed out of `repository.full_name` before dispatching to handlers, rejecting the request (422) on mismatch. Alternatively, resolve the target `Repository`/`Stack` using the same verified organization identifier rather than trusting `full_name` independently in `Handler#repository_name`.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (secret `S1`) and `victim-org` (secret `S2`), each owning at least one stack.
2. As an admin who legitimately knows `S1` (attacker-org's own webhook secret), build a `push` payload:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<any sha>",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(S1, raw_body)>` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner = "attacker-org"`, fetches `attacker-org`'s config/secret `S1`, and the signature validates.
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on victim-org's stack, even though the request was never signed by, nor authorized for, `victim-org`.

Note: I could not fully trace within the available tool budget whether any handler additionally triggers an automatic GitHub-side write (e.g., posted deployment status) or an automatic continuous-deployment run purely from a forged `status`/`check_suite` event; that would elevate this from a cross-tenant integrity issue to an unauthorized-deploy scenario, but is not confirmed with direct citations here.

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
