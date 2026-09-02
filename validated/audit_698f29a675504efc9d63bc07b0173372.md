Based on the evidence gathered, there is a valid analog: the organization used to select/verify the webhook HMAC secret is derived from attacker-controlled, not-yet-verified payload fields, breaking the binding "organization whose secret authenticated the request" = "organization the request is actually processed as."

### Title
Webhook signature verification selects the GitHub App secret using unverified payload data - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp` (and thus which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a value read directly out of the untrusted, not-yet-authenticated JSON body, before the signature has been checked.

### Finding Description
`verify_signature` calls `Shipit.github(organization: repository_owner)` and then verifies `X-Hub-Signature` against that organization's `webhook_secret`. [1](#0-0) 
`repository_owner` is computed purely from request JSON, with no cryptographic guarantee at the point it is used to select the verification key: [2](#0-1) 
`Shipit.github` resolves the app configuration keyed by this attacker-supplied organization name in a multi-org deployment (`github_app_config`/`secrets.github`): [3](#0-2) 

The equality that should hold is: *the organization whose `webhook_secret` validated the HMAC* == *the organization whose repository/stack the payload will actually be applied to by the event handler*. Because `repository_owner` is read from the same untrusted body used to select the key, and the body is otherwise processed unmodified by `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) 
an attacker who knows (or controls) the `webhook_secret` for one configured GitHub organization (e.g., their own org with a Shipit-linked app installation) can craft a payload whose `repository.owner.login`/`organization.login` says "org A" (to force verification against org A's known secret) while embedding a different `repository.full_name` or other identifying fields understood by the downstream handler to target a stack that belongs to a different organization "org B" in the same multi-tenant Shipit instance.

### Impact Explanation
If successful, this would let an attacker forge webhook-driven state changes (e.g., synthetic `push`, `status`, `check_suite`, `membership`, or `pull_request` events) against a stack/repository outside the organization whose secret was actually used to authenticate the request, in a Shipit instance configured with the documented multi-organization schema (`docs/setup.md`'s "Using Multiple Github Applications" section) [5](#0-4) 
This does not clear the reward bar as an unqualified "unauthorized deploy" or "cross-repository write" on its own, because Shipit webhook handlers only mutate metadata (statuses, commits, memberships, PR checklist state) rather than directly triggering deploys/rollbacks/merges from unauthenticated event data; actual deploy/rollback/merge actions still require an authenticated `User`/`ApiClient` action through the stack/API layer. I could not fully verify, in the time available, whether any specific handler (e.g., `push_handler.rb`, `status_handler.rb`) resolves the target `Stack`/`Repository` purely by `full_name` without re-validating that the `full_name`'s owner matches `repository_owner`, since the file reads for those handlers failed to return content in this session. That is the deciding factor for whether this crosses into the "unauthorized deploy" or "cross-repository write" impact bar.

### Likelihood Explanation
Requires the attacker to know a valid `webhook_secret` for at least one organization configured in the same multi-tenant Shipit instance — plausible if the attacker administers their own org's GitHub App installation pointed at a shared Shipit deployment — combined with crafting a payload whose owner/organization fields diverge from the fields the downstream handler actually keys stack resolution on.

### Recommendation
After signature verification succeeds, re-derive the organization that actually authenticated the request from the app config used (not from the payload), and reject/short-circuit any handler processing if the repository/organization fields consumed later in `handler.call(params)` do not match the organization whose secret validated the signature.

### Proof of Concept
Not fully constructable without confirming exactly how each event handler (`push_handler.rb`, `status_handler.rb`, membership/pull_request handlers) resolves the target `Stack` from payload fields — this file content could not be retrieved in this session due to a tool error on the final iteration. A concrete PoC would require: (1) a multi-org Shipit config, (2) knowledge of org A's `webhook_secret`, (3) a crafted payload with `repository.owner.login = "orgA"` (for signature routing) but repository/commit identifiers pointing at an org B stack, sent with a valid HMAC computed using org A's secret.

**Note on confidence:** Given the inability to inspect `push_handler.rb`, `status_handler.rb`, and other handler implementations in this final iteration, I cannot confirm whether the downstream stack-resolution logic re-validates the owner/organization consistency, which is required to conclusively prove exploitability meeting the Critical/High impact bar. This finding should be treated as a candidate requiring that additional verification before being considered fully validated.

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
