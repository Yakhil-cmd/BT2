### Title
Webhook signature authenticates the sending organization but not the `repository`/`organization` fields handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
### Finding Description
`WebhooksController#verify_signature` selects which `Shipit::GitHubApp` (and thus which `webhook_secret`) to validate the incoming HMAC signature against using a value taken directly out of the unauthenticated request body: [1](#0-0) [2](#0-1) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

Shipit explicitly supports hosting multiple, independently-installed GitHub Apps/organizations from a single instance, each with its own `webhook_secret` (`Shipit.github(organization:)`), as documented and tested: [3](#0-2) [4](#0-3) 

The HMAC signature (`X-Hub-Signature`) only proves that the request body was produced by *someone holding a particular org's `webhook_secret`* — it says nothing about which repository, stack, or organization the payload's *content* actually references. After `verify_signature` passes, `create` parses the same attacker-influenced JSON body and dispatches it, unfiltered, to registered handlers keyed only by the `X-Github-Event` header: [5](#0-4) 

Handlers such as the push/status/membership handlers subsequently resolve `Stack`/`Repository`/`Commit`/`Team` records by fields inside that same body (e.g. `repository.full_name`, `organization.login`) that were never cross-checked against the organization whose secret validated the signature. In other words, the binding the code enforces is:

`organization whose webhook_secret signed the request == organization named in payload for signature-selection purposes`

but the binding it should enforce (and doesn't) is:

`organization whose webhook_secret signed the request == organization/repository the handler subsequently mutates state for`

### Impact Explanation
Because Shipit's own documentation and code support multiple tenants/organizations behind one instance, an actor who legitimately controls one configured GitHub App/organization (and therefore legitimately knows *that* org's `webhook_secret`, as they set it themselves when installing their own app) can produce a validly-signed webhook body while setting the `repository`/`organization` JSON fields to point at a *different* organization's stacks configured in the same Shipit instance. Because handlers trust these unverified fields to locate the `Stack`/`Repository`/`Commit` to mutate, this allows cross-tenant forgery of push/status/membership/pull_request events — e.g., injecting fake successful CI `status` events that satisfy `required_statuses` and unblock merges/deploys for a repository/org the attacker does not own, or fabricating `membership`/`pull_request` events that create `Team`/`User`/`MergeRequest` records tied to a foreign stack. This can lead to an unauthorized deploy or merge being triggered for a repository outside the attacker's control, which satisfies the "unauthorized deploy/merge" high-severity criterion.

### Likelihood Explanation
This requires the instance to be configured for multiple GitHub organizations (an explicitly documented and tested Shipit deployment mode) and requires the attacker to control at least one of those configured orgs' webhook secret (which they would legitimately possess as the installer/owner of their own GitHub App, not a privileged Shipit credential). Given that starting point, forging the cross-org payload is trivial — it's just crafting a JSON body with a mismatched `repository`/`organization` field before signing it with the secret they already hold. No Shipit session, `ApiClient` token, or `GITHUB_TOKEN` is needed.

### Recommendation
After verifying the HMAC signature, re-derive the authorized organization from the *verified* secret/app configuration (not from body fields) and cross-check it against the `repository.owner.login`/`organization.login` used by each handler before any record lookup or mutation. Reject events whose declared repository owner does not match the organization associated with the GitHub App whose secret validated the signature.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own installed GitHub App and `webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications" section).
2. As the party controlling `OrgB`'s GitHub App (i.e., knowing `OrgB`'s `webhook_secret`), craft a `push` (or `status`) webhook JSON body whose `repository.owner.login` is `OrgB` (so `repository_owner` resolves to `OrgB`'s app for signature verification) but whose `repository.full_name`/other stack-resolving fields reference a repository/stack that actually belongs to `OrgA`.
3. Compute `X-Hub-Signature` using `OrgB`'s real `webhook_secret` over this crafted body, and POST it to `/webhooks` with `X-Github-Event: push` (or `status`).
4. `verify_signature` succeeds because the signature matches `OrgB`'s secret and `repository_owner` (`OrgB`) selected the right app. `create` then calls the registered handler(s) with the full parsed body, which resolve and mutate `OrgA`'s stack/commit records based on the forged `repository.full_name`, without any check that `OrgA` matches the organization actually authenticated by the signature.

Note: I was unable to read the exact contents of `push_handler.rb`, `status_handler.rb`, `handler.rb`, and `repository.rb` in this session (tool errors on the final iteration), so the precise field names each handler uses to resolve `Stack`/`Repository` records could not be directly confirmed from source in this pass — this should be verified against those files before treating this as fully confirmed.

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
