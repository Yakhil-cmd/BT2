### Title
Webhook signature is verified against the organization named in `repository.owner.login`/`organization.login`, while the repository actually written to is taken from an independent, unverified field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
This is a multi-tenant-secret analog of the Opyn "coerced/discarded validity signal" bug: the report's root cause is that a value used downstream (`getProceed`) is derived without carrying the qualifying context (the sign/boolean) that made the original computation meaningful, so a value can be *misattributed* to the wrong meaning. In `shipit-engine`, `WebhooksController#verify_signature` picks *which organization's webhook secret* to use for HMAC verification based on `repository_owner`, a field read straight out of the untrusted JSON body, and then hands the same untrusted body to event handlers that pick an entirely separate field (`repository.full_name`) to decide which `Repository`/`Stack` gets written to. The signature check therefore validates "this body was signed by organization X's secret" but the code that acts on the payload trusts "this body targets repository Y" — two different payload fields, only one of which is bound to the verification step.

### Finding Description
`verify_signature` is a `before_action` that determines the signing organization purely from the request body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the webhook secret for whatever organization name appears in the payload’s `repository.owner.login` (or `organization.login`): [3](#0-2) 

Once `verify_webhook_signature` returns true (i.e., the body’s HMAC matches *that org’s* configured `webhook_secret`), `create` dispatches the full, attacker-controlled JSON body to handlers: [4](#0-3) 

But the handlers never re-check `repository.owner.login`; they instead resolve the target `Repository`/`Stack` from `repository.full_name`: [5](#0-4) [6](#0-5) 

So the field that gates *which secret must sign the payload* (`repository.owner.login` / `organization.login`) is not the field that gates *which repository/stack the handler mutates* (`repository.full_name`). In a Shipit deployment configured for multiple organizations (`github_app_config`/`TOP_LEVEL_GH_KEYS` support a per-organization `secrets.github` map), this is exactly the "organization that authenticated versus the repository that is written" trust-binding equality from the rules, and it is broken: `verify(secret_of(payload.repository.owner.login)) == true` does **not** imply `handler.target == payload.repository.owner.login`'s repositories — it implies nothing about `payload.repository.full_name`, which is a sibling field inside the same unverified-until-that-point JSON body chosen by whoever crafts the request.

### Impact Explanation
An attacker who legitimately controls (or is a collaborator/admin on) one organization/repository configured in this Shipit instance's `secrets.github` map can compute a valid HMAC using *their own* org's `webhook_secret` (which they are entitled to know, e.g. as the org's GitHub App/webhook administrator) over a forged body where `repository.owner.login` is set to their own org (so it passes `verify_webhook_signature`) but `repository.full_name` is set to a *different* repository/stack tracked by the same Shipit instance. Handlers such as `PushHandler` and `StatusHandler` will then act on that unrelated stack — e.g., forcing `stack.sync_github(expected_head_sha: params.after)` or injecting a fabricated commit `Status` — for a repository the attacker does not own. This is a cross-repository write achieved by exploiting a signature check that authenticates the wrong field, matching the "cross-repository writes" Critical-impact category in the rules.

### Likelihood Explanation
This requires the deployment to be configured with per-organization webhook secrets (`Shipit.github_organizations`/`github_app_config`), which is a supported, documented configuration for multi-tenant Shipit installs, and requires the attacker to control at least one onboarded organization's webhook secret. That is a real but narrower precondition than a fully anonymous attacker, so likelihood is Medium-to-Low in single-org deployments (where there's only one secret, so the org name in the payload is irrelevant) but becomes concrete in any multi-org deployment, which is the scenario `github_app_config` exists to support.

### Recommendation
Bind the signature-verification identity to the same field(s) the handlers act on. Concretely, after computing `repository_owner` and verifying the signature, re-derive `repository.full_name` inside `verify_signature` and reject (422) if the organization portion of `full_name` does not match `repository_owner`/`organization.login` used to select the webhook secret. More robustly, do not let the payload choose which secret verifies it — resolve the expected organization from server-side state (e.g., the `Repository`/`Stack` record already provisioned for that `full_name`) before selecting `Shipit.github(organization:)`, so the secret used to verify is intrinsically tied to the repository the request claims to be about.

### Proof of Concept
1. Deploy Shipit configured with two organizations in `secrets.github`: `org-a` (attacker-administered) and `org-b` (victim, tracked stack `org-b/victim-repo`).
2. Attacker crafts a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `org-a`'s known `webhook_secret` over the raw body.
4. POST to `/webhooks`. `verify_signature` computes `repository_owner = "org-a"`, fetches `org-a`'s `GitHubApp`, and `verify_webhook_signature` succeeds because the attacker signed with the correct (their own) secret.
5. `create` dispatches to `Shipit::Webhooks.for_event('push')` → `PushHandler`, which resolves `repository_name` from `repository.full_name = "org-b/victim-repo"` and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack, despite the request never being signed by `org-b`'s secret.

**Uncertainty note:** I was not able to fully inspect `Repository.from_github_repo_name` or confirm whether any additional owner-cross-check exists elsewhere in the stack-resolution path (e.g., inside `Stack#sync_github`) within the indexed portions of the codebase; if such a check exists it could mitigate this specific handler but the underlying signature/target-field mismatch in `WebhooksController` would remain for any handler that trusts `repository.full_name` or similar fields without re-validating against the org used for signature verification.

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
