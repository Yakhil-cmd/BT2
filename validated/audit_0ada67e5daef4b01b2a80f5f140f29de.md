### Title
Webhook signature verification binds to `repository.owner.login`, but event routing/writes use the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate the HMAC signature against using `repository_owner`, derived from the payload's `repository.owner.login` (or `organization.login`) field. Every webhook handler, however, determines *which Shipit `Stack`/`Repository` the event applies to* using a completely different, unverified field: `repository.full_name`. The signature only proves the payload was signed by whoever owns the secret for the organization named in `repository.owner.login`; it proves nothing about the `repository.full_name` value used to route the write action.

### Finding Description
In `verify_signature`, the organization used to pick the verification secret is: [1](#0-0) 

```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

This value feeds `Shipit.github(organization: repository_owner)` [2](#0-1)  which, for multi-org configs, resolves to a per-organization webhook secret via `github_app_config(organization)` [3](#0-2) . Only the HMAC over the raw body is checked; the specific `repository.full_name` value inside that same, already-signed body is never cross-checked against `repository.owner.login`.

Every handler that then acts on the payload resolves the target `Stack`/`Repository` from a **different** field, `repository.full_name`, not `repository.owner.login`: [4](#0-3) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

The `pull_request` handlers repeat this pattern directly (e.g. `OpenedHandler#repository`, which resolves `Shipit::Repository.from_github_repo_name(params.repository.full_name)` and then provisions/closes review stacks) [5](#0-4) .

Because the field used to select the verifying secret (`repository.owner.login`) and the field used to select the acted-upon repository (`repository.full_name`) are independent values inside the same JSON body, an attacker who legitimately controls a GitHub App/webhook secret for *any* organization configured on the Shipit instance (e.g., their own org, onboarded via the documented multi-tenant setup in `github_app_config`/`Shipit.github_organizations`) can craft and correctly sign a payload where:
- `repository.owner.login` = their own org (so `verify_signature` picks their own valid secret and passes), and
- `repository.full_name` = `"victim-org/some-repo"` (any other repository/stack tracked by this same Shipit instance).

The signature check passes because it is computed and verified entirely against a payload the attacker controls and correctly signs with their own known-good secret; nothing ties the verified owner to the acted-upon repository name.

### Impact Explanation
This breaks the trust binding "organization that authenticated == repository that is written," matching the requested analog class. Concretely, an attacker with a valid webhook secret for org A can forge events (`push`, `pull_request`, `status`, `check_suite`, `membership`, etc.) that are routed by `repository.full_name` to a Stack belonging to org B:
- Forged `push` events enqueue `GithubSyncJob` for org B's stack (as shown by handler routing via `repository_name`), letting the attacker inject arbitrary `expected_head_sha` synchronization for a repository they don't control.
- Forged `pull_request` "opened"/"closed"/"labeled" events can create, close, or otherwise manipulate org B's review stacks via `ReviewStackAdapter`.
- Forged `status`/`check_suite` events can write commit statuses/check-run state for org B's commits, influencing Shipit's merge/deploy gating logic.

This constitutes unauthorized cross-repository writes into stacks not owned by the attacker's organization, satisfying the Critical impact bar ("cross-repository writes").

### Likelihood Explanation
Exploitability requires the attacker to control (or self-provision) a valid webhook secret for at least one organization configured on the target Shipit instance — a realistic scenario in multi-tenant/self-service Shipit deployments where multiple independent GitHub orgs each install their own GitHub App and are configured under `secrets.github` (see `github_app_config`, `github_organizations`) [6](#0-5) . No repository write access, Shipit session, or `ApiClient` token to the *victim* org is required — only knowledge of one's own legitimately-provisioned org secret, making this an unprivileged-attacker path relative to any other tenant on the same instance.

### Recommendation
When resolving the target `Stack`/`Repository` for a webhook event, verify that the `repository.full_name`'s owner segment matches the `repository_owner` (or `organization.login`) that was used to select and validate the webhook signature, rejecting (422) any payload where these disagree. This mirrors the report's recommended mitigation of validating that "input B" (the acted-upon repository) is actually bound to "input A" (the authenticated/signing organization) rather than trusting two independent fields from the same unauthenticated JSON body.

### Proof of Concept
1. Configure Shipit with two organizations, `org-attacker` and `org-victim`, each with its own GitHub App/webhook secret (multi-org `secrets.github` config, per `github_app_config`).
2. As the legitimate owner/admin of `org-attacker`'s GitHub App, compute a correct `X-Hub-Signature` HMAC (using `org-attacker`'s known webhook secret) over a JSON body of the attacker's choosing.
3. Craft the JSON body for a `push` event with:
   - `repository.owner.login = "org-attacker"` (or `organization.login = "org-attacker"`)
   - `repository.full_name = "org-victim/target-repo"` (a repo/stack actually tracked by Shipit under `org-victim`)
4. POST this to `/webhooks` with header `X-Github-Event: push` and the correctly computed signature for `org-attacker`'s secret.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"org-attacker"`, fetches `org-attacker`'s secret, and validates the signature successfully [2](#0-1) .
6. The `push` handler resolves the affected stacks via `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, i.e. `org-victim/target-repo` [4](#0-3) , and enqueues a `GithubSyncJob`/other writes against `org-victim`'s stack — despite the attacker never having proven any relationship with `org-victim`.

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

**File:** lib/shipit.rb (L170-181)
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
```

**File:** lib/shipit.rb (L190-200)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
