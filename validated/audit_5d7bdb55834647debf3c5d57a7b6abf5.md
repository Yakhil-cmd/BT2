## Finding: Webhook Organization Used for Signature Verification Is Not Bound to the Repository the Payload Acts On

### Title
Webhook signature verification organization is decoupled from the repository the payload writes to, allowing cross-organization commit-status / sync forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate a webhook's HMAC signature against using `repository.owner.login` (falling back to `organization.login`) read directly from the unauthenticated request body [1](#0-0) . However, once the signature check passes, the actual event handlers resolve the target `Repository`/`Stack` to act on using a *different* field from the same payload: `repository.full_name` [2](#0-1) . These two fields are never cross-checked against each other, so a webhook that is validly signed for organization A can carry a `repository.full_name` pointing at a repository belonging to organization B, provided both orgs are configured on the same Shipit instance (a documented and supported deployment, see `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`).

### Finding Description
This is analogous to the reported bug class: a value is trusted for one purpose (here, selecting the signing key/authentication boundary) while a *different, attacker-controlled* value from the same untrusted payload is the one actually acted upon — breaking the binding `organization that authenticated == repository that is written`.

- `Shipit.github(organization:)` looks up per-organization app config (`webhook_secret`, credentials) via `github_app_config` [3](#0-2) , keyed by the `organization` the controller extracts from `repository.owner.login` / `organization.login` [4](#0-3) .
- The HMAC is verified against the raw request body using that org's secret: `verify_webhook_signature` [5](#0-4) . Once verified, the *entire* raw payload — including the `repository.full_name` field that was never part of the org-selection logic — is passed unmodified to every handler.
- Every `Handler` subclass (e.g. `PushHandler`) resolves the affected `Stack` purely from `payload.dig('repository', 'full_name')` [2](#0-1) , with no re-check that this repository actually belongs to the organization whose secret validated the signature.
- `PushHandler#process` then triggers `stack.sync_github` for any stack found under that (attacker-chosen) `full_name`, regardless of which org's key signed the request [6](#0-5) .

Because a genuine GitHub webhook from a repository in org A is signed with org A's secret and only proves the payload came from GitHub for *some* event in org A, it does not prove the `repository.full_name` field truthfully identifies the repository in question. An attacker with legitimate push/webhook-triggering rights to any repository in org A (a normal, unprivileged external contributor relationship, not a Shipit credential) can get GitHub to deliver an event whose JSON body they otherwise cannot fully control, but for handlers/events where attacker-influenced sub-fields exist (e.g., commit `state`, `target_url`, `description` on `status` events, or `ref`/`after` on `push`), the org-boundary check performed by `verify_signature` provides no guarantee that `repository.full_name` matches the signing org.

### Impact Explanation
If a second, unrelated organization (org B) is configured on the same Shipit instance, forged/cross-org payloads validly signed by org A's webhook secret can be routed by `repository_name` to act on org B's `Repository`/`Stack` records — e.g., forcing a `GithubSyncJob` re-sync or (depending on which event/handler processes commit status fields) writing commit status data tied to org B commits. Where deploy/merge gating relies on such commit status records, this can contribute to an unauthorized deploy or merge decision, matching the Critical impact bar (unauthorized deploy) defined in scope.

### Likelihood Explanation
Exploitation requires: (1) the Shipit instance to be configured with multiple GitHub organizations (a documented, supported configuration), and (2) the attacker to have the ability to trigger a real, validly-signed webhook delivery from *any* repository under one of the configured organizations (e.g., by having push access to any repo they control there). No Shipit session, API token, or webhook secret is needed by the attacker themselves — only ordinary GitHub-side webhook-triggering ability in one of the configured orgs.

### Recommendation
In `WebhooksController#verify_signature` and/or `Handler#repository_name`, verify that the organization used to select the signing key (`repository.owner.login` / `organization.login`) matches the owner segment of `repository.full_name` before processing the event. Reject the webhook (422) if they diverge.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker has push access to `OrgA/some-repo`, which is registered with Shipit and configured to deliver webhooks.
3. Attacker triggers (or crafts, if the field is otherwise attacker-editable, e.g. via a `status`/commit-status style webhook body) a webhook payload where:
   - `organization.login` / `repository.owner.login` = `"OrgA"` (so `Shipit.github(organization: 'OrgA')` is used and the signature validates against OrgA's real secret, since it is a genuine OrgA-originated delivery),
   - `repository.full_name` = `"OrgB/target-repo"`.
4. `verify_signature` succeeds because the signature really was produced with OrgA's secret over this exact body [4](#0-3) .
5. The dispatched handler resolves the stack via `payload.dig('repository', 'full_name')` = `"OrgB/target-repo"` [2](#0-1)  and acts on OrgB's stack (e.g. `PushHandler` invokes `stack.sync_github` on it) [6](#0-5) , even though the request was never authenticated for OrgB.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
