### Title
Cross-organization webhook forgery via mismatched signature-verification key and event-processing repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit installation, the webhook signature is verified using a per-organization `webhook_secret` that is selected from a field inside the *unauthenticated* JSON body (`repository.owner.login` / `organization.login`), while the actual event-processing logic (e.g. `PushHandler`) resolves the target `Repository`/`Stack` from a *different* field of the same body (`repository.full_name`). This is directly analogous to the Optimism bug: the "origin check" (webhook secret / organization used to validate the HMAC) does not bind to the same value used for the "write path" (repository that gets synced), so a signature computed with one organization's secret can be replayed to act on a repository belonging to a different organization.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to validate the signature against using `repository_owner`, itself read straight out of the untrusted JSON payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a distinct config (and thus a distinct `webhook_secret`) per organization key in `secrets.github`: [3](#0-2) 

After the signature check passes, the controller re-parses the same raw body and dispatches it, unmodified, to the registered handlers: [4](#0-3) 

The handler that actually mutates state (e.g. `PushHandler`) determines which `Repository`/`Stack` to act on from `payload.dig('repository', 'full_name')`, a completely different field than the one used to select the verifying secret: [5](#0-4) [6](#0-5) 

Because the HMAC covers the full raw body (both fields), signing with organization A's secret over a payload where `organization.login`/`repository.owner.login` = "org-A" (used only to select the verification key) but `repository.full_name` = "org-B/some-repo" (used only to select the affected `Stack`) would pass signature verification and then run push-sync (or membership/team, pull_request, status handlers) against org B's repository/stack — a repository the sender never controls or has webhook credentials for. This breaks the equality that should hold: *organization whose secret authenticated the request* == *organization/repository that is written*.

Whether this is exploitable depends entirely on whether the deployment uses the **multi-organization** `secrets.github` schema (multiple orgs, each with their own `webhook_secret`) as documented in `docs/setup.md`/`config/secrets.development.shopify.yml`. In that configuration, an attacker who legitimately controls (or has compromised) one onboarded GitHub organization's App/webhook secret can forge a payload naming their own org for the signature check while naming an unrelated onboarded org/repository's `full_name` for the actual state-mutating fields.

### Impact Explanation
If reachable, this allows an attacker who is a legitimate integrator for one onboarded GitHub organization to inject forged webhook events (push/status/check_suite/pull_request/membership) that are attributed to and acted upon a different organization's stacks — e.g. triggering `GithubSyncJob`/CI status changes/team-membership changes for a repository/stack outside their control. This is a cross-repository/cross-organization write performed without the target organization's own webhook credential, matching the "cross-repository writes" / "unauthorized deploy" impact bar (continuous delivery configurations can turn a forged push+status combination into an actual deploy).

### Likelihood Explanation
Likelihood is **conditional and low-to-moderate**: it requires (a) the operator to have configured Shipit with the multi-organization `github:` secrets schema (supported and documented, but not the default single-org schema), and (b) the attacker to already hold legitimate webhook-secret-level trust for at least one onboarded organization. It does not require any Shipit session, API token, or GitHub App private key — only knowledge of one organization's `webhook_secret`, which is a lower bar than the other credentials this engine treats as privileged. I could not fully verify from the index whether any additional cross-check ties `repository_owner` to `repository.full_name`'s owner before handler dispatch; no such check was found in `WebhooksController` or `Webhooks::Handlers::Handler`.

### Recommendation
After signature verification, re-derive the organization strictly from the same field used to select the resource being mutated (`repository.full_name`'s owner segment, or an explicit `Repository#github_organization` lookup) and require it to equal `repository_owner`/the org whose secret validated the signature, rejecting the webhook (422) on mismatch. Alternatively, verify the signature using the secret of the organization that owns the resolved `Repository`/`Stack` rather than a value taken from the raw, unauthenticated payload.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`, `org-a` and `org-b`, each with its own `webhook_secret`.
2. As an attacker with legitimate control over `org-a`'s GitHub App/webhook secret, craft a JSON payload:
```json
{
  "organization": {"login": "org-a"},
  "repository": {"owner": {"login": "org-a"}, "full_name": "org-b/target-repo"},
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
3. Sign the raw body with `org-a`'s `webhook_secret` and send it to `/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"org-a"`, fetches `org-a`'s `GitHubApp`, and the HMAC validates successfully (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `PushHandler#process` resolves the target stacks via `repository.full_name` = `"org-b/target-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and enqueues `GithubSyncJob`/`sync_github` for `org-b`'s stack, an organization whose webhook credentials the attacker never possessed.

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
