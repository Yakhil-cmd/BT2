## Analysis

Based on the code gathered, this is a valid analog to the reported bug class (a payload field acted upon but not covered by the same trust boundary that authenticated the request).

### Title
Webhook signature is verified against an organization selected from an unauthenticated payload field, while the acted-upon repository comes from a different, independently-controlled field in the same payload — Organization-authenticated ≠ Repository-written (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` picks which GitHub App (and therefore which `webhook_secret`) to verify the HMAC signature with, using `repository_owner`, which is read straight out of the untrusted JSON body: `params.dig('repository', 'owner', 'login')` [1](#0-0) . That value is fed into `Shipit.github(organization:)`, which resolves per-organization config (including `webhook_secret`) from `secrets.github` [2](#0-1) , then `GitHubApp#verify_webhook_signature` HMACs the raw body with that org's secret [3](#0-2) .

Once the signature is accepted, the actual event handlers (e.g. `Handler#stacks`, used by `PushHandler`) determine *which repository/stack to act on* using a separate field from the same body: `payload.dig('repository', 'full_name')` [4](#0-3) . Nothing ties these two fields together — the code never checks that the org used to select the verifying secret (`repository.owner.login`) is the same org that owns the repository being written to (`repository.full_name`'s owner segment).

### Finding Description
In a multi-organization Shipit deployment (documented feature, see `docs/setup.md` "Using Multiple Github Applications" [5](#0-4) ), each organization has its own GitHub App and its own distinct `webhook_secret`, held by whoever administers that org's app installation.

The binding that should hold is:
```
organization whose secret authenticated the request == organization that owns the repository the handlers act on
```

Before the pull request/attack: a webhook for `OrgA/repo1` is HMAC-signed with `OrgA`'s secret; `repository.owner.login == "OrgA"` and `repository.full_name == "OrgA/repo1"` agree, and only `OrgA`'s administrators can produce a valid signature for it.

After the attacker's request: someone who legitimately knows `OrgA`'s `webhook_secret` (e.g., an admin of `OrgA`'s own GitHub App installation — an "unprivileged" party with respect to any other org/stack in the same Shipit instance) can construct an arbitrary JSON body where:
- `repository.owner.login = "OrgA"` (used only to pick the verification secret)
- `repository.full_name = "OrgB/victim-repo"` (used by the handlers to pick the `Stack`/`Repository` to act on)

They sign the whole raw body with `OrgA`'s secret. `verify_signature` succeeds because it only checks that the body matches a signature computed with the secret for the org named in the body itself — it never checks that this org matches the repository actually being processed [6](#0-5) . The event handler then resolves `Repository.from_github_repo_name("OrgB/victim-repo")` and acts on `OrgB`'s stacks, e.g. `PushHandler#process` enqueues `stack.sync_github` for any not-archived stack on that repo/branch [7](#0-6) .

### Impact Explanation
This lets an entity that controls only one organization's GitHub App secret forge webhook events attributed to a *different* organization's repositories/stacks that they have no legitimate access to. Depending on which handler is targeted, this can drive `GithubSyncJob` (spoofed push/head SHA causing sync against attacker-chosen "new" commits), status/check-run/check-suite state changes that Shipit uses to gate deploy safety checks, or pull_request lifecycle handlers — i.e., forged state used by Shipit's own deploy-safety and merge-queue logic for a repository the attacker does not control. This is a cross-organization authentication/authorization confusion consistent with "escalation into authorization" / "unauthorized … deploy" style impact categories.

### Likelihood Explanation
Requires the attacker to be an administrator of at least one org that has its own GitHub App configured in the same multi-org Shipit instance (a realistic setup for shared/internal Shipit deployments serving multiple teams/orgs) — this is an "unprivileged" attacker with respect to other orgs' repositories, matching the required threat model. No repository write access, Shipit session, or `ApiClient` token is needed; only knowledge of one's own org's webhook secret, which the attacker legitimately possesses.

### Recommendation
After selecting the GitHub App/secret via `repository_owner` and verifying the signature, re-validate that every organization-scoped field acted upon downstream (e.g., `repository.full_name`'s owner segment, `organization.login` in membership events, etc.) matches the same `repository_owner` used for verification, rejecting the webhook otherwise.

### Proof of Concept
1. Configure two orgs in `secrets.github` (`OrgA`, `OrgB`), each with a distinct `webhook_secret`, as `docs/setup.md` describes for multi-org setups.
2. As an administrator of `OrgA`'s GitHub App (who legitimately knows `OrgA`'s `webhook_secret`), craft a `push` payload:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, raw_body)>`.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and succeeds [8](#0-7) .
5. `PushHandler` resolves stacks via `repository.full_name = "OrgB/victim-repo"` [4](#0-3)  and enqueues `GithubSyncJob` for `OrgB`'s stack, despite the request never being authenticated by anything belonging to `OrgB`.

**Note on completeness:** I was unable to open `app/models/shipit/webhooks/handlers/status_handler.rb`, `check_suite_handler.rb`, `pull_request/closed_handler.rb`, and `app/models/shipit/repository.rb` directly in this final pass (tool call errors), so the full extent of what other handlers do with the mismatched repository field (beyond `PushHandler`, which was confirmed) is not fully enumerated here. The core root cause — verification org vs. acted-upon repository org divergence in `webhooks_controller.rb` and `handler.rb` — is confirmed directly from the code shown above.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
