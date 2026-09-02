### Title
Cross-Organization Webhook Forgery via Signature/Target Mismatch in Multi-GitHub-App Configuration - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and its `webhook_secret`) used to validate an incoming webhook's HMAC signature based on `repository.owner.login` (or `organization.login`) taken directly from the *unverified* JSON body. The webhook handlers, however, resolve the target `Repository`/`Stack` to act on using a *different* field from the same unverified body — `repository.full_name` (via `Handler#repository_name`). Because Shipit explicitly supports configuring one GitHub App per organization (`docs/setup.md`, `config/secrets.development.shopify.yml`, `test/dummy/config/secrets_double_github_app.yml`), an attacker who legitimately controls the GitHub App/webhook secret for one configured organization can craft a payload whose `repository.owner.login` names their own org (so it authenticates against their known secret) while `repository.full_name` names a repository belonging to a different configured organization, causing Shipit to act on that other organization's stacks.

### Finding Description
`Shipit.github(organization:)` picks the `GitHubApp` (and thus the `webhook_secret` used for HMAC verification) per organization, keyed off whatever string is passed in [1](#0-0) . `WebhooksController#verify_signature` derives that organization solely from the incoming, not-yet-verified request body: [2](#0-1) [3](#0-2) 

Signature verification itself is HMAC-SHA1 over the raw body using that organization's secret [4](#0-3) . The signature only proves the payload was signed by *some* configured organization's secret — it says nothing about which repository the payload's contents describe.

Once verification passes, `Shipit::Webhooks.for_event(event)` dispatches to handlers, and every handler resolves the affected `Repository`/`Stack`/`Commit` set using `repository.full_name` from the same JSON body, completely independent of the `repository.owner.login` that was used for signature selection: [5](#0-4) [6](#0-5) 

Nothing checks that `full_name`'s owner segment equals `repository.owner.login`/`organization.login`. In a single-GitHub-App deployment this is harmless (there is only one secret/org). But Shipit explicitly supports multi-organization deployments where each organization has its own GitHub App and its own `webhook_secret`, configured independently and potentially by different, mutually-untrusted teams (per `docs/setup.md` "Using Multiple Github Applications" and the `secrets_double_github_app.yml` fixture) [7](#0-6) . In that topology, anyone who controls the GitHub App settings for "OrgTwo" (and thus knows OrgTwo's `webhook_secret`) can HMAC-sign an arbitrary JSON body themselves and send it to Shipit's shared `/webhooks` endpoint, setting `repository.owner.login`/`organization.login` to `"OrgTwo"` (to pass signature verification) while setting `repository.full_name` to `"OrgOne/some-repo"` so the handler acts on OrgOne's stacks.

This breaks the intended trust binding "the organization whose credential authenticated the webhook == the repository being written to" — exactly the class of binding highlighted by the source report (a value used for one gatekeeping purpose, e.g. `setVenusInfo`'s address, diverges from the value later trusted for the operative effect).

### Impact Explanation
Depending on the handler exploited, this allows an attacker with legitimate control over one configured organization's GitHub App to forge events against a completely different organization's Stacks:
- `push` → triggers `stack.sync_github(expected_head_sha:)` on arbitrary stacks belonging to another org, causing GithubSyncJob to run and potentially advance/alter deploy state.
- `status`/`check_suite` → forges commit statuses/check runs for commits belonging to another org's repository, which can be used to satisfy `ci.require` conditions and cause an **unauthorized deploy** on continuous-deployment-enabled stacks in the victim organization.
- `membership` → creates/edits `Team`/`Membership` records scoped by `organization.login`, independent of full_name, but similarly relies on unverified fields.

Given continuous deployment/merge-queue configurations rely on commit statuses and check runs to gate deploys/merges, forging these across organization boundaries can result in an unauthorized deploy or merge in a repository the attacker does not otherwise have write access to — meeting the "Critical: unauthorized deploy/merge" bar.

### Likelihood Explanation
This requires a Shipit instance configured with multiple GitHub Apps for multiple organizations (an explicitly documented and supported configuration), and requires the attacker to control (or have created) the GitHub App for at least one of those organizations, which they can do without any Shipit credentials — GitHub Apps are typically self-service per org. Given the webhook endpoint is unauthenticated other than the per-org HMAC check, and the dispatch logic never cross-checks the signing organization against the resolved repository, exploitation only requires crafting one HTTP request with a valid signature for the attacker's own org.

### Recommendation
In `WebhooksController#verify_signature`/`#create`, after verifying the signature for the organization derived from the request, re-derive the organization from `repository.full_name` (the field actually used by handlers) and require it to match the organization used to select the `webhook_secret`. Reject the webhook if they differ. Alternatively, make every handler resolve the repository through the same trusted "authenticated organization" value rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgOne` and `OrgTwo`, each with its own GitHub App/`webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an attacker who owns/administers the GitHub App for `OrgTwo` (and thus knows `OrgTwo`'s `webhook_secret`), craft a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "OrgOne/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgTwo_webhook_secret, raw_body)>`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgTwo")` and successfully verifies the signature against the attacker-known secret.
6. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgOne/victim-repo")` and triggers `sync_github` on OrgOne's stack — despite the attacker having no legitimate relationship to `OrgOne`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
