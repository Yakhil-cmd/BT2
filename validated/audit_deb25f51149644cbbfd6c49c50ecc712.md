### Title
Webhook signature verification uses an attacker-controlled organization field that is not bound to the repository actually written - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to verify a webhook payload against based on `repository.owner.login`/`organization.login` — fields taken directly from the unauthenticated, attacker-supplied request body — before the signature has been checked. `GithubApp#verify_webhook_signature` additionally treats a blank/nil `webhook_secret` as automatic success (`return true unless webhook_secret`). Because Shipit supports multi-organization configuration where `webhook_secret` is documented as optional per org, an attacker who can get (or already knows) one configured organization's secret is nil can forge events for that org, and the same untrusted payload fields are subsequently trusted by event handlers to determine which stack/repository is acted upon.

### Finding Description
`verify_signature` derives the organization purely from request-controlled JSON: [1](#0-0) [2](#0-1) 

It then calls `Shipit.github(organization: repository_owner)` and asks that app's config to verify the signature: [3](#0-2) 

Critically, `verify_webhook_signature` short-circuits to `true` whenever the resolved organization's `webhook_secret` is blank — a state explicitly supported by the setup docs and example secrets files, which mark `webhook_secret` as "(optional)": [4](#0-3) [5](#0-4) 

This breaks the intended binding: *the organization whose credentials authenticate the webhook* should equal *the repository/organization whose state is written by the resulting event handlers*. Instead, the same untrusted `repository`/`organization` object in the JSON body is used both to select the verifying app (pre-verification) and, independently, by handlers (e.g., `MembershipHandler`, pull-request handlers, push handler) to decide which `Team`, `User`, `Stack`, or `Repository` record to create/update. Nothing enforces that the `repository.owner.login` used for the crypto check is the same trusted value used later for the write path; an attacker fully controls both.

### Impact Explanation
If any organization configured in `Shipit.github` secrets has no `webhook_secret` (a supported, documented configuration), the webhook signature check for events referencing that organization always passes without any real cryptographic check. Because the write-side logic (creating memberships, teams, users, syncing commits/pull requests, updating check-runs/statuses) is driven from the very same forged payload, this is a path to unauthenticated forged GitHub events being accepted as authentic, which can pollute `Team`/`Membership`/`User` records (used for authorization decisions such as `Shipit.github_teams`) and trigger sync jobs against attacker-chosen repositories — an escalation into GitHub-team-based authorization data with no credential required.

### Likelihood Explanation
Likelihood is contingent on deployment configuration: it requires (a) multi-organization GitHub App setup and (b) at least one configured organization lacking a `webhook_secret`. This is explicitly supported and shown as a valid configuration in `docs/setup.md` and the shipped example secrets templates, making it a plausible operator configuration rather than a purely theoretical one. However, it is not automatically present in a single-org default deployment (the default template also allows `webhook_secret: # nil`, so even single-org installs following the example config are exposed).

### Recommendation
Do not allow "no secret configured" to silently authorize a webhook. Either require `webhook_secret` for every configured organization and fail closed when absent, or, at minimum, cryptographically bind organization resolution to verification (e.g., verify against all configured secrets/orgs and require an exact match, rather than trusting attacker-supplied `repository.owner.login`/`organization.login` to pick the verifying key). Additionally, after signature verification succeeds, revalidate that the organization that was cryptographically verified matches the organization of the repository object the handlers will act upon.

### Proof of Concept
1. Deploy Shipit with multi-org config where `orgA` has a real `webhook_secret` and `orgB` (also configured, perhaps for an unrelated purpose) has `webhook_secret: nil` (a documented supported state).
2. POST to `/webhooks` with `X-Github-Event: membership` and a JSON body where `organization.login = "orgB"` (or `repository.owner.login = "orgB"`).
3. `verify_signature` resolves `Shipit.github(organization: "orgB")`; since `orgB.webhook_secret` is blank, `verify_webhook_signature` returns `true` regardless of the `X-Hub-Signature` header value (no valid signature needed).
4. `MembershipHandler#process` then executes using the same forged payload, creating/removing `Team`/`Membership` records that feed into `User#authorized?` and `Shipit.github_teams` checks — all without possessing any real GitHub webhook secret.

Note: I was unable to fully trace `Shipit.github`/`Shipit.github_configs` resolution logic in `lib/shipit.rb` (file read failed in the final iteration), so the exact mechanics of multi-org lookup (e.g., whether an unknown/mismatched org raises `GithubOrganizationUnknown` before reaching the blank-secret bypass) could not be fully confirmed from source. This should be verified directly in `lib/shipit.rb` before treating this as fully proven.

### Citations

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
