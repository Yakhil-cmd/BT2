### Title
Webhook organization used for signature verification is decoupled from the repository/organization the event handlers actually act on - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a field read directly out of the **unverified** JSON body. The event handlers that subsequently execute (`PushHandler`, `MembershipHandler`, etc.) resolve the repository/organization they act on from a **different, independently-controlled field** in the same unverified body (`repository.full_name`). Because these two fields are never checked against each other, and because `verify_webhook_signature` unconditionally passes when the selected organization has no `webhook_secret` configured, an attacker can pick any organization/login present in Shipit's config that lacks a secret to satisfy verification, while pointing the actual event payload at a stack belonging to an entirely different (secured) organization.

### Finding Description
`repository_owner` is derived straight from the raw JSON body before any signature check occurs: [1](#0-0) 

It is used only to pick which `Shipit.github(organization:)` config/secret to verify the signature against: [2](#0-1) 

`verify_webhook_signature` returns `true` with no signature check at all if that specific organization has no `webhook_secret` configured: [3](#0-2) 

Shipit explicitly supports multiple GitHub organizations sharing the same `/webhooks` endpoint, each with its own (optional) `webhook_secret`: [4](#0-3) 
The setup docs confirm the webhook secret is optional: "Webhook secret (optional): Fill it with some randomly generated string" [5](#0-4) 

Once the request clears (or bypasses) that org-scoped check, the actual event handler resolves the repository/stack to operate on from a **separate** JSON field, `repository.full_name`, with no cross-check against `repository_owner`: [6](#0-5) 

For example `PushHandler` uses that repository's stacks and triggers a GitHub sync with an attacker-chosen `after` SHA: [7](#0-6) 

`MembershipHandler` (also gated by the same `verify_signature` before_action) creates/removes `Team`/`User`/`Membership` records purely from body data, which feeds directly into `Shipit::Authentication#force_github_authentication`'s `current_user.authorized?` team-membership gate: [8](#0-7) 

**The broken binding**, expressed as an equality that should hold but doesn't:
`organization used to select/verify the webhook signature == organization/repository the dispatched handler operates on`

Before the fix analog: these two values are read from two independent, both-attacker-controlled JSON paths (`repository.owner.login` vs `repository.full_name`) within a single unsigned or weakly-verified request, and are never compared to each other.

### Impact Explanation
If Shipit is configured for more than one GitHub organization (a supported, documented configuration) and even one of those organizations has no `webhook_secret` set (explicitly "optional" per the setup docs), an unauthenticated network attacker can:
1. Send a POST to `/webhooks` with `X-Github-Event: membership` (or `push`, `status`, `check_suite`, `pull_request`) and `repository.owner.login` / `organization.login` set to the secret-less org — `verify_webhook_signature` returns `true` unconditionally.
2. Set `repository.full_name`, `member.login`, `team`, `ref`/`after`, etc. inside the same payload to target any stack/repository Shipit tracks, regardless of which org it belongs to.

This can be used to fabricate `membership` events that add an attacker-controlled GitHub login to a `Team`, directly escalating into `Shipit.github_teams` authorization used by `force_github_authentication` to grant access to the whole application — a High-impact escalation. It can also drive `push`/`status`/`check_suite` handlers to force spurious `sync_github`/`RefreshCheckRunsJob` operations against stacks under organizations that do have secrets configured, since the acted-upon repository is never validated against the org used for verification.

### Likelihood Explanation
Requires only network access to the public `/webhooks` endpoint (no session, no `ApiClient` token, no GitHub credentials) and a deployment that configures more than one GitHub organization where at least one lacks a `webhook_secret` — a state the project's own documentation presents as valid/optional ("Webhook secret (optional)"). No social engineering, TLS interception, or privileged access is needed.

### Recommendation
- Require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`).
- After signature verification succeeds for a given `repository_owner`, re-validate that `repository.full_name`'s owner segment matches the same `repository_owner`/organization used to select the verifying secret before dispatching to handlers, rather than trusting `repository.full_name` independently in `Handler#repository_name`.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`: `secured-org` (has `webhook_secret`) and `open-org` (no `webhook_secret`, per documented "optional" support).
2. POST to `/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": {"id": 1, "name": "Admins", "slug": "admins"},
  "organization": {"login": "open-org"},
  "member": {"login": "attacker-github-login"}
}
```
No valid `X-Hub-Signature` is required because `Shipit.github(organization: 'open-org')` has no `webhook_secret`, so `verify_webhook_signature` returns `true` at `lib/shipit/github_app.rb:76-78`. `MembershipHandler` processes the event, and `attacker-github-login` is granted membership in the `Admins` team, which — if `Admins` is later added to `Shipit.github_teams` — grants that login access to the whole Shipit application through `Authentication#force_github_authentication`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
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

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
