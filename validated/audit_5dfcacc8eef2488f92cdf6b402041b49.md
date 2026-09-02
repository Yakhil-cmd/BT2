Confirmed: `Handlers::Handler#stacks` resolves the target repository from `payload.dig('repository', 'full_name')` [1](#0-0) , which is a **different payload field** than the one used to select the HMAC verification key, `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) .

### Title
Cross-tenant webhook forgery via organization/repository field mismatch in signature verification - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a delivery against using `repository_owner`, which is read directly from the *unauthenticated* JSON body (`repository.owner.login` or `organization.login`) [3](#0-2) . Every event handler, however, determines which `Stack`/`Repository` to actually mutate using a *different* field of the same body: `payload.dig('repository', 'full_name')` [4](#0-3) . Because the field that selects the cryptographic key and the field that selects the acted-upon repository are independent and both attacker-controlled prior to verification, a party that legitimately controls one configured GitHub organization/app (and therefore knows its own `webhook_secret`) can sign a payload with `repository.owner.login`/`organization.login` set to their own org, while setting `repository.full_name` to an arbitrary victim repository belonging to a different configured organization. The signature check passes (`Shipit.github(organization: 'their-own-org').verify_webhook_signature` succeeds because they hold that org's secret), but the handler (`PushHandler`, `StatusHandler`, `MembershipHandler`, `PullRequest::*Handler`, etc.) operates on whatever `repository.full_name`/`organization.login`/team data is in the (attacker-crafted) body, unconstrained to that organization.

### Finding Description
The binding that should hold is: **organization that authenticated == repository/organization that is written**. Instead:
- Key selection binding: `Shipit.github(organization: repository_owner)` where `repository_owner = payload.dig('repository','owner','login') || payload.dig('organization','login')` [5](#0-4) .
- Action binding: `Repository.from_github_repo_name(payload.dig('repository','full_name'))` for repo-scoped events [1](#0-0) , or `params.organization.login` for `membership` events, used to set `team.organization` [6](#0-5) .

`verify_webhook_signature` only checks the HMAC of the raw body against the secret for whichever organization was named in the body; if that named organization is valid and its secret matches, verification succeeds regardless of what other fields (like `repository.full_name`) claim [7](#0-6) . Nothing ties the verified organization to the object the handler subsequently writes to.

Additionally, if any configured organization has no `webhook_secret` set, `verify_webhook_signature` unconditionally returns `true` for any payload claiming to be from that organization (`return true unless webhook_secret`) [8](#0-7) , which removes the authentication barrier entirely for such a claimed org while the handler still acts on the (unrelated) `repository.full_name`.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary called out explicitly in scope. A tenant of a multi-org Shipit deployment (or anyone who knows one configured org's `webhook_secret`, or who can name an org with no secret configured) can forge `push`, `status`, `check_suite`, `pull_request`, or `membership` events for a completely different organization's stacks/repositories/teams without ever holding that victim organization's webhook secret. This can trigger unintended `GithubSyncJob` runs, fabricated commit statuses influencing merge/deploy gating, forged team membership changes (`MembershipHandler` grants/revokes `Shipit.github_teams` membership using `Shipit::Authentication#current_user.authorized?`), or spurious pull-request/review-stack provisioning — i.e., escalation into `Shipit.github_teams` authorization and unauthorized influence over deploy-gating state for a stack the attacker does not own.

### Likelihood Explanation
Exploitability depends on the attacker legitimately controlling at least one organization configured in the same Shipit instance (multi-tenant deployments configuring several orgs under `Shipit.github` are explicitly supported, per `config/secrets.development.example.yml`) [9](#0-8) , or discovering an org configured with a blank `webhook_secret`. `WebhooksController` requires no session, API token, or repository write access — only knowledge of one org's own webhook secret (something a normal, unprivileged tenant already legitimately possesses), matching the "unprivileged-attacker" requirement.

### Recommendation
After resolving `repository_owner` for key selection, re-derive and cross-check the organization implied by `repository.full_name` (and any other acted-upon identifiers such as `organization.login` for membership events) and reject the webhook if they do not match the organization whose secret validated the signature. Do not treat a missing `webhook_secret` for a configured organization as an implicit "always verified" case; require explicit opt-in for unauthenticated webhooks per organization, scoped only to that organization's own repositories.

### Proof of Concept
1. Multi-org Shipit instance configures two GitHub Apps: `org-attacker` (installed by the attacker's own GitHub organization, so the attacker knows its `webhook_secret`) and `org-victim` (a separate tenant with its own stacks).
2. Attacker builds a `push` event JSON body: `{"repository": {"owner": {"login": "org-attacker"}, "full_name": "org-victim/victim-repo"}, "ref": "refs/heads/main", "after": "<attacker-chosen sha>"}`.
3. Attacker computes `X-Hub-Signature: sha1=HMAC(org-attacker's webhook_secret, raw_body)` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` computes `repository_owner = "org-attacker"`, loads `Shipit.github(organization: "org-attacker")`, and the signature verifies successfully because the attacker used the correct secret for `org-attacker` [3](#0-2) .
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-victim/victim-repo")` [1](#0-0) , `app/models/shipit/webhooks/handlers/push_handler.rb" start="12" end="17" />, and enqueues a `GithubSyncJob` against `org-victim`'s stack with an attacker-chosen `expected_head_sha`, even though the attacker never possessed `org-victim`'s webhook secret or any Shipit session/token for that org.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
