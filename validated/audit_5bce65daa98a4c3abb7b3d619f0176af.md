### Title
Signature-authenticated organization is not bound to the webhook's `repository.full_name` / `organization.login`, allowing cross-tenant webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification from a field inside the *unauthenticated* JSON body (`repository.owner.login` or `organization.login`), while every event handler resolves the actual write target (stack/repository/team) from a *different* field in the same body (`repository.full_name`, or `organization.login` used independently to tag a `Team`). These two fields are never checked against each other, so the "organization whose secret authenticated the request" and "the repository/organization actually written to" are not the same equality that the signature is supposed to guarantee.

### Finding Description
`verify_signature` computes the authenticating org purely from payload content: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`) and fetches `Shipit.github(organization: repository_owner)`'s `webhook_secret` to validate `X-Hub-Signature` against the raw body via `Shipit::GithubApp#verify_webhook_signature`: [3](#0-2) 

Once the signature check passes (proving only that *some* string matching `repository.owner.login`/`organization.login` has a valid HMAC for that org's configured secret), the request is dispatched to handlers that resolve their real target from a **different** field, `repository.full_name`: [4](#0-3) [5](#0-4) 

`Repository.from_github_repo_name` splits `full_name` on `/` and looks the repo up purely by `owner/name`, independent of `repository.owner.login`: [6](#0-5) 

The equality the signature is supposed to enforce is:
`organization authenticated (repository.owner.login / organization.login, checked against secret) == organization/repository actually written (repository.full_name / organization.login used to create Team)`

This equality is never checked. An attacker who legitimately controls a GitHub organization/app that is configured in Shipit (`config/github.yml`, see the multi-tenant example in `config/secrets.development.shopify.yml`) knows that organization's own `webhook_secret`. They can craft a raw JSON body where `repository.owner.login` (or `organization.login`) is set to *their own* org (so the HMAC computed with their own secret validates), but `repository.full_name` names a stack belonging to a **completely different, unrelated tenant/org** configured on the same Shipit instance.

Because `PushHandler`, and every `PullRequest::*Handler` (`opened_handler.rb`, `closed_handler.rb`, `reopened_handler.rb`, `label_capturing_handler.rb`, `unlabeled_handler.rb`) resolve the stack exclusively via `params.repository.full_name`: [7](#0-6) 

...these actions get executed against the foreign stack even though the signature only proved knowledge of a secret for a different, attacker-controlled org.

The same disjunction exists in `MembershipHandler`, which trusts `params.organization.login` (independent of any repository) to create/attribute a `Team`: [8](#0-7) 

and `Team` membership feeds directly into `User#authorized?`, which is the authorization gate used across the app (`Shipit.github_teams`): [9](#0-8) 

### Impact Explanation
This breaks the "organization authenticated vs. repository/organization written" trust binding explicitly called out as in-scope. Concrete unauthorized actions reachable with only a legitimately-configured-but-unrelated org's own webhook secret (no repository write access, no Shipit session, no admin privileges on the *target* org/repo):
- Forge `push` events (`PushHandler`) to trigger `stack.sync_github` on another tenant's stack — enqueuing sync/deploy pipeline actions against stacks the attacker has no access to.
- Forge `pull_request` `opened`/`closed`/`reopened`/`labeled`/`unlabeled` events to archive/unarchive review stacks or capture attacker-controlled labels on a victim tenant's review stack, manipulating deploy-gating state (`all_status_checks_passed?`, provisioning behavior) for a repository the attacker does not own.
- Forge `membership` events with a crafted `organization.login`/`team` payload to fabricate `Team`/`Membership` records that feed straight into `User#authorized?`, which governs `Shipit.github_teams`-based authorization used throughout the app — a direct escalation path into the app's authorization model.

This matches the High-impact category "escalation into `Shipit.github_teams` authorization" and touches cross-tenant unauthorized stack actions.

### Likelihood Explanation
Requires the attacker to control (own) at least one GitHub organization/app that is configured as a tenant on the target Shipit instance — a realistic scenario for any multi-tenant deployment (the repo's own `config/secrets.development.shopify.yml` documents multiple independent orgs sharing one Shipit instance). No access to the victim org/repo, no Shipit session/API token, and no interception is needed — the attacker only needs their own org's `webhook_secret`, which they legitimately possess by configuring their own GitHub App/webhook. This is a realistic, low-effort exploitation path for any multi-org Shipit deployment.

### Recommendation
In `WebhooksController#verify_signature`, after determining the authenticating organization, enforce that every field used later by handlers to resolve the target repository/organization (`repository.full_name`'s owner segment, `organization.login`) is identical to the organization that owns the verified secret; reject the webhook (422) on mismatch instead of trusting unrelated fields deeper in the pipeline.

### Proof of Concept
1. Configure Shipit with two tenants, `org-attacker` and `org-victim`, each with its own GitHub App and `webhook_secret` (as shown in `config/secrets.development.shopify.yml`).
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "full_name": "org-victim/victim-repo",
    "owner": { "login": "org-attacker" }
  }
}
```
3. Attacker signs the raw body with `org-attacker`'s own `webhook_secret` (`X-Hub-Signature: sha1=<hmac>`), which they legitimately possess.
4. POST to `/webhooks`. `verify_signature` resolves `repository_owner` = `org-attacker`, fetches `org-attacker`'s secret, and the HMAC check passes.
5. `PushHandler#process` resolves the stack via `Repository.from_github_repo_name("org-victim/victim-repo")` [4](#0-3)  and calls `stack.sync_github` on the victim's stack, even though the attacker never proved control of `org-victim`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
