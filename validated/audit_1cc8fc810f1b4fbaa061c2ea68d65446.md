### Title
Cross-organization webhook forgery via signature verified against `repository.owner.login` while handlers act on `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature against using `repository.owner.login` taken from the *unverified* JSON body, while every webhook `Handler` resolves the target `Stack`/`Repository` to mutate using a different field from the same unverified body — `repository.full_name`. Because the signature only proves "this body was signed by the app installed for the org named in `repository.owner.login`," but never binds that org to the repository the handlers actually act on, an attacker who legitimately controls a GitHub App/organization configured in Shipit's multi-org config can forge events attributed to a completely different, victim organization's repository.

### Finding Description
`Shipit` supports hosting multiple GitHub organizations in one instance, each with its own `webhook_secret`, keyed by organization name (`lib/shipit.rb` `github_app_config`, `TOP_LEVEL_GH_KEYS`, and the documented multi-org config in `docs/setup.md`). [1](#0-0) 

Signature verification in the webhook controller picks the app/secret to check with using a field read straight from the untrusted request body, *before* any cryptographic verification has occurred: [2](#0-1) [3](#0-2) 

`repository_owner` is derived from `params.dig('repository', 'owner', 'login')`. The HMAC is computed with `GitHubApp#verify_webhook_signature`, which trusts whichever `webhook_secret` is configured for that org name: [4](#0-3) 

Once the signature check passes, `WebhooksController#create` dispatches the raw parsed payload to every registered `Handler` for the event: [5](#0-4) 

Every handler, however, resolves *which* stacks to mutate using a **different** field of the same payload — `repository.full_name`, not `repository.owner.login`: [6](#0-5) [7](#0-6) 

Nothing ties `repository.owner.login` to `repository.full_name`'s owner segment. An attacker who legitimately operates a GitHub App/organization that Shipit is configured to trust (e.g., they set up "OrgA" per the documented multi-org onboarding flow and thus know OrgA's own `webhook_secret`) can craft a POST to `/webhooks` where:
- `repository.owner.login = "OrgA"` (so `verify_signature` selects OrgA's `GitHubApp`, whose secret the attacker knows and can sign with),
- `repository.full_name = "VictimOrg/victim-repo"` (so `PushHandler`/`StatusHandler`/etc. resolve and mutate the victim's `Stack`).

The signature will validate successfully (it's a legitimately-signed OrgA payload), yet the handler acts on the victim organization's repository — exactly the "organization that authenticated versus the repository that is written" binding break called out by the report's underlying bug class (a field acted upon that was never covered by the thing that was verified).

This is structurally identical to the Swivel bug: the code *comments/intent* (and the implicit trust model) assume the org that signed the webhook is the org whose repository is being acted on, but the actual code paths use two independently-controlled fields from the same unverified JSON blob for these two purposes.

### Impact Explanation
Handlers triggered this way perform state-changing, unauthenticated-from-GitHub's-perspective actions on arbitrary Stacks that Shipit tracks, e.g.:
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for any branch/SHA the attacker specifies on a victim's stack, forcing Shipit to sync to an attacker-chosen commit. [8](#0-7) 
- `StatusHandler`/`CheckSuiteHandler`/`membership` handlers similarly act on data keyed off `repository.full_name` while trust was established against `repository.owner.login`, letting an attacker forge commit statuses or check-run refreshes for a victim repository, which can influence whether a commit is deployable/mergeable through Shipit's merge queue — an unauthorized-deploy-adjacent primitive.

This crosses the "cross-repository writes" / "unauthorized deploy" severity bar since a party with no privileges on the victim organization or repository can inject state (synced SHAs, statuses) into that victim's Shipit-tracked stack.

### Likelihood Explanation
Requires: (1) the target Shipit instance configured for multiple GitHub organizations (a documented, supported configuration in `docs/setup.md`), and (2) the attacker legitimately controlling at least one of those configured orgs/apps and thus knowing its own `webhook_secret`. Given multi-tenant/multi-org Shipit deployments exist precisely to host several organizations (potentially with different trust levels, e.g. internal teams each owning their own GitHub App), an attacker in one tenant forging events for another tenant is a realistic insider/cross-tenant threat, not requiring compromise of the victim's credentials.

### Recommendation
Bind the field used to select the verifying `webhook_secret` to the same field used to resolve the target repository/stack. Concretely:
- In `WebhooksController#verify_signature` and `Handler#repository_name`, derive both the "authenticating organization" and "written repository" from the **same** value (e.g., always use `repository.full_name`'s owner segment, or verify that `repository.owner.login` case-insensitively matches the owner segment of `repository.full_name` before dispatching to handlers).
- Reject/`head(422)` any payload where these two derived values disagree.

### Proof of Concept
1. Shipit configured with multi-org github config containing `OrgA` (attacker-controlled, secret known to attacker) and `VictimOrg` (has a Stack tracking `VictimOrg/victim-repo`), per `docs/setup.md` "Using Multiple Github Applications".
2. Attacker builds a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "VictimOrg/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` using OrgA's known `webhook_secret` over the raw body.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")` → validates successfully against the attacker-known secret (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit/github_app.rb:76-83`).
6. `PushHandler#process` resolves `Repository.from_github_repo_name("VictimOrg/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/repository.rb:53-56`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack — an org the attacker never authenticated against.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
