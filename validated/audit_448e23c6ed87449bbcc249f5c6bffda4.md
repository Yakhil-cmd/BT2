### Title
Cross-organization webhook confusion: signature is verified against the organization named in the payload, but the repository that is written is a different payload field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to use for HMAC verification by reading `repository.owner.login` (or `organization.login`) directly out of the untrusted, attacker-suppliable JSON body, and then `Handler#stacks` separately reads `repository.full_name` from the very same body to decide which `Stack`/`Repository` record gets mutated. These are two independent, unauthenticated fields; nothing binds the "organization whose secret produced a valid signature" to the "repository that the handler actually acts on".

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` (line 59-62) is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. `Shipit.github(organization:)` (`lib/shipit.rb:170-181` / `lib/shipit.rb:196-200`) looks up a **per-organization** `webhook_secret` from `secrets.github[organization]`, confirming this app supports multiple independently-configured GitHub organizations sharing one Shipit instance.

Once the signature check passes, `create` dispatches to handlers (e.g. `PushHandler`, `StatusHandler`) via `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`):
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
`repository.full_name` is a *different* JSON field than `repository.owner.login`, and is entirely attacker-controlled within a request whose raw body the attacker composed themselves. Nothing after signature verification re-derives or cross-checks `repository.full_name` against the organization whose secret was used to authenticate the request.

This breaks the intended binding: `organization that authenticated == organization owning the repository being written`. An attacker who knows the `webhook_secret` configured for organization A (e.g. because they administer that org's GitHub App/webhook configuration, which is a legitimately weaker trust boundary than administering Shipit itself) can forge a raw JSON body with `repository.owner.login = "orgA"` (to pick org A's secret and pass `verify_signature`) while setting `repository.full_name = "orgB/some-repo"` for a repository/stack that belongs to a completely different, unrelated organization B also hosted on the same Shipit instance. The HMAC is computed over the full raw body they control, so it will validate correctly with org A's secret even though the payload semantically targets org B's stack.

### Impact Explanation
Depending on which webhook event is forged, this allows an org‑A‑privileged attacker to act on org‑B's stacks without any credential belonging to org B:
- `push` (`PushHandler`) triggers `stack.sync_github(expected_head_sha: ...)` on org B's stacks for an arbitrary branch/SHA, which is used elsewhere to drive automatic/continuous deployment flows.
- `status` (`StatusHandler`) creates a `Commit::Status` with an attacker-chosen `state`/`context` for any commit SHA that matches in the DB, which can be used to satisfy CI-gating checks (`ci.require`) that Shipit consults before allowing a deploy, i.e., forging a "green" CI status to unlock deploys.
- `membership` handler (`app/controllers/shipit/webhooks_controller.rb`, dispatched via `Shipit::Webhooks.for_event`) creates/removes `Team`/`Membership` records scoped by whatever organization/team name is embedded in the payload, independent of the signing organization.

This is a cross-repository/cross-organization write triggered purely by possession of one organization's webhook secret, matching the "Critical: cross-repository writes / unauthorized deploy" impact bar, since forged CI status combined with push/sync manipulation can be chained toward an unauthorized deploy on a stack the attacker has no legitimate access to.

### Likelihood Explanation
Requires: (a) the Shipit instance is configured with multiple GitHub organizations (`Shipit.github_organizations` supports this natively), and (b) the attacker knows the `webhook_secret` for at least one of those organizations — realistic for an org that legitimately owns/administers its own GitHub App/webhook integration into a shared Shipit instance, without needing any Shipit credential, `ApiClient` token, or GitHub App private key. No repository write access to the *victim* org is needed. This is a design gap rather than a rare edge case, so likelihood is Medium-High in any multi-organization Shipit deployment.

### Recommendation
After signature verification, re-derive `repository_owner`/organization strictly from the same trusted context used for verification, and validate that the repository/stack being acted upon in each handler actually belongs to that same verified organization (e.g., compare `Repository#owner` against `repository_owner` before invoking `Repository.from_github_repo_name`/stack lookups, and reject events where they diverge). Do not allow independent, unauthenticated fields in the same payload to separately choose "whose secret authenticates" and "which repository is mutated."

### Proof of Concept
1. Configure Shipit (illustrative) with two orgs in `secrets.github`: `orgA: { webhook_secret: "secretA" }`, `orgB: { webhook_secret: "secretB" }`, each with stacks for their own repos.
2. Attacker knows `secretA` (e.g., they configured org A's own webhook integration).
3. Attacker crafts a raw JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(secretA, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner == "orgA"`, fetches `Shipit.github(organization: "orgA")`, and validates the signature successfully against `secretA`.
6. `PushHandler#process` is invoked; `Handler#repository_name` reads `payload.dig('repository','full_name') == "orgB/victim-repo"`, resolving stacks that belong to org B, and calls `stack.sync_github(expected_head_sha: ...)` on them — an action the attacker was never authorized to trigger for org B. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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
