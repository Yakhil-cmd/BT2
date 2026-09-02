### Title
Webhook signature verification keys on `repository.owner.login`, but the org-write is bound to `organization.login` / `repository.full_name` from the same attacker-controlled body - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the HMAC signature using a field read out of the still-unverified JSON body (`repository.owner.login`, falling back to `organization.login`), while the handlers that actually mutate state (`Team`, `Membership`, `Stack`, `Commit::Status`) trust *other* fields in that same body (`organization.login`, `repository.full_name`, `sha`) to decide **which** GitHub org/repository/commit to write to. Because the signing key and the write target are derived from two independently attacker-suppliable fields inside one HMAC-signed-by-the-attacker-themselves payload, an attacker who owns *any* org onboarded to this Shipit instance (i.e. knows that org's `webhook_secret`) can forge a webhook whose signature validates against their own org but whose write-target fields point at a victim org/team/stack.

### Finding Description
`verify_signature` computes the signing organization purely from body content, before the signature is checked: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

The HMAC itself only proves "whoever crafted this body knows the secret for the org named by `repository_owner`." It proves nothing about the other fields inside the same body. Yet handlers use different fields to select what gets written:

- `MembershipHandler` trusts `organization.login` to bind a github Team (and thus `Shipit.github_teams` authorization membership) — for the `membership` event, `repository_owner` also falls back to `organization.login` (same field), so this path is self-consistent for `membership` events specifically: [3](#0-2) 

- `Handler#stacks`/`#repository_name` (used by `PushHandler`, `CheckSuiteHandler`, `StatusHandler` transitively via `Commit.where(sha:)`) key exclusively off `repository.full_name`, a **different** field than `repository.owner.login` used for signature selection: [4](#0-3) [5](#0-4) 

`repository.owner.login` and `repository.full_name`'s owner segment are normally the same value when GitHub itself produces the payload, but the signature never actually ties them together — it is computed over the raw bytes using a secret chosen by `repository.owner.login`. An attacker who administers **their own** org/repo (`attacker-org/attacker-repo`) with the Shipit GitHub App installed knows `attacker-org`'s `webhook_secret`. They can POST directly to `/webhooks` (no session, no `ApiClient` token required — this endpoint is unauthenticated by design) with:
- `repository.owner.login = "attacker-org"` (or `organization.login = "attacker-org"`) → selects the app/secret they know, so `verify_webhook_signature` passes,
- `repository.full_name = "victim-org/victim-repo"` and arbitrary `ref`/`after`/`sha` → is what `PushHandler`, `CheckSuiteHandler`, and `StatusHandler` actually act on.

This breaks the binding "organization that authenticated == repository that is written," exactly the analog class called out in scope: quote-price staleness (`_isBadData`) computed for one input is silently discarded/overridden by an unrelated later check (base price), just as here the org-identity check used for authentication is decoupled from the org/repo identity used for the write.

### Impact Explanation
Concretely reachable, unprivileged-attacker impacts:
- Forged `push` events can invoke `Stack#sync_github(expected_head_sha:)` against a victim stack the attacker does not own, feeding an attacker-chosen `expected_head_sha`.
- Forged `status` events can inject arbitrary CI status (`state`, `description`, `target_url`, `context`) onto **any** commit by `sha` regardless of which repo it belongs to, since `StatusHandler` matches purely on `Commit.where(sha: params.sha)` with no repository/stack scoping at all — this can flip a commit to "deployable" state and enable an unauthorized deploy.
- Forged `check_suite` events can trigger `schedule_refresh_check_runs!` against arbitrary stacks/branches of a victim repo.

Falsifying commit deployability status (`status` event) is the most severe: it can be used to make an otherwise-failing/unreviewed commit appear CI-green, enabling an unauthorized deploy on a victim stack — matching the "unauthorized deploy" impact bucket in scope. This aligns with High/Critical severity per the rules ("unauthorized deploy" is explicitly Critical-tier).

### Likelihood Explanation
Requires the attacker to control at least one org/repo that is legitimately onboarded to the same Shipit instance (multi-tenant github config) and know that org's own `webhook_secret` — plausible in any Shipit deployment serving multiple orgs/teams, and the `/webhooks` endpoint is unauthenticated and internet-reachable by design (it is meant to receive GitHub's callbacks), so no session, `ApiClient` token, or repository write access on the victim side is needed. Likelihood is Low-to-Medium: it needs the instance to actually host multiple orgs and the attacker to hold legitimate admin rights over one of them, but no interaction with the victim is required beyond a single crafted HTTP POST.

### Recommendation
Bind the signature-verification identity to the same identity used for the write:
- After verifying the signature, re-derive `repository_owner`/`organization` used for handler dispatch strictly from the *same* field that selected the signing secret, and reject the request (422) if `repository.full_name`'s owner segment (or `organization.login`) does not match `repository_owner` used in `verify_signature`.
- In `StatusHandler`, scope `Commit.where(sha:)` lookups to commits belonging to `stacks`/`repository_name` derived from the verified organization, instead of a global, repository-unscoped `sha` match.
- Consider verifying signatures per-repository record (loaded from the DB by `repository.full_name`) rather than trusting an org name pulled straight from the unverified body.

### Proof of Concept
1. Attacker legitimately owns `attacker-org` with the Shipit GitHub App installed; they know `attacker-org`'s configured `webhook_secret` (their own app credential, not a Shipit secret).
2. Attacker crafts a `status` event body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/attacker-forced",
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/dummy"}
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker_webhook_secret, body)>` themselves.
4. POST to `/webhooks` with `X-Github-Event: status`. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and the signature validates.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` — because this lookup is repository-unscoped, it matches and updates the victim's commit status regardless of the `attacker-org` binding used for authentication, potentially marking a victim commit "deployable" for an unauthorized deploy. [6](#0-5) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
