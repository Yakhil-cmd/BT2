### Title
Cross-organization webhook status forgery bypasses CI gating and enables unauthorized deploys - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates an inbound webhook only against the GitHub App secret belonging to the organization named in the payload's `repository.owner.login` (or `organization.login`) field [1](#0-0) , resolved via `Shipit.github(organization: repository_owner)` and `github_app_config(organization)` which look up a per-organization secret keyed purely by that string [2](#0-1) . Once the signature check passes, the entire parsed JSON body — including any other field the attacker chose to include — is handed unmodified to the registered handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) . Critically, `StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` with no scoping to the organization/repository that was authenticated [4](#0-3) .

### Finding Description
The equality that should hold is: **the organization whose secret authenticated the webhook == the organization/repository whose state is mutated by the handler.** This binding is broken:

1. `verify_signature` derives `repository_owner` from `params.dig('repository','owner','login')` or `params.dig('organization','login')` — fields fully controlled by the HTTP body the caller supplies [5](#0-4) . It uses that value purely to pick *which secret* to check the HMAC against; it never re-validates that other identifying fields in the same body (e.g. `sha`, `repository.full_name`) actually belong to that organization.
2. `Shipit.github(organization:)` maintains one `GitHubApp`/secret per configured organization [2](#0-1) ; this is the documented multi-tenant configuration (`config/secrets.development.example.yml`, commented-out multi-org block).
3. Any party who legitimately owns/administers **one** organization tracked by this Shipit instance (and therefore knows/controls that organization's webhook secret, e.g. because they configured the GitHub App themselves, or received it) can compute a valid HMAC over an arbitrary JSON body, as long as `repository.owner.login` (or `organization.login`) in that body matches their own organization.
4. Nothing stops the attacker from also stuffing the body with a `sha` value that belongs to a commit in a **completely different, victim** stack/organization tracked by the same Shipit install. `StatusHandler` performs `Commit.where(sha: params.sha)`, a **global, unscoped** query across every repository's commits [4](#0-3) , then calls `commit.create_status_from_github!(params)` for every matching commit, letting the attacker set an arbitrary `state`/`context`/`description` on that foreign commit.
5. Status state directly gates deploy safety: `Commit#deployable?` requires `success? && !blocked?` [6](#0-5) , and `blocking?`/`required?` are matched purely by `context` string against the victim stack's configured `blocking_statuses`/`required_statuses` [7](#0-6) . An attacker who knows (or guesses/enumerates via the public deploy UI) the victim stack's required CI `context` name can forge a `success` status for that context on the victim's pending commit, satisfying `deployable?` and unblocking continuous deployment (`stack.schedule_merges` is even triggered on success transitions in `Commit#add_status`) [8](#0-7) .

This is the direct analog of the reported `executeModule` issue: a caller-controlled field (which organization "authenticated" the request) is decoupled from the caller-controlled data actually acted upon (which repository/commit is written), and the signature only covers "was this bytes-for-bytes body signed by *some* known secret", not "does this body's target belong to the signing tenant."

The same unscoped pattern also affects `MembershipHandler`, which trusts `params.organization.login` to attach team membership without verifying it matches the signing organization's identity beyond the same string reused for HMAC selection [9](#0-8) , though the status-forgery path has the clearer, higher-impact consequence (deploy bypass).

### Impact Explanation
This crosses the "escalation into `Shipit.github_teams` authorization... unauthorized deploy" bar explicitly listed as High/Critical impact. An attacker who is an authorized administrator of *any* one organization configured in a multi-tenant Shipit instance can forge CI status/commit-status events for *any other* organization's tracked repositories, bypassing that victim's CI gating and triggering an unauthorized deploy/merge — without ever needing write access to the victim's GitHub repository, an `ApiClient` token, or the victim's webhook secret.

### Likelihood Explanation
Requires only: (a) the Shipit instance be configured for multiple GitHub organizations (a documented, supported configuration), (b) the attacker control/administer one of those configured organizations (able to receive/derive its webhook secret), and (c) knowledge of a target commit `sha` and the victim stack's CI `context` name (both are commonly visible on the public Shipit deploy page / GitHub UI for the target stack). No privileged Shipit session or GitHub write access on the victim repo is needed, matching the reachable, unprivileged-attacker profile required by the rules.

### Recommendation
`WebhooksController`/`Handler` should re-derive the acted-upon repository/stack strictly from the same organization value that was cryptographically verified, and every handler (especially `StatusHandler`, `MembershipHandler`, `CheckSuiteHandler`) should scope its DB lookups (`Commit.where(sha: ...)`, team creation, etc.) to stacks/repositories belonging to the verified organization, rejecting the payload (422) if the `repository.full_name`'s owner does not match the organization whose secret validated the signature.

### Proof of Concept
Given a Shipit instance configured with two organizations, `attacker-org` (attacker legitimately controls this GitHub App/webhook secret) and `victim-org` (tracks a stack the attacker wants to force-deploy):

1. Attacker finds a pending commit `sha` in `victim-org/victim-repo` awaiting a CI context `ci/tests` (visible on the public Shipit stack page).
2. Attacker crafts a JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" } },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/tests"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, body)` — a valid signature, since `repository_owner` resolves to `attacker-org`, whose secret the attacker knows.
4. POST to `/webhooks` with header `X-Github-Event: status`.
5. `verify_signature` passes (signed with the correct, known `attacker-org` secret) [1](#0-0) .
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and finds the victim commit, creating a `success` status with `context: "ci/tests"` on it, regardless of it belonging to `victim-org` [4](#0-3) .
7. `Commit#deployable?` now returns true for that commit if it was the only blocker [6](#0-5) , and if `victim-org`'s stack has continuous deployment enabled, `stack.schedule_merges` fires, triggering an unauthorized deploy [8](#0-7) .

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```

**File:** app/models/shipit/status/common.rb (L46-52)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
      end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L36-43)
```ruby
        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
