### Title
Webhook signature is verified against the payload's `repository.owner.login`, but every event handler acts on a different, unauthenticated field (`repository.full_name` / bare commit `sha`) — allowing a legitimate multi-org GitHub App owner to forge status/push events against another organization's stacks - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` to validate the HMAC signature using `repository_owner`, computed from the attacker-controlled JSON body itself (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). [1](#0-0) [2](#0-1) 

Once verification passes, the raw body is handed unchanged to the event handlers, which resolve the *target* repository/stack from a completely different field: `payload.dig('repository', 'full_name')`. [3](#0-2) 

`StatusHandler` goes even further and does not scope by repository at all — it matches on bare commit `sha` across the whole database: [4](#0-3) 

In a multi-org Shipit deployment (`Shipit.github(organization:)` / `github_app_config`), each organization has its own GitHub App and its own `webhook_secret`. [5](#0-4) 

The binding that should hold is: **organization whose secret validated the signature == organization/repository the handler writes to**. Because `repository_owner` is read from the same attacker-suppliable JSON body that also carries `repository.full_name`, nothing forces these two values to refer to the same repository.

### Finding Description
An attacker who legitimately controls one organization onboarded onto this Shipit instance (and therefore knows/administers that organization's GitHub App `webhook_secret`, e.g. as configured in `config/secrets.yml` under `github.<org>.webhook_secret`) can craft an arbitrary raw JSON body themselves, HMAC-sign it with their own org's secret, and set `repository.owner.login` to their own org (so `verify_signature` fetches the matching, correct app/secret and the signature is accepted), while setting `repository.full_name` to a **different, victim organization's repository** that they have no access to.

- `verify_signature` uses `repository_owner` purely to pick which secret to check the signature against — it never asserts that this owner matches the repository the payload ultimately targets. [6](#0-5) 
- All handlers (`PushHandler`, `MembershipHandler` via a different `organization` key, `pull_request/*`) resolve the target stack from `Handler#repository_name`, i.e., `payload.dig('repository', 'full_name')`, which is independent of `repository_owner` in the multi-repo payload shape. [3](#0-2) [7](#0-6) 
- `StatusHandler` is worse still: it doesn't even consult the repository field for scoping, it matches purely by commit `sha` value across the entire `Commit` table, so a forged, validly-signed webhook from any onboarded org can write a `success`/`failure` status onto any other stack's commit that happens to share (or that the attacker can predict/brute-force) a `sha`. [4](#0-3) 

This mirrors the report's bug class exactly: the field that is cryptographically authenticated (`repository.owner.login`, used to pick the verifying secret) differs from the field that drives the state-changing action (`repository.full_name` / bare `sha`), breaking the equality `authenticated organization == acted-upon repository`.

### Impact Explanation
`Commit#create_status_from_github!` feeds `add_status`, which can flip a commit's `state` to `success`, which is a direct input to `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`), and also triggers `stack.schedule_merges`. [8](#0-7) [9](#0-8) 

An attacker holding a legitimate but unrelated organization's webhook secret can therefore forge a valid-looking `status` webhook, pass Shipit's own signature check (because the check is keyed off attacker-controlled `repository.owner.login`), and mark a commit belonging to a completely different, victim stack as CI-`success`, unblocking or accelerating an otherwise-blocked deploy/merge. `push` events can similarly cause `stack.sync_github` to be triggered for stacks they don't own, though this is less directly abusable than the status forgery. This crosses the "unauthorized deploy" impact bar in an equality-of-organization sense: the organization that was authenticated is not the organization whose repository/stack state gets mutated.

### Likelihood Explanation
Requires the attacker to be an administrator of some organization already onboarded to the same Shipit instance (i.e., they know that org's `webhook_secret` from having set up the GitHub App themselves, which is a normal, unprivileged-with-respect-to-other-orgs position in a shared/multi-tenant Shipit deployment). No access to the victim org, no GitHub token, and no Shipit session/API key is required — only the ability to know/administer one org's own webhook secret and to POST a self-crafted signed request to the shared `/webhooks` endpoint.

### Recommendation
- Do not use attacker-suppliable JSON body fields to select the verifying secret unless the resulting handler action is provably re-scoped to the same field afterwards.
- After signature verification, re-validate that `repository_owner` (used for signature selection) matches the actual repository referenced by `repository.full_name` in the payload before dispatching to handlers.
- In `StatusHandler`, scope the `Commit` lookup by repository (join through `Stack`/`Repository`) rather than by bare `sha`, so cross-repository sha coincidences (or forged payloads) cannot mutate an unrelated stack's commit status.

### Proof of Concept
1. Attacker administers `attacker-org`, which is a valid organization configured in Shipit's `secrets.github.attacker-org.webhook_secret`.
2. Attacker crafts a JSON body for the `status` event:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<sha of a commit in victim-org/victim-repo's tracked stack>",
  "state": "success",
  "context": "ci/attacker-forged"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, body)>` themselves.
4. `WebhooksController#verify_signature` computes `repository_owner == "attacker-org"`, fetches `attacker-org`'s app/secret, and the signature validates successfully. [6](#0-5) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, which finds the victim commit purely by `sha` (repository ownership never checked) and records a `success` status on it, potentially making it `deployable?` in the victim's stack. [4](#0-3) [8](#0-7)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L366-384)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
```
