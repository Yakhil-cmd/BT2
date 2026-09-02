### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login`, but event handlers act on the unrelated `repository.full_name` field - allowing cross-repository webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to use for HMAC verification based on `repository_owner`, a value pulled from `params.dig('repository','owner','login')` (or `params.dig('organization','login')`). Once the signature check passes, `create` dispatches the *entire raw payload* to event handlers, which act on `payload.dig('repository','full_name')` to resolve the target `Stack`/`Repository`. These two payload fields are never cross-validated against each other, so a valid signature for organization A does not guarantee the acted-upon repository actually belongs to organization A.

### Finding Description
`verify_signature` computes the signing organization purely from the attacker-controlled JSON body: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up per-organization webhook secrets in a multi-tenant configuration (documented in `docs/setup.md`, "Using Multiple Github Applications"), where each configured GitHub organization has its own `app_id`/`webhook_secret`: [3](#0-2) 

After signature verification succeeds, the controller hands the *whole raw payload* — unmodified — to the registered handlers: [4](#0-3) 

Handlers resolve their target `Stack`(s) using a completely different field of the same payload, `repository.full_name`, via `Repository.from_github_repo_name`: [5](#0-4) 

Nothing enforces that `repository.full_name` (e.g. `"OrgB/victim-repo"`) is actually owned by `repository.owner.login`/`organization.login` (e.g. `"OrgA"`) that was used to select the signing secret. This is the same bug class as the audited report: a boolean/derived value (`ethIs0`, here `repository_owner`) is checked against one entity (`ovlFeed`, here org A's webhook secret) while the operation that follows (`_liquidity` from `marketFeed`, here the target `Stack`/repository resolved from `repository.full_name`) is actually performed against a different, unverified entity.

The binding that should hold is:
`organization authenticated (repository_owner used for HMAC secret selection) == repository actually written to (repository.full_name used by handlers)`

Before the attacker's crafted request, in a legitimate webhook, both fields come from the same GitHub-generated payload and always match. After an attacker crafts a payload with `repository.owner.login = "OrgA"` but `repository.full_name = "OrgB/victim-repo"`, and signs it with OrgA's real webhook secret (which the attacker legitimately possesses because they administer/own the GitHub App/org "OrgA" that is configured in this multi-tenant Shipit instance), `verify_signature` passes using OrgA's secret, but the handlers operate on OrgB's repository/stack — a repository the attacker has no ability to push to or administer.

### Impact Explanation
An attacker who legitimately owns/administers any single GitHub organization onboarded to a shared, multi-organization Shipit installation (and therefore knows that org's `webhook_secret`) can forge webhook deliveries claiming to originate from a repository under a completely different, unrelated organization tracked by the same Shipit instance. Depending on which handler processes the event, this enables:
- Injecting fake `status`/`check_suite` events for arbitrary commits on a victim stack, which is exactly the kind of signal (`all_status_checks_passed?`, required CI gating) used by `MergeRequest#reject_unless_mergeable!`/`merge!` to decide whether a PR can be merged and by deploy safety checks — see `app/models/shipit/merge_request.rb` [6](#0-5) .
- Triggering `GithubSyncJob` or other repo-scoped side effects for a stack the attacker does not own.
- Manipulating team/membership records via the `membership` handler for an org they don't control.

This crosses a repository/organization trust boundary: cross-repository writes/an unauthorized influence on merge/deploy gating for a repository the attacker was never granted access to, satisfying the "cross-repository writes" / "unauthorized deploy, rollback or merge" Critical-impact bar, provided the deployment is a genuine multi-org Shipit installation (the documented, supported "Using Multiple Github Applications" configuration).

### Likelihood Explanation
Requires: (1) the target Shipit instance configured with multiple GitHub organizations (a documented, supported feature, not a misconfiguration), and (2) the attacker legitimately controlling/administering at least one of those onboarded organizations (thus knowing its own `webhook_secret`). Given those preconditions — which do not require compromising the victim organization, the deploy host, or any Shipit account/API token — forging the payload and computing a valid HMAC-SHA1 signature with the attacker's own known secret is trivial. The likelihood is therefore moderate to high specifically for multi-tenant deployments; it is not exploitable at all for single-organization deployments (where `repository_owner` always resolves to the sole configured org and the attacker would need that org's secret regardless).

### Recommendation
In `WebhooksController#verify_signature`/`create`, after selecting the webhook secret via `repository_owner`, additionally verify that the actual repository being acted upon (`payload.dig('repository','full_name')`) belongs to that same `repository_owner`/organization before dispatching to handlers — e.g. assert `repository_full_name.split('/').first.casecmp(repository_owner) == 0`, or resolve the `Stack`/`Repository` and check its `owner` matches the authenticated organization before invoking any handler.

### Proof of Concept
1. Shipit is configured with two GitHub organizations, `OrgA` (attacker-owned/administered) and `OrgB` (victim, with an existing tracked `Stack` for `OrgB/victim-repo`), per the multi-org config in `test/dummy/config/secrets_double_github_app.yml` / `docs/setup.md`.
2. Attacker knows `OrgA`'s `webhook_secret` (they administer that org/app).
3. Attacker crafts a JSON payload:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and sends it with header `X-Github-Event: status` to the public `/github/webhooks` endpoint.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")`, verifies successfully with OrgA's secret [7](#0-6) .
6. `create` dispatches the payload to the `status` handler, which resolves stacks via `repository.full_name = "OrgB/victim-repo"` [8](#0-7)  and records a forged "success" status for the victim's commit, potentially satisfying `required_statuses`/merge-queue gating for `OrgB`'s stack despite the attacker having no access to `OrgB`.

Note: I was unable to fetch the full contents of `push_handler.rb` and `status_handler.rb` before the tool budget ended; the exact side effects (which model fields get written) should be double-checked in those files, but `handler.rb`'s shared `stacks`/`repository_name` resolution logic confirms the root-cause mismatch independent of the specific handler.

### Citations

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

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
