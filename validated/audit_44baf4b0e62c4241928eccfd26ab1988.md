This confirms the multi-organization config schema: `Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization key in `secrets.github` ( [1](#0-0) ), and `WebhooksController#verify_signature` selects which organization's secret to verify against using only the payload-supplied `repository.owner.login` (or `organization.login`) field [2](#0-1) , while every event handler resolves the actual `Stack`/`Repository` to mutate from a *different* payload field, `repository.full_name` [3](#0-2) . Since both fields live in the same attacker-controlled JSON body and the signature only proves "this body was HMAC'd with organization X's secret," not "organization X owns the repository named in this body," an operator who has legitimate but low-privilege access to configure their **own** organization's webhook secret in a shared/multi-tenant Shipit instance can forge a payload whose `owner.login` matches their own org (so it authenticates) but whose `repository.full_name` names a victim stack belonging to a different, unrelated organization also hosted on the same Shipit instance.

### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login` while every event handler acts on the independent, equally attacker-controlled `repository.full_name` field, letting one configured organization forge writes into another organization's stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate against using `repository_owner`, derived from `params.dig('repository','owner','login')` (falling back to `params.dig('organization','login')`), and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [4](#0-3) . `Shipit.github` looks up a per-organization config block (and thus a distinct `webhook_secret`) keyed by that same organization string [1](#0-0) . However, every webhook handler (push, pull_request, status/check_suite via `Handler#stacks`, etc.) determines *which* `Stack`/`Repository` to act on using `repository.full_name`, a sibling field in the same JSON body that is not cross-checked against `repository.owner.login` [3](#0-2) [5](#0-4) . Because the HMAC only proves "this exact byte-for-byte body was signed with organization X's secret," and doesn't itself constrain what `full_name` may say, an attacker with legitimate access to configure Organization X's webhook secret in the same Shipit deployment can construct a payload where `owner.login = "X"` (so it passes signature check against X's secret) but `repository.full_name = "Y/victim-repo"` naming a stack that belongs to a completely different, unrelated organization Y also onboarded to the same Shipit instance.

### Finding Description
The trust binding that should hold is: *organization that authenticated the request* == *repository/organization that owns the stack being written*. The code breaks this equality:

- Verification binding: `repository_owner` (used to select the secret) comes from `repository.owner.login` / `organization.login`.
- Effect binding: `repository_name` used by handlers to locate the DB `Repository`/`Stack` comes from `repository.full_name`, an independent JSON field [3](#0-2) .

Both values are inside the same raw HTTP body that is HMAC-signed as a whole, so a *third party who doesn't know any org's secret* cannot exploit this (the whole body, including both fields, must match the HMAC). But the binding is enforced only "the org whose secret was used to sign this blob," not "the org that this blob's `full_name` refers to." Any principal who is entitled to configure/rotate one organization's `webhook_secret` in a Shipit deployment that hosts multiple organizations (a realistic Shopify/Shipit multi-tenant use case supported directly by `Shipit.github_app_config`) can freely choose the `full_name` value inside their own signed payload, since nothing in `verify_signature` or in the handlers cross-validates that `repository.full_name`'s owner segment matches the `repository.owner.login`/`organization.login` used for signature selection.

This is structurally the same class of bug as M-10: a field that downstream logic treats as authoritative (`repository.full_name`, deciding *what gets written*) is not actually the field the "migration"/verification step covers meaningfully as an equality (`repository.owner.login`, deciding *whose secret authorizes the write*) — the code assumes these always refer to the same repository, but nothing enforces it.

### Impact Explanation
An org admin who legitimately controls Organization X's GitHub App/webhook secret on a shared Shipit instance can send crafted webhook requests that pass signature verification under X's identity, yet cause push/pull_request/status/check_suite handlers to act on stacks belonging to Organization Y's repositories: triggering `stack.sync_github`, closing/opening/archiving review stacks, injecting fake commit statuses that gate `deployable?`/merge-queue logic, or creating spurious teams/users via the `membership` handler for organizations they don't own. This is an unauthorized cross-repository/cross-organization write and can be leveraged to force an unauthorized deploy path (e.g., forging a passing CI `status` on a victim stack's commit to satisfy `deployable?`/merge-queue gating) — matching the "cross-repository writes" / "unauthorized deploy" Critical impact category.

### Likelihood Explanation
Likelihood is bounded by whether the deployment is multi-tenant (multiple organizations configured under `secrets.github`, each with its own onboarded stacks) — which the engine explicitly supports via `github_app_config`/`github_organizations` [6](#0-5) . In such a deployment, any org that has been granted its own webhook secret (a normal, low-privilege-relative-to-other-tenants setup step, not a Shipit admin/session credential) can exploit this without needing any other organization's secret, GitHub App key, or Shipit session.

### Recommendation
In `WebhooksController#create`/handlers, after selecting the verifying organization via `repository_owner`, re-derive and enforce that the owner segment of `repository.full_name` (and/or `organization.login` for org-scoped events) matches the same `repository_owner` used to pick the webhook secret before dispatching to any handler; reject the request (422) on mismatch. Equivalently, scope `Repository.from_github_repo_name` lookups to repositories that are also verified to belong to the authenticating organization/webhook_secret.

### Proof of Concept
1. Shipit is configured with two organizations under `secrets.github`: `orgX` (attacker-administered, has its own `webhook_secret`) and `orgY` (victim, unrelated, hosts stack `orgY/victim-repo`).
2. Attacker builds a JSON payload for the `push`/`status` event:
   ```json
   {
     "repository": { "owner": { "login": "orgX" }, "full_name": "orgY/victim-repo" },
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>"
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(orgX_webhook_secret, body)` using the secret they legitimately hold for `orgX`.
4. `verify_signature` computes `repository_owner = "orgX"`, loads `Shipit.github(organization: "orgX")`, and successfully verifies the signature [7](#0-6) .
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orgY/victim-repo")` [3](#0-2) [8](#0-7) , enqueuing `sync_github`/status updates against `orgY`'s stack despite the attacker only owning `orgX`'s webhook credentials — an org-crossing write that the signature check was supposed to prevent.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
