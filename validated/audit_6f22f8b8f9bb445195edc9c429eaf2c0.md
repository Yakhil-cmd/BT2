### Title
Cross-Repository Commit Status Forgery via Webhook Signature/Payload Binding Break - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The `WebhooksController` selects which organization's webhook secret to use for HMAC verification based on `repository.owner.login` (or `organization.login`) read directly from the *unverified* JSON body, but the handlers that act on the payload (in particular `StatusHandler`) apply the payload's effects without re-checking that the acting organization actually owns the target resource. This breaks the "organization that authenticated" vs. "repository/commit that is written" binding described in the report's bug class.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to verify against using a value taken straight from the JSON body, before the signature has been validated: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: ...)` resolves a distinct `GitHubApp` config (and distinct `webhook_secret`) per organization in multi-org deployments: [3](#0-2) 

Because a Shipit instance can serve multiple organizations, each with their own webhook secret, an attacker who legitimately administers (or is a collaborator on) **one** low-privilege organization tracked by the same Shipit instance knows/controls that organization's own webhook secret. Since a webhook is just an HTTP POST from GitHub's servers signed with that secret, nothing stops the attacker from directly POSTing to `/webhooks` themselves, self-signing the payload with the secret of the organization they legitimately control, while filling in event-specific fields that reference an entirely different, unrelated repository/commit tracked by the same Shipit instance.

The most impactful handler that fails to bind the authenticated organization to the object being mutated is `StatusHandler`: [4](#0-3) 

`Commit.where(sha: params.sha)` performs a **global** lookup by commit SHA with no scoping to the repository/organization that authenticated the request (unlike `PushHandler`/pull-request handlers, which at least resolve `Repository.from_github_repo_name(params.repository.full_name)` before acting — though that field is likewise not cross-checked against `repository.owner.login` used for signature selection). Since commit SHAs are effectively public (visible via `git log`, PRs, CI, etc.) and not organization-secret, an attacker who can produce *any* validly-signed webhook (using their own org's secret) can forge a `status` event carrying an arbitrary `sha` belonging to a commit/stack owned by a completely different organization, and the handler will happily write that fabricated CI status (`state`, `context`, `description`, `target_url`) onto that unrelated commit: [5](#0-4) 

This is exactly the class of bug in the reference report: a value is authenticated/authorized against one binding key (`webhook_secret` keyed by `repository.owner.login`/`organization.login`), but a *different* field in the same payload (`sha`, and to a lesser extent `repository.full_name`) is what actually gets acted upon, with no cross-check that they refer to the same, authorized organization/repository.

### Impact Explanation
Forged commit statuses on a victim's commit can satisfy `ci.require` / CI gating logic used to decide whether a commit is deployable, and Shipit stacks with continuous deployment enabled can automatically ship a commit once all required statuses are green. An attacker holding only a legitimate, low-privilege webhook secret for one organization on a shared Shipit instance can therefore forge a "success" status for a commit belonging to a completely different, higher-privilege repository/stack, potentially causing an **unauthorized deploy** to occur for that stack. This satisfies the High/Critical impact bar ("unauthorized deploy").

### Likelihood Explanation
Requires: (a) a Shipit instance configured with `Shipit.github_organizations` for more than one organization (documented multi-org support, `#1151`), and (b) the attacker legitimately administering the GitHub App/webhook config for at least one such organization (i.e., knowing its `webhook_secret`), which is a realistic scenario for shared/self-serve Shipit deployments. No repository write access or Shipit session/API token is required — only knowledge of one organization's webhook secret, which the attacker is entitled to as that org's admin. The commit SHA being targeted is public information.

### Recommendation
Bind the webhook's authenticated organization to every resource the handler mutates:
- In `WebhooksController`, once `repository_owner` is used to pick the verifying secret, pass that verified organization identity into the handler dispatch so handlers can assert the resource they act on belongs to that same organization.
- In `StatusHandler`, scope `Commit.where(sha: params.sha)` by the commit's stack/repository and verify that repository's owning organization matches the authenticated `repository_owner`/`organization.login` used in `verify_signature`, rejecting the event otherwise.
- Apply the same repository-ownership cross-check to `PushHandler` and the `PullRequest` handlers, which currently trust `repository.full_name` without confirming it matches the organization whose secret validated the request.

### Proof of Concept
1. Shipit is configured with two organizations, `victim-org` and `attacker-org`, each with its own `webhook_secret` (`secrets.github.victim-org.webhook_secret`, `secrets.github.attacker-org.webhook_secret`).
2. Attacker legitimately administers `attacker-org`'s GitHub App integration and therefore knows `attacker-org`'s `webhook_secret`.
3. Attacker learns (via public GitHub) the SHA of a commit `abc123` belonging to a stack under `victim-org/some-repo` that is gated by `ci.require: [ci/tests]` and has continuous deployment enabled.
4. Attacker crafts a `status` event payload:
   ```json
   {
     "sha": "abc123",
     "state": "success",
     "context": "ci/tests",
     "repository": { "owner": { "login": "attacker-org" } }
   }
   ```
5. Attacker computes `X-Hub-Signature: sha1=HMAC(secretForAttackerOrg, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
6. `WebhooksController#verify_signature` resolves `repository_owner` → `"attacker-org"`, fetches `attacker-org`'s app/secret, and the signature verifies successfully (attacker's own valid secret).
7. `StatusHandler#process` runs `Commit.where(sha: "abc123")`, finds the victim's commit (no organization check), and calls `commit.create_status_from_github!(params)`, marking `ci/tests` as `success` on the victim's commit.
8. If this was the last blocking status, Shipit's continuous deployment logic may trigger an unauthorized deploy of `victim-org/some-repo`. [6](#0-5) [4](#0-3)

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

**File:** lib/shipit.rb (L170-181)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
end
```
