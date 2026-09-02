## Title
Cross-organization forged commit status write via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

## Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App / webhook secret to validate a signature by reading `repository.owner.login` **from the untrusted payload itself**, and only proves that the request was legitimately signed by *some* organization's registered GitHub App — not that the event actually concerns that organization's repository. [1](#0-0) 

`StatusHandler#process`, however, resolves the target of the event purely by commit SHA, globally across the entire database, with no repository/organization scoping at all: [2](#0-1) 

This breaks the equality that should hold: `organization that authenticated the webhook == repository whose Commit/Status is written`.

## Finding Description
In a multi-tenant Shipit install (a documented, supported configuration — see `docs/setup.md` "Using Multiple Github Applications", and `lib/shipit.rb#github`/`github_app_config`), each GitHub organization has its own GitHub App and its own `webhook_secret`. [3](#0-2) 

`verify_signature` picks which `webhook_secret` to check against based on `repository_owner`, which is read from the JSON payload the *attacker* controls (`params.dig('repository','owner','login')`): [4](#0-3) 

An attacker who owns/administers *any* GitHub organization onboarded onto the same Shipit instance can legitimately trigger a GitHub `status` webhook for their own repository (e.g., by setting a commit status via the GitHub API on a commit in a repo they control). GitHub signs this payload with that attacker-controlled organization's `webhook_secret`, so `verify_webhook_signature` passes — the signature is valid for the organization named in the payload. [5](#0-4) 

Once the request passes `verify_signature`, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which looks up **any** `Commit` row in the whole database matching `params.sha`, with zero relation to the `repository` field in the same payload: [6](#0-5) 

Because git commit SHAs are content-addressed, an attacker can obtain a commit with an identical SHA to one tracked by a victim stack simply by forking the victim's (often public) repository — the forked commit retains the exact same SHA in the attacker's own repo. The attacker then reports a commit status (e.g., `"state": "success"`) for that SHA from their own org/app, satisfied by their own legitimately signed webhook, and `StatusHandler` writes/overwrites a `Status` on the commit as tracked by the **victim's** stack, because lookup is by bare SHA only: [2](#0-1) 

Compare this to the sibling handlers (`PushHandler`, pull-request handlers), all of which correctly scope through `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before touching any `Stack`: [7](#0-6) [8](#0-7) 

`StatusHandler` is the outlier that omits this scoping.

## Impact Explanation
Commit statuses are load-bearing for deploy authorization: they feed `required_statuses`, `blocking_statuses`, and `soft_failing_statuses` in `DeploySpec`, which gate whether a commit is considered deployable (used by continuous delivery and manual deploy checks): [9](#0-8) 

By forging a `success` status for a victim commit from an unrelated, attacker-controlled organization's legitimately-signed webhook, the attacker can make a commit that has not actually passed the victim's real CI appear deployable, enabling an unauthorized deploy of that commit through Shipit's continuous-delivery/merge-queue gating. This matches the "unauthorized deploy" Critical impact category.

## Likelihood Explanation
This requires: (1) the target Shipit instance is a multi-org deployment (explicitly documented and supported), (2) the attacker controls (or can install the Shipit GitHub App on) any one of the onboarded organizations — a normal, unprivileged action for their own org, not the victim's, (3) the attacker can fork/duplicate a public commit from the victim repo to get a matching SHA, and (4) can post a commit status via the GitHub API for their own repo. All of these are achievable by an attacker with no access to the victim's repository or Shipit session — only ownership of a separate GitHub organization that happens to be configured on the same Shipit instance.

## Recommendation
Scope `StatusHandler#process` by repository, mirroring `Handler#stacks`/`Repository.from_github_repo_name(payload.dig('repository','full_name'))`, and only update statuses on commits belonging to that repository's stacks — e.g., restrict the `Commit` lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent, instead of a bare, global `Commit.where(sha:)`.

## Proof of Concept
1. Shipit is configured with two GitHub organizations, `victim-org` (tracks a public repo `victim-org/app` with a stack) and `attacker-org` (attacker owns/administers this org and has installed the Shipit GitHub App there with their own `webhook_secret`), per `docs/setup.md`'s multi-app config.
2. Attacker forks `victim-org/app` into `attacker-org/app-fork`. The HEAD commit (and its ancestors) retain identical SHAs to the upstream commits, including a commit `SHA_X` that is queued for deploy in `victim-org`'s Shipit stack.
3. Attacker uses the GitHub API (with their own repo's admin rights) to POST a commit status `{"sha": "SHA_X", "state": "success", "context": "ci/required-check"}` against `attacker-org/app-fork`.
4. GitHub delivers a `status` webhook to Shipit, signed with `attacker-org`'s `webhook_secret`, with `repository.owner.login == "attacker-org"`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates the signature successfully (it is valid for that org). [10](#0-9) 
6. `StatusHandler#process` runs `Commit.where(sha: "SHA_X")`, finds the commit belonging to `victim-org`'s stack (because the SHA is identical), and calls `create_status_from_github!`, writing a forged `success` status onto the victim's commit. [2](#0-1) 
7. If `"ci/required-check"` is one of `victim-org`'s `required_statuses`/`blocking_statuses`, the victim's commit now appears deployable even though its real CI never reported success, potentially triggering an unauthorized deploy via continuous delivery.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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

**File:** app/models/shipit/deploy_spec.rb (L194-204)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```
