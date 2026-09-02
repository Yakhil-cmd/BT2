### Title
Cross-repository status forgery bypasses per-organization webhook authentication - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook against the webhook secret of a *specific organization* — the one named in the payload's `repository.owner.login` (or `organization.login`) field — via `Shipit.github(organization: repository_owner).verify_webhook_signature`. That authentication establishes the equality: **organization whose secret signed the request == organization named in `payload['repository']['owner']['login']`**. However, `Shipit::Webhooks::Handlers::StatusHandler#process` never re-checks that binding when applying the payload: it looks up commits purely by SHA, globally, with `Commit.where(sha: params.sha)`, and calls `commit.create_status_from_github!(params)` on every match, regardless of which repository/stack that commit belongs to. [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
The controller's signature check only proves that the request was signed with the webhook secret belonging to *some organization that is onboarded to this Shipit instance* — namely whichever organization is named in the attacker-controlled `repository.owner.login` field of the same payload used to select the secret:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

This check is scoped to the *organization*, not to the *specific repository/commit* the event claims to describe. It is entirely satisfiable by an attacker who legitimately owns/administers a repository under a different organization that is *also* onboarded to the same Shipit instance (a common real-world setup: many teams/orgs share one Shipit deployment). Such an attacker can configure a real GitHub status webhook on their own repository and let GitHub sign it with their own org's webhook secret — a perfectly valid signature for their own org.

The vulnerable step is that `StatusHandler`, which handles the `status` event, does not verify that the commit SHA in the payload belongs to a repository owned by the authenticated organization:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

Contrast this with `Handler#stacks`, which *does* scope lookups by `repository_name` (`payload.dig('repository', 'full_name')`) via `Repository.from_github_repo_name` used by `PushHandler`, showing that the codebase's own convention is to scope processing to the specific repository in the payload — a convention `StatusHandler` fails to follow. [5](#0-4) [6](#0-5) 

Git commit SHAs are content-addressed but are not unique to one repository: any fork of a public/shared repository contains identical SHAs for shared history. An attacker who forks (or otherwise gains write/App access to) a repository sharing history with a repository tracked by another organization's Shipit stack can send a `status` event for that shared SHA, signed with their own org's webhook secret, and have it accepted and applied to the *victim's* commit record — because the handler never checks that the commit's owning repository matches the authenticated organization.

### Impact Explanation
`commit.create_status_from_github!(params)` updates the commit's CI/CD status record, which feeds into deployability checks (`required_statuses`, `blocking_statuses`) used by continuous deployment (`Stack.schedule_continuous_delivery` / `ContinuousDeliveryJob`) and by manual deploy gating in `app/controllers/shipit/api/stacks_controller.rb` and `app/models/shipit/stack.rb`. Forging a passing status for a commit in a victim stack that the attacker does not control can make an otherwise-blocked commit appear deployable, enabling an **unauthorized deploy** through continuous deployment or by unblocking a manual deploy request — this satisfies the High-impact bar (escalation causing an unauthorized deploy) defined in the rules.

### Likelihood Explanation
Exploitability requires: (1) the target Shipit instance hosts stacks for more than one GitHub organization (a common multi-tenant setup), (2) the attacker controls or has webhook-triggering access to a repository in a *different, weaker-trust* organization that is also onboarded, and (3) a commit SHA collision — trivially achievable via a fork of the victim's public repository, which shares the exact same git history and SHAs. No privileged Shipit credentials, GitHub App keys, or `webhook_secret` disclosure are required, satisfying the "unprivileged attacker" constraint; the attacker only needs ordinary GitHub write access to their own onboarded repository.

### Recommendation
Scope `StatusHandler#process` (and any other handler that looks up records solely by content hash) to the repository named in the same payload used for signature verification, e.g. filter `Commit.where(sha: params.sha)` down to commits whose `stack.repository` matches `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, consistent with `Handler#stacks`. More generally, webhook signature verification should assert equality between the authenticated organization/repository and the repository whose data the handler is about to mutate, not merely that some onboarded organization's secret matches the request.

### Proof of Concept
1. Onboard two organizations to the same Shipit instance: `victim-org/app` (tracked stack) and `attacker-org/app` (attacker's own fork of `victim-org/app`, sharing commit history/SHAs).
2. Attacker pushes/labels a commit in their fork whose SHA `abcdef123...` is identical to a commit SHA that also exists (and is pending/blocked) in `victim-org/app`'s tracked stack.
3. Attacker's own GitHub App/webhook for `attacker-org/app` sends a `status` event: `{"sha": "abcdef123...", "state": "success", "context": "ci/required-check", "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/app"}}`, signed by GitHub with `attacker-org`'s legitimate webhook secret.
4. `WebhooksController#verify_signature` resolves `repository_owner` to `attacker-org` and successfully verifies the signature against `attacker-org`'s own secret — succeeds legitimately.
5. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which executes `Commit.where(sha: 'abcdef123...')` — matching the commit belonging to `victim-org/app`'s stack — and calls `create_status_from_github!` on it, marking the required check as passing.
6. The victim stack's commit is now falsely reported as passing its required status check, potentially triggering an unauthorized continuous deployment or unblocking a manual deploy that the victim organization never approved.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
