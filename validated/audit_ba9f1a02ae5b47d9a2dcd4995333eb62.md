### Title
Cross-repository commit status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate a signature against based on `repository_owner`, i.e. `params.dig('repository','owner','login')`, and validates the HMAC over the raw payload with that organization's secret. [1](#0-0)  That check only proves the payload was sent by a party who controls a GitHub App/webhook installation on the organization named in the payload's `repository.owner.login` — it says nothing about which `Stack`/`Commit` in Shipit's database the event is allowed to affect. For `status` events, `StatusHandler#process` uses the authenticated payload's `sha` to look up commits with a completely unscoped, global query, `Commit.where(sha: params.sha)`, across every repository/stack in the installation, and writes a GitHub-reported status onto whatever rows match. [2](#0-1) 

### Finding Description
The binding that should hold is: **organization that authenticated == repository whose commit is written**. Concretely, `verify_signature` authenticates that *some* org named in the payload's `repository.owner.login` sent this webhook (using that org's `webhook_secret`). [3](#0-2)  `StatusHandler`, however, resolves the target of the write purely by `sha`, with no cross-check that the `Commit` row it updates belongs to a `Stack`/`Repository` matching the authenticated `repository.owner.login`/`full_name`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

Because git commit SHAs are content-addressed and preserved across forks, any organization that installs its own legitimate GitHub App (obtaining its own valid `webhook_secret`) can fork a victim's public repository being tracked by Shipit. The forked repo shares identical commit SHAs with the upstream victim repository. The attacker's own, correctly-signed `status` webhook (verified with the attacker's own org's `webhook_secret` since `repository.owner.login` in the payload is the attacker's own org) carries a `sha` that is identical to a commit that also exists in the victim's `Stack`. `StatusHandler` finds and updates the victim's `Commit` row (via the global `Commit.where(sha:)` scan) with an attacker-chosen `state` (e.g. `success`), `description`, `context`, and `target_url`. `Commit#create_status_from_github!` records this straight from the webhook `params` with no re-validation against the actual repository. [4](#0-3) 

### Impact Explanation
Shipit uses commit status/CI state to gate deploys: `Commit#deployable?` requires `success?` and `!blocked?` unless the stack disables CI enforcement, and `blocked?`/`blocking_statuses` are computed purely from the `Status::Group` built off these `statuses` rows. [5](#0-4)  Continuous delivery is also scheduled off the same `deployable?` check right after a status update. [6](#0-5)  An attacker who forges a `success` status on a victim's commit via this cross-repository binding break can therefore make an otherwise CI-failing or CI-pending commit appear deployable, potentially triggering an unauthorized (continuous) deploy of unvetted code — this satisfies the "Critical: unauthorized deploy" bar in the rules.

### Likelihood Explanation
The prerequisites are all attacker-controlled and require no privileged Shipit access, no `ApiClient` token, and no compromise of the victim's or Shipit's secrets: (1) create/own a GitHub org and App (`webhook_secret` you generate yourself), (2) fork the victim's public repository (shared commit history/SHAs by construction of git forking), (3) trigger or fabricate a `status` event on your fork's copy of the shared commit and let your legitimate App deliver the (correctly signed) webhook to Shipit's `/webhooks` endpoint. No interaction with the victim org, Shipit staff, or any Shipit credential is needed. This is a purely unprivileged attack surface bounded entirely by `app/controllers/shipit/webhooks_controller.rb` and `app/models/shipit/webhooks/handlers/status_handler.rb`.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and any other handler that resolves targets purely from payload identifiers, e.g. re-check `check_suite`/`commit`-keyed handlers) to commits belonging to stacks whose `Repository` matches the authenticated `repository.full_name`/`owner.login` from the same payload, e.g. `Commit.joins(stack: :repository).where(sha: params.sha, repositories: { owner: repository_owner, name: repository_name })`, rather than a bare global `Commit.where(sha:)`. More generally, every webhook handler must verify that the entity it mutates (`Commit`, `Stack`, etc.) is actually owned by the repository/organization whose secret validated the signature, not merely correlated by an attacker-influenceable value like `sha`.

### Proof of Concept
1. Attacker creates GitHub org `evil-org` and installs a GitHub App on it (self-service, no victim interaction); Shipit config now trusts `evil-org`'s own `webhook_secret` for org `evil-org`.
2. Attacker forks `victim-org/tracked-repo` (a repository Shipit is tracking as a `Stack`) into `evil-org/tracked-repo`. The fork shares identical commit SHAs with upstream, including `<victim_sha>` that exists as a `Commit` row under the victim's `Stack`.
3. Attacker generates (or has GitHub naturally generate, e.g., via a check run on the fork) a `status` webhook event where `repository.owner.login == "evil-org"`, `repository.full_name == "evil-org/tracked-repo"`, `sha == "<victim_sha>"`, `state == "success"`.
4. GitHub signs this payload with `evil-org`'s webhook secret and delivers it to Shipit's `/webhooks` endpoint.
5. `WebhooksController#verify_signature` looks up `Shipit.github(organization: "evil-org")` and successfully verifies the signature — it belongs to `evil-org`, which is legitimate. [3](#0-2) 
6. `StatusHandler#process` runs `Commit.where(sha: "<victim_sha>")`, which matches the victim's `Commit` row (because SHAs are global, not scoped to `evil-org`), and calls `create_status_from_github!` with `state: "success"`, marking the victim's commit as passing CI regardless of the real status in `victim-org/tracked-repo`. [2](#0-1) [4](#0-3) 
7. If the victim's stack has continuous deployment enabled, `schedule_continuous_delivery` fires because `deployable?` now returns true, resulting in an unauthorized deploy of the (potentially still-failing) victim commit. [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-287)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end

    def children
      self.class.where(stack_id:).newer_than(self)
    end

    def detach_children!
      children.detach!
    end

    def pull_request?
      pull_request_number.present?
    end

    # TODO: remove in a few versions when it is assumed the commits table was backfilled
    def pull_request_number
      super || message_parser.pull_request_number
    end

    def title
      pull_request_title || message_header
    end

    def message_header
      message.lines.first.to_s.strip
    end

    # TODO: remove in a few versions when it is assumed the commits table was backfilled
    def pull_request_title
      super || message_parser.pull_request_title
    end

    def revert?
      title.start_with?('Revert "') && title.end_with?('"')
    end

    def revert_of?(commit)
      title == %(Revert "#{commit.title}") || title == %(Revert "#{commit.message_header}")
    end

    def short_sha
      sha[0..9]
    end

    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
