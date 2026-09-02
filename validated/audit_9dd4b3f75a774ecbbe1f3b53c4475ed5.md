## Title
Cross-repository commit status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The `status` webhook handler authorizes the *request* by verifying the GitHub HMAC signature keyed to the organization/repository owner named in the payload, but the *action it performs* — writing a CI status onto a `Commit` record — is looked up only by the raw git SHA, with no check that the SHA actually belongs to the repository/organization that was authenticated. Because git SHAs are content-addressed and are shared identically across forks (and any repository containing the same commit), a legitimate webhook signed by an attacker-controlled organization's own installation secret can be used to write/forge a CI status onto a commit belonging to an entirely different, unrelated stack/repository whose owner never authorized that write.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to validate against using the `repository.owner.login` (or `organization.login`) field taken directly from the payload body: [1](#0-0) [2](#0-1) 

This only proves that *the sender controls a valid webhook secret for that named organization* — it says nothing about which commits that organization is entitled to affect.

`StatusHandler#process`, however, does not scope its effect to the authenticated repository at all. It looks up commits purely by SHA across the entire `commits` table: [3](#0-2) 

Compare this with the base `Handler` class, which does provide a `stacks`/`repository_name` scoping helper used by other handlers (e.g. `PushHandler`, `CheckSuiteHandler`): [4](#0-3) [5](#0-4) 

`StatusHandler` never calls this scoping helper, so `params.sha` is matched against every `Commit` row in the database regardless of which `stack`/repository it belongs to.

`Commit#create_status_from_github!` then writes the forged status, which directly feeds `Commit#status`, `#deployable?`, `#blocked?`, and continuous-delivery scheduling: [6](#0-5) [7](#0-6) [8](#0-7) 

**The broken binding, stated as an equality that fails:**
`organization/repository that authenticated the webhook signature` ≠ `repository/stack whose commit row is mutated by the handler`.

Because a commit's SHA is a hash of its content and parent history, it is identical across:
- forks of the same repository (a very common, unprivileged GitHub feature — anyone can fork a public repo),
- any two Shipit-tracked stacks that happen to share history (e.g. a repo added twice under different names/environments, or downstream mirrors).

An attacker who forks a repository that is tracked by Shipit, installs/owns their own GitHub App webhook configuration on their fork's organization (an unprivileged, self-service action requiring no access to the victim's org, repository, or Shipit credentials), and pushes/triggers a `status` event referencing a SHA that also exists in the victim's tracked repository, will have that event's signature verified successfully (it is legitimately signed by their own org's secret) and processed by `StatusHandler`, which then writes the forged status onto the victim's `Commit` row.

### Impact Explanation
A forged commit status can flip a commit from blocked/pending to `success`, satisfying `Commit#deployable?` and `Stack#deployable?`/`#blocking_statuses` checks, and can trigger `schedule_continuous_delivery`, causing an **unauthorized deploy** to be scheduled/executed for a stack the attacker has no relationship with — matching the High/Critical "unauthorized deploy" impact category. This requires no Shipit session, no `ApiClient` token, and no access to the victim organization's webhook secret; it only requires the attacker to control a webhook delivery signed by their *own* organization's secret, satisfying the "unprivileged attacker" and "no Shipit-session/token" constraints.

### Likelihood Explanation
Exploitability depends on the attacker being able to produce/control a commit SHA that also exists in the victim's tracked history — most reliably achieved by forking a public GitHub repository that Shipit tracks (forks preserve identical commit SHAs for all pre-fork history) and configuring their own webhook/App installation on that fork or its organization to fire a `status` event for one of those shared SHAs. This is a realistic and unprivileged scenario for any Shipit deployment that tracks public/forkable repositories.

### Recommendation
Scope `StatusHandler#process` (and any other handler operating on bare SHAs) to the repository named in the payload, using the same `Handler#stacks`/`repository_name` helper already used elsewhere, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining through `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, so a status can never be attributed to a commit outside the authenticated repository/stack.

### Proof of Concept
1. Attacker forks `victim-org/app` (a Shipit-tracked repo) to `attacker-org/app`; the fork shares commit SHA `abc123...` with the upstream commit tracked as a `Shipit::Commit` under `victim-org/app`'s stack.
2. Attacker installs their own GitHub App / configures a webhook with a secret they control on `attacker-org/app`.
3. Attacker triggers (or crafts, since GitHub will sign whatever they configure/send from their own installation) a `status` webhook event with body:
   ```json
   {"sha":"abc123...","state":"success","context":"ci/attacker","repository":{"owner":{"login":"attacker-org"}}}
   ```
   signed with `attacker-org`'s webhook secret.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature (it's the attacker's own valid secret) at [9](#0-8) .
5. `StatusHandler#process` runs `Commit.where(sha: "abc123...")` with no repository filter [3](#0-2)  and finds/updates the victim's `Shipit::Commit`, calling `create_status_from_github!`, potentially unblocking deploys for `victim-org/app`.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
