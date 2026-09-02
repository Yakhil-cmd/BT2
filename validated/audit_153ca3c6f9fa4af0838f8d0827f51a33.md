### Title
Cross-organization forged commit-status injection due to signature verification being scoped to a different field than the one used to select the record mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App/organization derived from `repository.owner.login` (falling back to `organization.login`), but `StatusHandler#process` (the code that actually mutates data) selects the target `Commit` purely by `sha`, with no scoping to the organization or repository that was authenticated. This breaks the binding "organization authenticated == repository/record written," analogous to the point-doubling report's core flaw where the value used for the security check is disconnected from the value that determines the final trusted output.

### Finding Description
`verify_signature` picks which `GitHubApp` (and therefore which `webhook_secret`) to validate the HMAC signature against, based solely on `repository_owner`: [1](#0-0) [2](#0-1) 

`webhook_secret` is explicitly documented as **optional** per configured GitHub App/organization: [3](#0-2) [4](#0-3) 

And when no secret is configured for that organization, verification is bypassed entirely: [5](#0-4) 

Once the signature check passes (or is skipped because the org-of-record has no secret), `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler`, which looks up the `Commit` **only by `sha`**, with no repository/organization filter at all: [6](#0-5) 

Because `repository.owner.login` (the value proving "this org sent it") and the field that actually determines which stack/commit is written to (`sha`, which is globally unique across all stacks in the DB) are never checked against each other, an unprivileged sender who can satisfy the (possibly secret-less) authentication for **any** configured organization can inject a forged commit status for a commit belonging to an entirely different, unrelated, and properly-secured organization's repository — exactly the "organization authenticated vs. repository written" binding break called out in the task rules, and structurally the same class of bug as the report: a check is performed against one value while the effect is applied based on a different, unlinked value.

### Impact Explanation
`create_status_from_github!` directly influences whether a commit is `deployable?` and whether continuous delivery/merge queue proceeds: [7](#0-6) [8](#0-7) 

A forged "success" status can flip `deployable?` to true and trigger `schedule_continuous_delivery`, which schedules `ContinuousDeliveryJob`: [9](#0-8) 

This can cause an unauthorized deploy of a commit whose real CI is failing/pending, satisfying the "unauthorized deploy" Critical-tier impact. The attack does not require repository write access, an `ApiClient` token, or the target org's `webhook_secret` — only the ability to satisfy verification for any org registered in the multi-org config that has no (or a weak) webhook secret, which is an explicitly supported, documented configuration.

### Likelihood Explanation
The likelihood depends entirely on deployment configuration: it requires Shipit to be configured with multiple GitHub Apps/organizations (a supported and documented feature, see `secrets_double_github_app.yml`) where at least one has no `webhook_secret` set — itself a documented "optional" setting. Given that setup, exploitation requires no credentials at all: just knowledge of a target commit `sha` (public information on GitHub) and an HTTP POST to `/webhooks` with the `X-Github-Event: status` header and a crafted `repository.owner.login`/`organization.login` matching the secret-less org.

### Recommendation
- In `StatusHandler` (and any other handler using `Handler#stacks`/`repository_name`), scope the `Commit`/`Stack` lookup by the same repository/organization identity that was used to select the signing secret in `verify_signature`, and reject the webhook if `repository.owner.login` doesn't match `repository.full_name`'s owner segment.
- Consider requiring `webhook_secret` to be mandatory for any organization capable of authenticating writes, or at minimum, refuse events whose target repository/organization differs from the one that produced a valid (or bypassed) signature.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgA` (no `webhook_secret` set, per documented "optional" support) and `OrgB` (properly secured, hosts the real target stack and commit `abc123...`).
2. As an unauthenticated external party, POST to `/webhooks` with:
   - `X-Github-Event: status`
   - No/garbage `X-Hub-Signature`
   - Body: `{"repository": {"owner": {"login": "OrgA"}, "full_name": "OrgA/anything"}, "sha": "abc123...", "state": "success", "context": "ci/required", ...}`
3. `verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally [10](#0-9) .
4. `StatusHandler#process` finds the real `Commit` in `OrgB`'s stack purely by `sha` and creates a fabricated "success" status on it [6](#0-5) , potentially triggering an unauthorized deploy via `schedule_continuous_delivery`.

### Citations

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

**File:** docs/setup.md (L118-119)
```markdown

**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-47)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
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
