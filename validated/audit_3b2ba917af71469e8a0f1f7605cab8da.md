### Title
Webhook signature verification selects the trust context from an unbound `repository.owner.login`/`organization.login` field while event handlers dispatch on the independently attacker-controlled `repository.full_name` field, breaking the "organization authenticated" = "repository written" binding - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App/`webhook_secret` to verify the incoming signature with, based on `repository.owner.login` (falling back to `organization.login`) read out of the *same* JSON body it is about to validate. Once the HMAC check passes, the raw body is handed unmodified to `Shipit::Webhooks.for_event(event)` handlers, which instead key all of their side effects off `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb#L36-L38`, `push_handler.rb`, pull-request handlers, etc.). Nothing enforces that `repository.owner.login` (the field used to pick the verification secret) and the owner segment of `repository.full_name` (the field used to pick the `Repository`/`Stack` that gets acted upon) refer to the same organization. This is the exact analog of the M-20 pattern called out in scope: "an organization that authenticated versus the repository that is written."

### Finding Description
In a multi-organization Shipit deployment (`docs/setup.md#L182-L209`, `lib/shipit.rb#L170-L200`), each GitHub organization onboarded onto the instance has its own GitHub App and its own `webhook_secret`, resolved via `Shipit.github(organization: repository_owner)` (`lib/shipit.rb#L170-L200`, `app/controllers/shipit/webhooks_controller.rb#L24-L30`).

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

The signature check verifies that the raw body was HMAC'd by *whoever knows the secret for the organization named in `repository.owner.login`*. It does not, and cannot, verify that the *rest* of the payload's content (in particular `repository.full_name`, which is the field the handlers actually act on) belongs to that same organization - both fields are attacker/sender-controlled body content, just two different keys in the same JSON blob.

Every event handler ignores `repository.owner.login` and instead resolves the target `Repository`/`Stack` purely from `repository.full_name`:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

```ruby
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [3](#0-2) 

The `PushHandler` (and the pull-request handlers, closed/labeled/unlabeled/opened/reopened) then invoke real state-mutating actions - `stack.sync_github(...)`, `stack.archive!`/`unarchive!`, `ReviewStackAdapter#create!` - against whatever `Stack`/`Repository` happens to match `repository.full_name`:

```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [4](#0-3) 

The equality that is supposed to hold is:
`organization that produced a valid HMAC (derived from repository.owner.login)` == `organization whose repository/stack is written to (derived from repository.full_name)`

Nothing in the request path enforces this equality. Any sender who legitimately controls the `webhook_secret` for one onboarded organization ("Org A" - e.g. because they themselves created/installed the GitHub App for their own low-privilege organization on this shared Shipit instance, exactly as an unprivileged Party in the source bug controls their own account) can send a request whose:
- `repository.owner.login` = `"org-a"` (so `verify_signature` selects and validates against Org A's own secret - a signature the sender can legitimately produce), and
- `repository.full_name` = `"org-b/some-repo"` (an entirely different organization's repository that is tracked by a `Stack` in this same Shipit instance, which the sender has no GitHub-side access to).

The request passes signature verification (it really was HMAC'd with Org A's secret over the exact bytes sent) and is then dispatched to handlers that act on Org B's `Stack`.

### Impact Explanation
This crosses the organization/authentication boundary explicitly named in scope as Critical: "cross-repository writes." Depending on which event/handler is targeted:
- `push` → forces `stack.sync_github` polling for Org B's stack, and can drive branch-mismatch/queue state changes for a repository the attacker never had GitHub access to.
- `pull_request` (`opened`/`reopened`/`labeled`/`unlabeled`/`closed`) → can create, archive, or unarchive `ReviewStack`s for Org B's repository (`opened_handler.rb`, `closed_handler.rb`, `labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`), i.e. provisioning/tearing down infrastructure that belongs to a different organization's stacks, purely by knowing your own org's webhook secret.

This is the direct structural analog of M-20: a signature/authentication check bound to one identity (`repository.owner.login`/the org whose secret is used) while the state-changing logic is bound to a different, independently forgeable field (`repository.full_name`) - exactly the "authenticated organization vs. written repository" binding called out in the rules as a valid analog class.

### Likelihood Explanation
Requires only that the attacker legitimately administers (or has otherwise obtained, as a normal part of onboarding) the `webhook_secret` for *any* organization configured on the shared Shipit instance - not the target organization's secret, not a GitHub App private key, not a Shipit session, and no GitHub-side write access to the target repository. In any Shipit installation serving more than one GitHub organization (the documented and supported multi-org configuration), this is a low-privilege-to-cross-org escalation with no additional gating.

### Recommendation
In `WebhooksController#verify_signature`, after selecting `github_app` by `repository_owner`, additionally assert that the owner segment of `repository.full_name` (and/or `organization.login` when present) matches `repository_owner` before dispatching to handlers; reject (422) on mismatch. Alternatively, have handlers resolve the target `Repository`/`Stack` using the same organization identity that was cryptographically verified (`repository_owner`), rather than trusting the independent `repository.full_name` field, so the two never diverge.

### Proof of Concept
1. Onboard/administer Org A's GitHub App on a shared Shipit instance that also hosts Org B's stacks (multi-org config per `docs/setup.md#L182-L209`), giving the attacker legitimate knowledge of Org A's `webhook_secret`.
2. Craft a `push` webhook body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/target-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(org-a-webhook-secret, raw_body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "org-a")` and the HMAC validates successfully (`app/controllers/shipit/webhooks_controller.rb#L24-L30`).
5. `PushHandler#process` resolves `Repository.from_github_repo_name("org-b/target-repo")` (`app/models/shipit/webhooks/handlers/handler.rb#L36-L38`, `app/models/shipit/repository.rb#L53-L56`) and calls `stack.sync_github` on Org B's stack - a stack the attacker never had GitHub push/webhook rights to - despite authenticating only as Org A.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
