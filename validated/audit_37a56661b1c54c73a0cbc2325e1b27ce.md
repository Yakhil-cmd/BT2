### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while the event is applied to whatever `repository.full_name` (or `sha`) says, allowing a compromised/malicious organization on a multi-org Shipit install to forge events for another organization's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC key to validate `X-Hub-Signature` by looking at `repository.owner.login` (falling back to `organization.login`) and calling `Shipit.github(organization: repository_owner)`. Once the signature check passes, the raw payload is dispatched to handlers that resolve the *actual* record to mutate using a **different** field of the same attacker-controlled JSON body: `Handlers::Handler#stacks` uses `payload.dig('repository', 'full_name')`, and `Handlers::StatusHandler#process` uses `payload['sha']` alone (not scoped to a repo at all). Nothing enforces that the owner used for signing equals the owner embedded in `full_name`.

### Finding Description
`verify_signature` binds trust to one field: [1](#0-0) [2](#0-1) 

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
```

The handlers that actually mutate state use a different field from the same payload to select the target: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

and, most sensitively, `StatusHandler` resolves target commits purely by `sha`, with no repository scoping check at all: [4](#0-3) 

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

Shipit explicitly supports hosting multiple GitHub organizations from a single instance, each with its own `webhook_secret` (see `docs/setup.md`, "Using Multiple Github Applications", and `Shipit.github_organizations`/`Shipit.github(organization:)` in `lib/shipit.rb`). Anyone who administers the GitHub App/webhook for **one** configured organization (call it `org-attacker`) knows that organization's `webhook_secret` and can compute a valid `X-Hub-Signature` for any payload body they choose - they are not restricted to their own repository's data. The check only proves "this payload was signed with `org-attacker`'s secret"; it never proves "the repository/commit this payload references belongs to `org-attacker`."

Because `repository_owner` (used to select the signing key) and `repository.full_name`/`sha` (used to select the write target) are read from **independent JSON keys in the same attacker-supplied body**, an attacker who owns `org-attacker` can send:

```json
{
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "org-attacker/decoy" },
  "sha": "<commit sha belonging to victim-org/victim-repo tracked by the same Shipit instance>",
  "state": "success",
  "context": "ci/required-check"
}
```

signed with `org-attacker`'s webhook secret. `verify_signature` looks up the key for `org-attacker`, verifies successfully, and `StatusHandler#process` then looks up `Commit.where(sha: ...)` globally (not scoped by stack/repo) and writes a forged `success` status onto a commit belonging to `victim-org/victim-repo` — an organization/stack the attacker never authenticated for.

This is the same trust-binding defect as the referenced report: a value that is authenticated (`org-attacker`, via HMAC) is silently assumed to be the same value that gets acted upon (`victim-org`'s commit/repo), with no equality check enforced between them.

### Impact Explanation
A forged `success`/passing status on an arbitrary commit satisfies CI requirements enforced by `MergeRequest`/merge-queue and continuous-deployment logic (`Status`, `MergeRequest::StatusChecker`, `ProcessMergeRequestsJob`), which gate automatic merges and deploys on required status contexts. An attacker who controls the webhook secret for any one organization configured in a shared multi-org Shipit instance can inject fabricated CI-passing statuses (or push/check_suite triggers) against commits/stacks belonging to a different organization's repository, potentially causing an unauthorized merge or deploy in a repository they do not own and were never granted access to. This matches the "cross-repository writes" / "unauthorized deploy, rollback or merge" impact tier.

### Likelihood Explanation
Exploitation requires only knowledge of the `webhook_secret` for one organization already configured in `Shipit.secrets.github` (a routine, low-privilege credential an org's own GitHub App administrator legitimately possesses) plus knowledge/guessing of a target commit SHA tracked by another stack on the same Shipit deployment (obtainable via the public GitHub commit history of the victim repo, or via Shipit's own commit/stack UI if readable). No Shipit session, `ApiClient` token, or GitHub repository write access is needed — only the ability to POST a crafted, self-signed payload to the shared `/webhooks` endpoint. This is realistic specifically in the documented multi-organization deployment mode.

### Recommendation
After signature verification succeeds, re-derive the trusted organization from the record that will actually be written (the resolved `Repository`/`Stack`), and reject the webhook if it does not match the organization whose key verified the signature. Concretely:
- In `Handlers::Handler#stacks`, ensure the resolved `Repository#owner` equals the `repository_owner` used to verify the signature (pass it through from the controller), and drop the event otherwise.
- In `StatusHandler#process`, scope `Commit.where(sha: ...)` by `stacks` (as already computed from the trusted repository) rather than by a bare, repository-agnostic SHA lookup.

### Proof of Concept
Preconditions: Shipit instance configured for two organizations, `org-attacker` and `victim-org` (per `docs/setup.md` multi-org setup), each with distinct `webhook_secret`. Attacker administers `org-attacker`'s GitHub App/webhook settings and thus knows `org-attacker`'s `webhook_secret`. Attacker knows a commit SHA `S` belonging to a stack tracked under `victim-org/victim-repo`.

1. Attacker builds JSON body:
```json
{
  "repository": {"owner": {"login": "org-attacker"}, "full_name": "org-attacker/whatever"},
  "sha": "S",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged"
}
```
2. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org-attacker_webhook_secret, body)>`.
3. Attacker POSTs to `/webhooks` with header `X-Github-Event: status`.
4. `verify_signature` resolves `Shipit.github(organization: "org-attacker")`, verifies successfully (signature matches `org-attacker`'s secret), and processing proceeds.
5. `StatusHandler#process` executes `Commit.where(sha: "S")`, finds the commit under `victim-org/victim-repo`, and calls `create_status_from_github!`, creating a `success` `Status` for context `ci/required-check` on `victim-org`'s commit — despite the attacker never having any credential for `victim-org`.

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
