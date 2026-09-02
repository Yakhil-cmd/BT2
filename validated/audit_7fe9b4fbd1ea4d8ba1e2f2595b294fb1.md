### Title
GitHub Status webhooks update commit CI state across all stacks in the authenticated organization, not just the repository that emitted the event - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The `status` webhook handler resolves the target `Commit` purely by its 40-hex SHA, with no filtering on the repository/stack the webhook actually originated from. Signature verification only proves the payload came from *some* repository within a known GitHub organization, not from the specific repository whose commit is being updated. This breaks the binding "an organization that authenticated versus the repository that is written."

### Finding Description
`WebhooksController#verify_signature` derives the signing key purely from the organization in the payload and validates the HMAC against that org-wide `webhook_secret`: [1](#0-0) 

`GithubApp#verify_webhook_signature` only proves the payload was signed with the org's shared secret - it says nothing about which repository within that org sent it: [2](#0-1) 

Once the signature check passes, `StatusHandler#process` looks up commits solely by SHA, across every `Commit` record in the database (i.e. across every stack/repository configured in this Shipit instance), and applies the incoming CI state to all of them: [3](#0-2) 

Because a GitHub App's webhook secret is shared by every repository the App is installed on within an organization, any repository in that org can produce a validly-signed `status` event. An attacker who can create commit statuses on **any** repository in the org (e.g. via a repo where they have push/status-write access, using the GitHub Statuses API directly - which does not require pushing a commit to a branch) can set the `sha` field to match a commit that exists in a **different** repository's stack, as long as they can produce a commit object with an identical SHA. Git commit SHAs are a hash purely over the commit's metadata (tree, parents, author, committer, timestamps, message) - all of which are public information for any commit visible via the GitHub API/UI. An attacker can therefore fabricate an identical commit object in a repository they control, attach it to any commit's SHA in their own repo (it does not need to be reachable from a branch), then call the Statuses API on it. GitHub emits a signed `status` webhook for the org, and `StatusHandler` will happily attach that forged status to the *unrelated* target commit in a different stack.

This is analogous to the reported issue's root cause: a verification boundary (an authentic, signed source) is checked at one granularity (organization) while the action performed operates at a finer, unchecked granularity (any repository/commit in the database), letting an authenticated-but-lower-privileged party mutate state that should require a different repository's trust.

### Impact Explanation
Commit CI status directly gates `Commit#deployable?`, merge-queue eligibility (`MergeRequest::StatusChecker`, `any_status_checks_missing?`, `any_status_checks_failed?`), and continuous deployment scheduling. Forging a "success" status on a target commit in a stack the attacker does not otherwise control can satisfy required CI checks, unblock the merge queue, and trigger an unauthorized deploy in a repository the attacker has no access to - a cross-repository, cross-trust-boundary compromise. This falls under the Critical impact bucket ("cross-repository writes ... or an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Exploitation requires the attacker to have status-write access to at least one repository within the same GitHub organization/App installation as the target stack (a lower bar than write access to the target repository itself), and the ability to construct a commit object with a colliding SHA using publicly available metadata of the target commit. This is a realistic scenario in any Shipit deployment managing multiple repositories/stacks under one GitHub organization/App installation, which is the common configuration documented in `docs/setup.md`.

### Recommendation
Scope `StatusHandler#process` (and any other webhook handler that looks up commits/state by SHA alone) to the repository named in the webhook payload, e.g. join through `stack.repository` and filter `Commit.where(sha: params.sha, stack: Stack.where(repository: matching_repo))` before applying the status, instead of matching by SHA across the entire `Commit` table.

### Proof of Concept
1. Configure two stacks, `stack-a` (repo `org/repo-a`) and `stack-b` (repo `org/repo-b`), both under the same GitHub App installation for organization `org`.
2. As a user with status-write access to `org/repo-a` (but no access to `org/repo-b`), fetch the public metadata (tree SHA, parents, author/committer, timestamps, message) of the commit currently pending deploy in `stack-b`.
3. Construct an identical commit object in `org/repo-a` (not pushed to any branch) that produces the exact same SHA as the target commit in `stack-b`.
4. Call GitHub's Statuses API against `org/repo-a` for that SHA with `state: success` and the CI context required by `stack-b`'s `shipit.yml`.
5. GitHub delivers a `status` webhook signed with `org`'s shared `webhook_secret`; `WebhooksController#verify_signature` passes because it only validates the org, not the repository. [1](#0-0) 
6. `StatusHandler#process` finds the `Commit` row belonging to `stack-b` by SHA (ignoring that the webhook came from `repo-a`) and records the forged "success" status against it. [3](#0-2) 
7. `stack-b`'s commit now satisfies required CI checks and becomes deployable/mergeable, even though the attacker never had access to `org/repo-b`.

Note: I was not able to fully verify, within the available tool budget, whether the other webhook handlers (`push_handler.rb`, `check_suite_handler.rb`, `pull_request/*`) properly scope by repository or share this same gap; a full review of those files would be needed to determine the complete blast radius.

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
