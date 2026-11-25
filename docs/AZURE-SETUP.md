# An Azure reference setup for a private discovery portal

This is general deployment guidance for a small firm, not a turnkey deployment of the sample. The starter is a loopback-only learning tool. **Do not expose it to the internet.** A cloud implementation needs a reviewed production application with persistent identities, storage, and a scanner. Use invented requests and files until the complete system has passed your firm's review.

## What to hand your operator

In the portable source template, start in **azure-runtime**. Use a fresh virtual environment for the supported Python version, install the listed requirements, and run the tests on invented material. Seed a fresh state file with:

    python seed.py --username your-counsel-user --origin https://your-dedicated-host.example --out intake-v2.state --fictional-sample

The seed prompts for distinct test passwords. Keep the resulting encrypted state file and its key private and separate. Use the runtime's separate worker secret, the exact HTTPS origin and Blob account URL, and your own private container names. The included config module defines and validates those settings. Name the initial state blob **intake-v2.state** in the configured state container. Build an allowlisted runtime ZIP, then deploy only that ZIP:

    python build-azure-zip.py discovery-runtime.zip

For Azure, do not set the deployed app's origin to localhost. If cookie reserialization affects your dedicated Azure hostname, use only the documented exact-host staging option and confirm the behavior with a real browser. Keep host-only cookies as your default elsewhere.

## A small staging setup

1. **Give staging its own resource group and hostname.** Create a Linux Azure Functions app on Flex Consumption, using a supported Python runtime that matches the build. Enable HTTPS only. Start with request access denied by default and allow only your testers or your private network. Confirm IPv4 and IPv6 behavior if you use IP rules, and restrict the separate deployment endpoint as well. IP restrictions supplement application sign-in; they do not replace it. [Flex setup](https://learn.microsoft.com/en-us/azure/azure-functions/flex-consumption-how-to) · [App Service access restrictions](https://learn.microsoft.com/en-us/azure/app-service/app-service-ip-restrictions)
2. **Separate Azure's runtime storage from the firm's data.** Functions needs its own host/deployment storage with the authentication configured for that plan. Create a different Blob Storage account for application state and original documents. Disable anonymous blob access for firm data and avoid shared keys for the data account when using Entra ID. Use private containers for state and quarantine. Lock down the network separately, according to how the Function app and recovery operators reach it. [Functions connections](https://learn.microsoft.com/en-us/azure/azure-functions/manage-connections) · [Storage security](https://learn.microsoft.com/en-us/azure/storage/common/secure-storage)
3. **Give each component only what it needs.** Turn on the app's managed identity and assign Blob data roles on the specific containers it needs, not across the whole subscription. Keep release or scanner access separate from ordinary app accounts. Store application secrets and key material in a protected secret store such as Key Vault; use the identity and Key Vault references where supported, and specify who can recover or rotate them. Never put secrets in Git, deploy archives, sample files or prompts. [Container-scoped data roles](https://learn.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-access) · [Key Vault references](https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references)
4. **Use the right persistence and scanning boundaries.** Store encrypted state and originals separately. A small pilot may use conditional Blob writes with version checks; a busier installation should use a transactional database for assignments, answers, and audit records. Receive a file into quarantine before scanning. A separately authenticated scanner can poll outbound from an office machine, so you do not need to open the scanner to the internet. Keep signatures current, bind each verdict to that exact original, deny downloads while pending or if the scanner fails, and allow only authorized counsel to retrieve a cleared original. Do not bundle scanner binaries with the starter. [ClamAV documentation](https://docs.clamav.net/)
5. **Deploy application code only.** Build an allowlisted archive with the app entry point and host configuration at the archive root, plus dependencies and web assets. For Flex, use the supported package deployment path and remote build when compatible with your runtime. Give the runtime read access to files *inside* the archive; you can still keep the archive itself private. Do not package case data, passwords, runtime storage, or local configuration. Confirm Azure discovers the running function; a CLI success or a completed upload alone is not proof. [Package deployment](https://learn.microsoft.com/en-us/azure/azure-functions/deployment-zip-push)
6. **Verify what a respondent actually sees.** Check that login persists across multiple requests, including after a page refresh. Inspect the actual HTTPS response to make sure the hosting adapter preserved cookie attributes, and test with a real browser and separate accounts. Keep sensitive responses out of logs and notifications. Verify the respondent cannot see another matter or another person's assignments, and confirm revocation invalidates that person's existing sessions.

## What makes the setup defensible

Document the choices that you could explain and demonstrate later, not just the service names in the architecture diagram:

- **Who can see what.** Keep a record of who instructed the respondent to use the portal, which matter and requests the person could see, and when access was granted or revoked. Use separate accounts and test what each actually sees.
- **What happened to the original.** Record the receipt, original-file digest, quarantine decision, and authorized retrieval without putting case content in ordinary operational logs. Preserve exact bytes and metadata; do not convert a scan verdict into a claim that a document is authentic or relevant.
- **What left the system.** Keep model calls, analytics, and external notifications away from client content by default. In the basic respondent workflow, no issue text, provisional answer, or document is sent to a model. A separately approved counsel-side AI workflow needs its own data-flow review and vendor terms.
- **What a failed check does.** Demonstrate that no one can download a pending file, a respondent cannot access another person's assignments, and revoking access ends the existing session. Keep the test results and the configuration of the build tested. Recheck after a meaningful change.

Those are verifiable features, not a legal conclusion about particular communications or documents. Have counsel evaluate privilege and disclosure in the actual matter.

## Before any client data

Use a fictional matter to prove all three request types, preserved source wording, optional supporting files, durable answer receipt, failure-closed quarantine, and exact original retrieval. Test revocation and restore an encrypted backup into a fresh private environment. Confirm the restored snapshot and document objects are coherent and that recovery does not reinstate revoked access. Configure cost alerts, retention and holds, application patching, and a person or process to notice a stopped scanner. Azure's storage protections are useful but not a substitute for an actual restore drill. [Blob soft delete](https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview)

Keep staging separate from production, and do not open production access just to diagnose staging. To share the finished portal, use distinct respondent credentials, counsel-approved assignments, and a clear revocation and recovery process. A hosting provider's security features do not establish attorney-client privilege on their own.
