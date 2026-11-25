# Start here: the lawyer's guide

## 1. Pick the right link

- **Trying the demo?** Use only the invented sample. A link starting with http://127.0.0.1 works only on the computer running it. Do not send it to a client or upload a real document.
- **Setting up your firm?** Give your technologist or coding assistant the [build instructions](docs/BUILD-WITH-YOUR-AI.md). Ask for a private test link, a counsel login, and a second test login. Have them complete the [Azure checks](docs/AZURE-SETUP.md) or the equivalent on your host. A sign-in screen by itself is not a green light.

## What you need before you start

- An AI coding assistant you can use with a project folder and a terminal, or a developer. You do not need model API keys to run the portal.
- A firm-controlled Azure subscription with billing and an administrator authorized to create an app, private storage, and permissions, or an equivalent hosting setup. The Azure route uses a Function app with host/deployment storage and separately secured Blob storage for portal data. Plan for a protected secret store, backups, and cost alerts.
- A computer you control that can keep the independent file scanner running and contact the portal, or an approved managed scanner. You do not need a separate Azure VM for the office-scanner design. If the scanner goes offline, uploads wait in quarantine.
- A private project folder or private repository for your own configuration. A GitHub account is convenient, not necessary to read a public repository. You can start with your host's HTTPS address; a custom domain is optional.

### What to ask your AI to do

Point your coding assistant at a local copy of the code and ask it to follow **docs/BUILD-WITH-YOUR-AI.md** in order. Give it the fictional example, your preferred cloud region, your approved testing network, and a budget ceiling. Ask it to (1) run the demo, (2) show you the proposed Azure resources and costs before buying anything, (3) stage using fictional data, and (4) produce a signed-off checklist before you send a link. Do not give the AI raw passwords, case documents, or access to your real inbox or matter records for this setup. Use your approved credential workflow when Azure requires sign-in.

### Rough Azure budget

For a low-volume pilot, start with a **USD $5–$20 per month planning allowance**, not a price quote or cap. Example assumptions: U.S. pay-as-you-go, Flex Consumption on demand, zero Always Ready instances, fewer than 20,000 requests in a month, roughly half a second each at 2 GiB, 1–5 GB of stored data, light traffic and logs, and a scanner on equipment you already own. That example is about 20,000 GB-seconds. Microsoft's published eligible monthly Flex grant is 100,000 GB-seconds and 250,000 executions per subscription, shared across its eligible apps. Even when execution falls within the grant, storage, operations, logs, secrets, backups, and data transfer can still cost money. Plans, region, traffic, retries and retention can change the bill. This estimate excludes domain registration, AI subscriptions, paid scanning/VMs, professional time and taxes. Enter your actual assumptions in the [Azure pricing calculator](https://azure.microsoft.com/en-us/pricing/calculator/), review [Functions pricing](https://azure.microsoft.com/en-us/pricing/details/functions/), and set a budget alert before deploying. An alert does not stop charges.

## 2. Set up a matter

1. Sign in as counsel. Select **Create a new intake**.
2. Give the matter a name. Create a separate username and password for the first person. Do not reuse your counsel login or anyone else's password. Creating the matter does not send an invitation.
3. For a short set, enter requests individually. For a prepared set, select **Load prepared requests (JSON)** and paste the file contents. Ask your technologist or approved coding assistant to prepare the file using the fictional sample format. Keep real discovery out of unapproved AI tools. Check that the original numbers and wording were preserved, each request is in the right group, and the exact definitions are separate from their plain-English explanations.
4. By default, do **not** assign every request to the first person. Leave that box unchecked unless that person should see the entire set. Select **Create intake**. Then use **Add respondent** for each additional person, and **Assign the same request** to assign an existing item to each person who should see it. Check **Assigned to** in the counsel view. A person without assignments should see none.
5. Do not give a respondent the counsel credentials. Keep passwords out of notes, pleadings, and shared tracking files.

## 3. Test before anyone uses it

Do this on a fictional intake from a separate browser profile, private window, or device; a second tab in the same browser profile may share the counsel session.

- Sign in as a sample respondent. Check that the person cannot see any other matter or anyone else's assignments.
- Open **Interrogatories**, **Requests for Production**, and **Requests for Admission** in any order. Make sure a sample defined term has both its exact definition and an explanation.
- Send an answer before completing the other requests. Refresh or sign back in and look for the submitted answer. In counsel's view, verify the same answer is actually there.
- Upload a fictional file. It should say it is pending a security check; counsel should not be able to download it yet. After clearance, check that **Download original** gives you the same file.
- Use **Revoke access** on the sample login. Confirm that its open session stops working and that it cannot sign back in. Have your operator confirm the backup restore drill and test the approved link from a separate network before you use it for a real matter.

## 4. Invite the person yourself

Only after the operator confirms the real deployment is ready and you have reviewed assignments:

- Send your approved **HTTPS** portal link and the person's username. Send a password by a separate approved channel if possible. Do not send a localhost or test link.
- Tell them: “This is a way to send information privately to me for review. Nothing you enter is a final discovery response. You can work in any order, ask me for clarification here, and return later. Please do not forward your login or paste our communications into a chatbot.”
- Verify the recipient and how they are communicating with you. A person receiving a login does not make their input privileged.

## 5. Review what came back

- In **Counsel workspace**, open the matter. Review answers, follow-ups, and cleared files under the matching request. An interrogatory can have supporting documents, but they are optional. For production requests, **still searching**, **cannot find**, and **never existed** mean different things; don't treat them as interchangeable.
- **Draft saved** means not sent. **Submitted** means the response was sent to counsel's portal. **Pending security check** means the file arrived but cannot be downloaded. If it stays pending, ask the operator to check the scanner; do not ask the respondent to route the file around quarantine.
- Use **Add a request or follow-up question** for missing facts or records. Review for responsiveness, privilege, and completeness before anything is served. No button in this kit files, serves, or emails a formal response.
- When access is no longer needed, use **Revoke access**. That ends access without deleting the record.

**If you get stuck:** Check that you are on the correct HTTPS link, in the right role, and on the right matter. For a failed upload, check the file type, size, and the error message. For sign-in or missing data, stop and contact your operator; do not open access or bypass security to finish a test.

[What this system does and does not protect](docs/WHITE-PAPER.md) · [Technical build instructions](docs/BUILD-WITH-YOUR-AI.md)
