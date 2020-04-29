This repo is organized as calm-dsl for source control. The product json bluepint is stored in the 'blueprint' folder.

Purpose:

To demonstrate automation of a simple Protection Domain strategy and self-service actions via Calm. The blueprint features user-selectable remote retention policies. It maps each VM to a Protection Domains with a 1:1 placement. The Protection Domain name is equal to the Calm Application name and, due to this, the application name must adhere to Protection Domain naming conventions (for example, no spaces are allowed). Each Protection Domain is created using a once per 24hr schedule. The "Local" backup type creates a local Protection Domain only, also with a 24 hour schedule. This schedule exists to prevent a Protection Domain alert, while still enabling self-service out-of-band snapshot support.

Day 2 Actions:

- Create Snapshot
- List Snapshots
- Restore Last Snapshot

Requirements and Assumptions:

- Source and Target clusters are registered to the same Prism Central.
- API user is configured on Prism Central.
- Remote Site has been configured and tested on Source and Target.
- Remote Site name must equal the target cluster name.

Configuration:

- Edit the 'remote_protection_domain_cluster' Application Profile variable.
- Populate the correct credentials for the Prism Central API.
- Populate the correct credentials for the user VM.

Areas for Improvement:

- Choose a specific snapshot via drop-down (possible in future Calm release).
- New action to change the backup type post-launch.
