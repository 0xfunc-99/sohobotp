# Extra MSI tables (added by build-msi.sh with msibuild; wixl cannot author them)

`SaveToken` (CustomAction type 11282 = 2 exe + 16 installed file + 1024 deferred
+ 2048 no impersonation, i.e. SYSTEM + 8192 HideTarget) runs
`sohobotp-agent.exe save-token "[TOKEN]"` between InstallServices and StartServices, only
when TOKEN is set and the product is not being removed. HideTarget keeps the command line
(and so the token) out of the installer log; MsiHiddenProperties hides TOKEN in the property
dump and the logged command line. The token is stored in the agent's state folder (SYSTEM
and Administrators only), not in HKLM\SOFTWARE, which every user can read.
