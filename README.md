# Kerb-Canary
A powershell script to enumerate logon sessions for Kerberos tickets with abnormal time-to-live(TTL) or commonly exploited weak ciphers (RC4) and then report on them through various means. The script also has the ability to purge any logon sessions detected with either of the above attributes.

Since this script needs a high level of administrative access to use WMI/Klist functions, it's best run from a scheduled task with local system authority. It can however be run interactively by a local user.
