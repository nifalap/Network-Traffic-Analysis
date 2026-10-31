# Network Traffic Analysis

Three malware investigations I did in Wireshark using pcaps from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html). That site posts traffic from real infections for practice. For each one I wrote an incident report like I would in a SOC: who got infected, how it happened, the C2, IOCs, and what I'd do about it.

After writing each report I checked it against the site's answer key.

## Reports

1. [NetSupport RAT](investigations/01-netsupport-rat/report.md): started with a single SIEM alert for a RAT and had to find the infected machine and user.
2. [Fake Google Authenticator download](investigations/02-fake-authenticator/report.md): the user searched for Google Authenticator and got malware from a fake site. I traced it from the search to the C2 servers.
3. [Fake browser update](investigations/03-fake-browser-update/report.md): got a list of IDS alerts. Most were noise, a few were real. A hacked website pushed a fake Edge update that installed NetSupport RAT.

## What I got out of it

- Finding the hostname, MAC, user account and even the user's full name just from network traffic (DHCP, NBNS, Kerberos, LDAP, SAMR)
- Spotting beaconing. The infected hosts called home about once a minute, which stands out once you look at the timestamps.
- In two of these the RAT sent plain HTTP over port 443, which is an easy thing to alert on
- Building a timeline from DNS and TLS SNI when everything is encrypted
- Not trusting every IDS alert. In #3 most of the 19 alerts were normal Windows/AD traffic.

The filters I ended up using a lot are in [wireshark-filters.md](wireshark-filters.md).

I only looked at the pcaps and didn't export or run any of the malware. The pcaps aren't in this repo.
