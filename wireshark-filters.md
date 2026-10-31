# Wireshark filters I used

Starting filter for every pcap, shows web requests and HTTPS connections without the SSDP noise:
```
(http.request or tls.handshake.type eq 1) and !(ssdp)
```

Finding the victim:
```
dhcp                     hostname + MAC
nbns                     hostname
kerberos.CNameString     windows username
ldap.AttributeDescription == "givenName"    full name (worked in #3)
```
In #1 and #2 the full name wasn't in LDAP, so I used Edit > Find Packet, searched packet details for the last name, and found it in a SAMR response.

Looking at a suspicious IP or domain:
```
ip.addr == x.x.x.x
tls.handshake.extensions_server_name contains "something"
dns.qry.name == "something.com"
http.user_agent contains "NetSupport"
```

Other things that helped:
- View > Time Display Format > UTC so the times match the alerts
- Right-click a field > Apply as Column (I added CNameString and Host)
- Statistics > Conversations > IPv4 sorted by bytes. The C2 servers were near the top in #2.
