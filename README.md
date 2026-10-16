# Internal-Security-Logs-Analysis
Finding data exfiltration in 20 days of logs using network traffic investigation, threat detection, and evidence-based reporting
<hr />

# Summary

This challenge involved investigating potentially malicious activity within a simulated enterprise environment using **authentication records**, **firewall logs**, and an **asset inventory**. The objective was to find, distinguish, and calculate the motives of the suspicious behavior **hidden** inside all these logs, **distinguishing** it from legitimate administrative or operational activity, **correlating** these events across available data sources, and documenting the hypothesis and conclusion in an actionable **technical + tactical threat intelligence report** without exaggerating the evidence.


For your curiosity, the logs I used are available for viewing and download on this repository. Feel free to attempt this challenge yourself!

<hr />
<br />

# Provided Data

| Data Source Name       | Purpose        |
|------------|------------|
| Asset Inventory      | Written host roles of expected behavior and identifies authorized activity.  |
| Firewall Logs        | Logged allowed and denied connections, destination services, traffic volumes, and timing patterns.   |
| Authentication Events | Logged time of authentication, successful and failed logins, and Country login locations. |

No other logs were provided. With how large this investigation ended up turning out, it's safe to say this was not enough logs to fully complete the investigation and confirm the exfiltration. <br />
**But, strength in traffic analysis is in knowing how much data you have to work with, and knowing where your limits are based on the provided information you have!**

<br /> <br />

Now, let's get into the analysis!

# My Investigative Approach

My investigation followed a very hypothesis-driven approach. Rather than instantly treating every unusual event as malicious, each lead was evaluated using the following sequence I created:

1. **Observe**: Record what the logs directly establish.

2. **Contextualize**: Compare the observation with known assets, expected activity, and other records.

3. **Hypothesize**: Develop a plausible explanation for the observed behavior.

4. **Correlate**: Search for related events across different log sources and time windows.

4.5. **Contradiction**: Combine with Correlate. Consider contradictory sources and determine whether this still distinguishes them as malicious.

5. **Assess**: State what is supported, what remains uncertain, and what additional evidence is needed.

This **approach** helped structure my observations and starting leads, and prevented individual anomalies from being concluded as a definitive proof of compromise.

## Observe

The first step was to understand what normal activity looked like within this supplied data.

Authentication records showed that accounts normally authenticated from Canadian IP addresses, including sources in the `99.240–250.*` range. This provided a useful comparison when examining successful logins from unfamiliar geographic locations.

The asset inventory also documented an internal vulnerability scanner, `SEC-SCAN-01` (`10.20.30.50`), authorized to scan clinical workstations, kiosks, and servers on Mondays and Fridays between `22:00` and `00:00`, running every 3-4 days. 

<br />

These observations provided context for evaluating anomalies. However, previously observed IP ranges were only treated as a baseline of expected behavior. Geographic location by itself cannot determine whether a login was legitimate or not.

## Contextualize

Two accounts warranted further examination.

### Account: `p.singh`

The authentication events contained successful logins from the account's usual Canadian sources, as well as two successful logins from Belizean IP address `209.126.162.16` on **September 14** at `02:14:45` and `02:16:03`.

The unfamiliar location and successful authentication made this activity suspicious. Because the account also historically had successful logins from its usual sources, the observations raised the possibility of concurrent legitimate use and/or unauthorized account use.

<hr />

### Account: `c.yamamoto`

The authentication events showed successful authentication from Canadian sources before successful logins from the Netherlands, beginning September 16 at 11:07, associated with 145.53.245.66. Further successful logins from the Netherlands were observed through September 19.

<hr />

### My Interpretation: 

The observed change in geography locations should warrant an investigation, especially in the context of other suspicious activity in the environment. <br />
But just by itself, it holds no indicator of account compromise or misuse.

**Both accounts presented authentication anomalies consistent with possible credential misuse. But neither geographic inconsistency alone nor a successful login from an unfamiliar location can prove that an account had been compromised. This only tells us that the geographic location changed.** <br />

Travelling, VPN routing, legitimate remote access, and other explanations would need to be considered too.

## Correlating This to Other Events

The next lead was the internal address `10.20.40.70` in the firewall logs, which began silently probing internal services on **September 14** at approximately `02:32:33`. <br />
But wait, doesn't this align with the similar authentication timestamp as `p.singh`, who logged in from Belize on the same day, and the **same hour**? 

<br />

This combination was more informative than an isolated denied connection.

The firewall records included denied attempts involving **RDP (3389), RPC (135), and SSH (22), alongside allowed SMB (445) connections**. The probing lasted from `2:32:33` to `3:05:29`, late at night.

The pattern suggested an attempt to silently discover reachable internal services, followed by communication with a file server.

The allowed **SMB connections** was to a server at `10.20.20.11`. <br />
The asset inventory identified `10.20.20.11`, named `FS-CLIN-01`, as a **data-centre file server** hosting a clinical records share. This increased the potential significance of the **SMB** activity. <br /> <br />

**Contradictory sources:** The relationship between `10.20.40.70` and either suspicious user account could not be established from the available records alone. Although the timing was suggestive, the investigation lacked access to **VPN session records**, which could map authenticated users to assigned internal addresses.

Regardless, this was not normalized **expected** behavior, so the source should be treated as suspicious.

### Continuing the Correlation

Continuing to investigate SMB activity, the firewall recorded 15 allowed SMB connections from `10.20.40.70` to `FS-CLIN-01` between September 14 at `02:32:40` and `03:05:29`.

Across these records, the logged totals were:

* `bytes_received: 16,740,818 bytes`, approximately 16.7 MB.
* `bytes_sent: 234,603 bytes`, approximately 0.23 MB.

The allowed connections established that SMB communication was permitted between the source and the file server during the observed period. The destination's role made the activity important to investigate.

However, this only tells us the amount of bytes exchanged and received. It doesn't tell us:

1. **Which** files, if any, were opened,
2. **Whether** authentication succeeded at the SMB application layer,
3. **Or whether** the transfer involved sensitive data.

<br />

The precise meaning of the `sent` and `received` bytes must also be interpreted by the logging system's understanding, too.

So to validate the hypothesis, the next step would be to examine the file-server authentication records, SMB session logs, file-access auditing, and relevant endpoints involved. <br /> <br />

**Which we don't have.** <br />

But wait, there's more!

## External Communications

A subsequent lead was recurring outbound traffic from FS-CLIN-01 to external IP address 45.147.210.18 over TCP port 8443.

The supplied records showed:

First observed: September 15 at 01:05:00.

Last observed: September 20 at 23:59:56.167.

Total allowed connections: 2,145.

Median interval between connections: Unpredictable, approximately 3-6 minutes between a certain number of connections, before multiple hours of inactivity.

Total logged bytes sent: 2,452,210.

Total logged bytes received: 1,279,698.

In the context of the earlier suspicious activity, this became a reasonable hypothesis to investigate.
The appropriate next step would be to identify the process responsible, validate the external destination against approved services, and compare the traffic with the server's normal behavior.

The same file server also generated 35 allowed outbound TCP/443 connections to 45.148.204.78 between September 18 at `01:20:38` and September 20 at `02:56:49`.

The records contained a total of 171,902,186 bytes sent, approximately 171.9 MB, and 189,405 bytes received.

The outbound traffic remained worthy of investigation because it originated from a file server hosting a clinical records share and targeted an external address during a period that also contained suspicious authentication and network activity.
