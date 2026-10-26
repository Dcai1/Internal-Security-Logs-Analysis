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
**But, I believe that true strength in traffic analysis, is in knowing how much data you have to work with, and knowing where your limits are based on the provided information you have!**

<br /> <br />

Now, let's get into the analysis!

# My Investigative Approach

<hr />

My investigation followed a very hypothesis-driven approach. Rather than instantly treating every unusual event as malicious, each lead was evaluated using the following sequence I created:

1. **Observe**: Record what the logs directly establish.

2. **Contextualize**: Compare the observation with known assets, expected activity, and other records.

3. **Hypothesize**: Develop a plausible explanation for the observed behavior.

4. **Correlate**: Search for related events across different log sources and time windows.

4.5. **Contradiction**: Combine with Correlate. Consider contradictory sources and determine whether this still distinguishes them as malicious.

5. **Assess**: State what is supported, what remains uncertain, and what additional evidence is needed.

This **approach** helped structure my observations and starting leads, and prevented individual anomalies from being concluded as a definitive proof of compromise.

<hr />
<br />

## Observe

The first step was to understand what normal activity looked like within this supplied data.

The authentication records showed that accounts normally authenticated from Canadian IP addresses, including sources in the `99.240–250.*` IP range. This provided a useful comparison when examining successful logins from unfamiliar geographic locations.

The asset inventory also documented an internal vulnerability scanner, `SEC-SCAN-01` (`10.20.30.50`), authorized to scan clinical workstations, kiosks, and servers on Mondays and Fridays between `22:00` and `00:00`, running every 3-4 days. 

<br />

I treated this simply as normal traffic observations. They give me a baseline for evaluating potential anomalous behavior, since geographic location by itself cannot determine whether a login was anomalous or not. 

<br />
<br />

But while observing this, I found some suspicious login patterns:

<br />

## Contextualize

Two accounts warranted further examination.

<hr />

### Account: `p.singh`

The authentication events contained successful logins from the account's usual Canadian sources, as well as two successful logins from Belizean IP address `209.126.162.16` on **September 14** at `02:14:45` and `02:16:03`.

The unfamiliar location and successful authentication made this activity suspicious. Because the account also historically had successful logins from its usual sources, these observations raised the possibility of unauthorized account use.

<hr />

### Account: `c.yamamoto`

The authentication events showed successful authentication from Canadian sources before successful logins from the Netherlands, beginning September 16 at 11:07, associated with 145.53.245.66. Further successful logins from the Netherlands were observed through September 19.

<hr />

### My Interpretation Of This: 

<hr />

The observed change in geography locations should warrant an investigation. But just by itself, it holds no indicator of account compromise or misuse. <br />
Travelling, VPN routing, legitimate remote access, and other explanations would need to be considered too. 

<hr />

<br />

But this is a great starting point. Let's dig in further by analyzing the other log file, the **firewall logs**.

<br />

## Correlating This to Other Events

The next lead was the internal address `10.20.40.70` in the firewall logs, which began silently probing internal services on **September 14** at approximately `02:32:33`. <br />
But wait, doesn't this align with the similar authentication timestamp as `p.singh`, who logged in from Belize on the same day, and the **same hour**? 

<br />

### My Interpretation Of This: 

<hr />

This correlation was more informative than anything else here, and it lines up with the previous suspicious login timestamps.

The firewall records included denied attempts involving sensitive ports like **RDP (3389), SSH (22), SMB (445) connections,** and more. The probing slowly lasted from `2:32:33` to `3:05:29`, late at night. They tried to be as stealthy as possible.

The pattern suggested an attempt to silently discover reachable internal services, with **SMB** connections successful to a file server, followed by communication to that file server.

The allowed **SMB connections** was to a server at `10.20.20.11`. <br />
The asset inventory identified `10.20.20.11`, named `FS-CLIN-01`, as a **data-centre file server** hosting a clinical records share. This increased the potential significance of the **SMB** activity. <br /> <br />

**Contradictory sources:** The normal relationships between `10.20.40.70` and either suspicious user accounts could not be established from the available records alone. Although the timing was suggestive, the investigation lacked access to **VPN session records**, which could map authenticated users to assigned internal addresses. <br />
In other words, we don't have an idea of what **normal behavior** looks like for this file server.

Regardless, this was not normalized **expected** behavior, and since the timing **aligns** with the suspicious authentication from Belize, the source should definitely be treated as suspicious.

<hr />
<br />

### Continuing the Correlation

Continuing to investigate SMB activity, the firewall recorded 15 allowed SMB connections from `10.20.40.70` to `FS-CLIN-01` between September 14 at `02:32:40` and `03:05:29`.

Across these records, the logged totals were:

* `bytes_received: 16,740,818 bytes`, approximately 16.7 MB.
* `bytes_sent: 234,603 bytes`, approximately 0.23 MB.

The allowed connections established that SMB communication was permitted between the source and the file server during the observed period. The destination's role made the activity important to investigate.

### My Interpretation Of This: 

<hr />

This only tells us the amount of bytes exchanged and received. It doesn't tell us:

1. **Which** files, if any, were opened,
2. **Whether** authentication succeeded at the SMB layer,
3. **Or whether** the transfer involved sensitive data.

<hr />

<br />

So to validate the hypothesis, the next step would be to examine the file-server authentication records, SMB session logs, file-access auditing, and relevant endpoints involved. <br /> <br />

**Which we don't have.** <br />

But wait, there's more!

<br />

## External Communications

### Observation

A subsequent lead was recurring outbound traffic from FS-CLIN-01 to external IP address 45.147.210.18 over TCP port 8443.

The total supplied records showed:

**First observed:** `September 15` at `01:05:00.`

**Last observed:** `September 20` at `23:59:56.167`.

**Total allowed connections:** `2,145`.

**Observed Interval between connections:** Unpredictable, approximately `180-360 seconds` between a certain number of connections, before multiple hours of inactivity, likely until the next midnight.

**Total logged bytes sent:** `2,452,210`.

**Total logged bytes received:** `1,279,698`.

### My Interpretation Of This: 

<hr />

In the correlation of the earlier suspicious activity, this became a reasonable hypothesis to document and start an investigation.
The appropriate next step would be to dig deeper and identify the process responsible, validate the external destination against approved services, and compare the traffic with the server's normal behavior. 

<br />

**Again, we don't have the information required to do this.**

The same file server also generated 35 allowed outbound TCP/443 connections to 45.148.204.78 between September 18 at `01:20:38` and September 20 at `02:56:49`.

The records contained a total of 171,902,186 bytes sent, approximately 171.9 MB, and 189,405 bytes received.

The outbound traffic remained worthy of investigation because it originated from a file server hosting a clinical records share and targeted an external address during a period that also contained suspicious authentication and network activity.

<hr />

## Assess

### The Final Step

We've analyzed the two provided log files given to us, the `authentication logs` and the `firewall logs`. We established a baseline for normal traffic and identified all the anomalous traffic located in the system. 

<br />

But as seen in the previous explanations, there isn't enough information provided for us to fully come to a conclusion of whether or not sensitive files were exfiltrated. <br /> <br />


This is the best we could do with the provided information. But even **this** is a handful. Someone taking over this investigation will already have all the information they need.

<br />

With all the observations acquired from this analysis, these are the key findings:

<hr />

1. Normal authentication traffic expects a VPN session authentication under IP ranges `99.240-250.*` and in the CA country.
2. 2 suspicious authenications from a different IP range, and different countries were observed
3. Suspected probing from an IP address unlisted in the asset inventory was observed near midnight, shortly after a suspicious authentication succeeded
4. The suspected probing scanned for multiple vulnerable ports on many assets listed in the asset inventory
5. A vulnerable port (SMB) was found on a file server holding medical records, followed by suspected exploitation
6. Communications from that file server begins outbound connections to an IP unlisted in the asset table, over the span of multiple days before beginning data exfiltration
7. 191,902,186 Bytes were sent to that outbound IP connection between September 18-20. 189,405 Bytes were received.
8. The logs end here.

<hr />
<br />

## Conclusion

From **analyzing**, **correlating**, **contradicting** events listed in the provided log files and utilizing a calm, non-biased **log analysis** mindset, a viable hypothesis of suspected data exfiltration was created. <br /> <br />

While it's a shame that there was not enougn provided information to complete the investigation single-handedly and come to a conclusion, there was still enough information to locate suspicious activities and correlate them to other events with a combination of the other logs.

<br />

With our current findings now finalized, the next action would be **transforming this into documentation and threat intelligence**, leading to **actionable** insight.
