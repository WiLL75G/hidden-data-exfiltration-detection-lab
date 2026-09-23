# Hidden Data Exfiltration Detection Lab

> **2 controlled image uploads. 77 bytes of additional data. 3 detection stages. 2 custom Suricata rules. 1 detection gap investigated from baseline through tuning.**

A hands-on SOC and detection engineering investigation into what network telemetry actually reveals when additional data is carried inside an image upload.

This project was built around one question:

**If the network can see an image being uploaded, does that mean the detection stack can identify the additional data being carried with it?**

The answer from this experiment was no.

Suricata had visibility into both transfers, but the existing alert did not distinguish the modified image carrier from the clean control.

I then built and tested two detection iterations to understand the gap.

> **Main takeaway: Visibility is not the same as detection.**

---

## Architecture

![Lab Architecture](architecture/lab-architecture.png)

```text
Windows Endpoint
192.168.64.17
      |
      | HTTP POST /upload
      | TCP 8081
      v
Suricata 7.0.3
Interface: enp0s1
      |
      | Network telemetry
      | EVE JSON
      v
Ubuntu HTTP Receiver
192.168.64.12:8081
```

### Detection Workflow

```text
Clean Control
     +
Modified Carrier
       |
       v
Generate Traffic
       |
       v
Inspect Suricata Telemetry
       |
       v
Compare With Ground Truth
       |
       v
Identify Detection Gap
       |
       v
Detection V1
       |
       v
Negative + Positive Testing
       |
       v
Tune Detection
       |
       v
Detection V2
       |
       v
Validate Results
```

---

# At a Glance

| Item | Result |
|---|---|
| Clean PNG | 17,824 bytes |
| Modified carrier | 17,901 bytes |
| Difference | 77 bytes |
| Transport | HTTP POST |
| Destination | `192.168.64.12:8081` |
| Network sensor | Suricata 7.0.3 |
| Existing alert | SID `2034635` |
| Detection V1 | SID `1000010` |
| Detection V2 | SID `1000011` |
| V1 control result | ALERT |
| V1 modified result | ALERT |
| V2 control result | NO ALERT |
| V2 modified result | ALERT |

---

# Scope

This project investigates an **image carrier containing appended test data**.

It does **not** use LSB, pixel manipulation, or another image steganography algorithm.

The modified file remained a valid PNG, but the controlled payload was appended after the PNG data.

Detection V2 also uses a **known test marker**.

Therefore:

**This project does not claim to provide universal steganography detection.**

The purpose is to demonstrate a repeatable detection engineering process:

```text
Baseline
→ Generate
→ Observe
→ Compare
→ Detect
→ Test
→ Tune
→ Validate
```

---

# Investigation Question

The scenario was deliberately simple.

A normal image is uploaded over HTTP.

Then a modified copy carrying additional controlled data is uploaded through the same path.

The network sensor monitors both.

The questions were:

1. What does Suricata actually see?
2. Does existing alerting distinguish the two transfers?
3. Can a behavioral detection identify the upload?
4. Can the detection be tuned and validated against both a positive and negative sample?

---

# Lab Environment

| Component | Role |
|---|---|
| Windows endpoint | Traffic source |
| `192.168.64.17` | Windows lab IP |
| Ubuntu | Receiver and Suricata host |
| `192.168.64.12` | Ubuntu lab IP |
| TCP `8081` | HTTP receiver |
| Suricata 7.0.3 | Network monitoring and detection |
| PowerShell | Artifact preparation |
| curl | Controlled HTTP uploads |
| jq | EVE JSON investigation |

All activity was performed inside systems and network infrastructure under my control.

---

# Phase 1 — Establish the Baseline

Before modifying anything, I established normal behavior.

The clean sample was:

```text
control.png
```

Size:

```text
17,824 bytes
```

SHA256:

```text
5BC7002B5E287EC1091B040DA49434F9EB60734584BC6FAC495CFD77FCA910D7
```

The file was uploaded from Windows:

```powershell
curl.exe -X POST --data-binary "@C:\StegoLab\control.png" -H "Content-Type: image/png" http://192.168.64.12:8081/upload
```

The receiver returned:

```text
OK
```

The SHA256 of the received object matched the source.

This established:

- a known clean sample
- a known transfer path
- a known file size
- a known hash
- baseline network telemetry

![Baseline Transfer](evidence/01-baseline-control-transfer.png)

---

# Phase 2 — Create the Experimental Carrier

I created a controlled marker:

```text
STEGOLAB_TEST_MARKER_2026
```

The marker was added to a copy of the PNG as appended ASCII data.

The resulting artifact was:

```text
stego.png
```

Size:

```text
17,901 bytes
```

SHA256:

```text
BEC85B9965F2B109793D7540933E2AA24CEA8F7721360A260213BD535EF4F50F
```

The size difference was:

```text
17,901 - 17,824 = 77 bytes
```

The modified carrier still rendered as an image.

### Ground Truth

The known marker gave me something deterministic to validate later.

Instead of assuming the additional data survived the transfer, I could prove it.

---

# Phase 3 — Transfer the Modified Carrier

The modified image followed the same path:

```powershell
curl.exe -X POST --data-binary "@C:\StegoLab\stego.png" -H "Content-Type: image/png" http://192.168.64.12:8081/upload
```

Response:

```text
OK
```

The receiver recorded:

```text
17,901 bytes
```

The received SHA256 matched the Windows source.

I then searched the received object for the controlled marker:

```bash
grep -a -o 'STEGOLAB_TEST_MARKER_2026' ~/stego-exfil-lab/uploads/control_received.png
```

Result:

```text
STEGOLAB_TEST_MARKER_2026
```

This closed the ground-truth loop.

```text
Marker created
      ↓
Added to carrier
      ↓
HTTP transfer
      ↓
Received object
      ↓
SHA256 matched
      ↓
Marker recovered
```

The additional test data had crossed the monitored network intact.

![Modified Carrier Transfer](evidence/02-modified-carrier-transfer.png)

---

# Phase 4 — Inspect the Network Telemetry

Suricata recorded both transactions as HTTP.

## Control

```text
Source:       192.168.64.17
Destination:  192.168.64.12:8081
Method:       POST
URI:          /upload
User Agent:   curl/8.21.0
File Size:    17,824 bytes
HTTP Status:  200
```

## Modified Carrier

```text
Source:       192.168.64.17
Destination:  192.168.64.12:8081
Method:       POST
URI:          /upload
User Agent:   curl/8.21.0
File Size:    17,901 bytes
HTTP Status:  200
```

The file size differed by exactly:

```text
77 bytes
```

The flow bytes to the server also differed by:

```text
77 bytes
```

This was useful evidence.

Suricata could see the difference in the transferred data.

But seeing a difference did not mean the existing detection understood its significance.

---

# Phase 5 — Existing Detection

Both transactions triggered the same existing Suricata signature:

```text
SID: 2034635
ET INFO Python BaseHTTP ServerBanner
```

The alert was associated with the Python HTTP service.

It appeared for both samples.

```text
Clean control
      ↓
SID 2034635


Modified carrier
      ↓
SID 2034635
```

The alert provided information about the server.

It did **not** distinguish the modified carrier from the clean image.

That became the detection gap.

> The sensor had visibility into the transaction, but the existing alert did not identify the experimental condition I was investigating.

![Existing Detection Comparison](evidence/03-existing-detection-comparison.png)

---

# Detection Hypothesis

My first detection hypothesis was intentionally broad:

> An HTTP POST from the Windows endpoint to the lab upload service should be detectable as upload behavior.

This was not intended to detect hidden data.

It was designed to establish whether I could reliably detect the behavior carrying it.

---

# Phase 6 — Detection V1

Detection V1 focused on the HTTP POST.

```text
SID: 1000010
LAB Possible Data Upload via HTTP POST
```

Rule:

```text
alert http 192.168.64.17 any -> 192.168.64.12 8081 (msg:"LAB Possible Data Upload via HTTP POST"; flow:established,to_server; http.method; content:"POST"; sid:1000010; rev:1;)
```

Expected:

```text
Clean control     → ALERT
Modified carrier  → ALERT
```

Actual:

```text
Clean control     → ALERT
Modified carrier  → ALERT
```

Detection V1 worked exactly as designed.

But it exposed another problem.

It detected the **transfer behavior**, not the difference between the two samples.

![Detection V1](evidence/04-detection-v1-validation.png)

---

# Detection V1 Troubleshooting

Detection V1 did not work immediately.

That became an investigation of its own.

The rule passed:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Suricata reported:

```text
Configuration provided was successfully loaded.
```

But SID `1000010` remained silent.

Instead of immediately rewriting the rule, I verified each layer.

```text
Traffic captured       → YES
HTTP parsed            → YES
Method POST            → YES
Correct source         → YES
Correct destination    → YES
Correct port           → YES
Rule syntax valid      → YES
Alert generated        → NO
```

I queried the running ruleset:

```text
Rules loaded:   51,904
Rules failed:   0
Rules skipped:  0
```

Then I checked Suricata's active default rule path.

Result:

```text
/var/lib/suricata/rules
```

I had originally written the rule to:

```text
/etc/suricata/rules/local.rules
```

But the active `local.rules` was being resolved from:

```text
/var/lib/suricata/rules/local.rules
```

### Root Cause

The rule was syntactically valid.

It was simply in the wrong rule file.

After adding SID `1000010` to the active rule path and reloading the rules:

```bash
sudo suricatasc -c reload-rules
```

Suricata returned:

```text
{"message": "done", "return": "OK"}
```

The detection then fired successfully.

### Troubleshooting Lesson

> **A valid detection rule is not necessarily an active detection rule.**

Telemetry availability, rule syntax, rule loading, and rule logic are separate things to validate.

---

# Additional Troubleshooting — Receiver Failure

During another test, Windows returned:

```text
curl: (7) Failed to connect to 192.168.64.12:8081
```

I checked the Ubuntu listener:

```bash
sudo ss -lntp | grep ':8081'
```

Nothing was listening.

The HTTP receiver had stopped.

I restarted it:

```bash
cd ~/stego-exfil-lab && python3 receiver.py
```

Uploads resumed successfully.

This was not a detection problem.

It was a service availability problem.

That distinction mattered during troubleshooting.

---

# Additional Troubleshooting — EVE JSON

During telemetry analysis, an older malformed JSON record caused `jq` parsing errors against `eve.json`.

Rather than treating the entire log as unusable, I processed the records individually and ignored malformed lines.

Example pattern:

```bash
sudo tail -n 3000 /var/log/suricata/eve.json | while IFS= read -r line; do printf '%s\n' "$line" | jq -c 'FILTER' 2>/dev/null; done
```

This allowed valid events to remain usable for the investigation.

---

# Phase 7 — Detection Tuning

Detection V1 answered one question:

**Can I detect the upload behavior?**

Yes.

But it could not answer:

**Can I distinguish my controlled modified sample from the clean control?**

```text
V1

Control   → ALERT
Modified  → ALERT
```

That became the tuning problem.

Before creating V2, I verified Suricata's HTTP request-body inspection configuration.

```text
request-body-limit: 100kb
```

The test artifacts were approximately 18 KB.

That meant the request body was within the configured inspection limit for this experiment.

---

# Phase 8 — Detection V2

Detection V2 was deliberately designed as a **lab validation rule**.

It searched the HTTP request body for the controlled marker.

```text
SID: 1000011
LAB Hidden Marker in HTTP Upload
```

Rule:

```text
alert http 192.168.64.17 any -> 192.168.64.12 8081 (msg:"LAB Hidden Marker in HTTP Upload"; flow:established,to_server; http.request_body; content:"STEGOLAB_TEST_MARKER_2026"; sid:1000011; rev:1;)
```

The objective was not to claim arbitrary hidden-data detection.

The objective was to validate whether Suricata could inspect the request body and distinguish the controlled positive sample from the negative control.

---

# Phase 9 — Negative Validation

I uploaded `control.png` again.

Expected:

```text
SID 1000011 → NO ALERT
```

Actual:

```text
SID 1000011 → NO ALERT
```

This silence was intentional.

The marker did not exist in the clean sample.

That made the clean image the negative control for Detection V2.

![Detection V2 Negative Test](evidence/05-detection-v2-negative-test.png)

### Intentional Silence Record

```text
Rule:
SID 1000011

State:
Intentionally quiet

Condition:
Clean control upload

Reason:
Known validation marker absent

Owner:
Lab analyst

Review condition:
Review if Detection V2 is changed beyond the controlled marker test
```

---

# Phase 10 — Positive Validation

I then uploaded `stego.png`.

Suricata generated:

```text
SID:        1000011
Signature:  LAB Hidden Marker in HTTP Upload
Source:     192.168.64.17
Destination:192.168.64.12:8081
Direction:  to_server
Method:     POST
File Size:  17,901 bytes
```

Result:

```text
Modified carrier → ALERT
```

The positive sample behaved as expected.

![Detection V2 Positive Test](evidence/06-detection-v2-positive-test.png)

---

# Final Results

| Sample | Size | Existing SID 2034635 | V1 SID 1000010 | V2 SID 1000011 |
|---|---:|---|---|---|
| Clean control | 17,824 B | ALERT | ALERT | NO ALERT |
| Modified carrier | 17,901 B | ALERT | ALERT | ALERT |

The investigation moved through three detection states:

```text
EXISTING DETECTION

Control  → ALERT
Modified → ALERT

Could not distinguish samples.


DETECTION V1

Control  → ALERT
Modified → ALERT

Successfully detected upload behavior.
Still could not distinguish samples.


DETECTION V2

Control  → NO ALERT
Modified → ALERT

Successfully distinguished the controlled marker test.
```

---

# Detection Tuning Summary

The most important tuning change was:

```text
V1
Detect the HTTP POST behavior
        ↓
Too broad for sample distinction
        ↓
V2
Inspect the request body for the controlled marker
```

The purpose of V2 was validation.

It demonstrated that Suricata could inspect the relevant HTTP body and match a known indicator.

It should **not** be interpreted as a production-ready hidden-data detector.

---

# Lessons Learned

## 1. Visibility does not equal detection

Suricata recorded both transfers.

That did not mean the existing detection could explain what made the modified transfer different.

## 2. An alert firing does not prove useful detection

Detection V1 worked.

But it fired on both the positive and negative samples.

The alert alone was not enough.

## 3. Controls make conclusions stronger

Without `control.png`, I could have seen SID `1000010` fire on the modified carrier and incorrectly assumed I had built a meaningful detector.

The control exposed that the rule was detecting something broader.

## 4. Negative tests deserve documentation

The absence of SID `1000011` for the clean control was expected behavior.

Intentional silence can be part of successful validation.

## 5. Ground truth comes before detection claims

I verified:

```text
Source artifact
Destination artifact
File size
SHA256
Marker recovery
Network telemetry
Positive detection
Negative detection
```

That allowed the conclusions to stay tied to evidence.

## 6. Troubleshooting should isolate layers

During this project I encountered:

```text
Artifact creation problem
Rule path problem
Receiver availability problem
JSON parsing problem
Detection tuning problem
```

They required different fixes.

Treating every failure as a detection failure would have sent the investigation in the wrong direction.

---

# What I'd Improve

This proof of concept deliberately uses a known marker.

A stronger next iteration would remove that dependency.

I would explore:

### 1. True Image Steganography

Use controlled LSB or another image steganography technique rather than appended data.

That would create a more realistic image-based hiding scenario.

### 2. HTTPS

Repeat the experiment over encrypted traffic.

This would test what network telemetry remains available when payload inspection is no longer directly possible.

### 3. Endpoint Telemetry

Add endpoint evidence around:

```text
File creation
Process execution
PowerShell activity
Network connection
Upload process
```

Then correlate endpoint and network observations.

### 4. Behavioral Detection

Instead of searching for a known marker, investigate combinations such as:

```text
Unusual destination
+
Unexpected upload process
+
Rare destination port
+
Upload volume
+
Host baseline deviation
```

### 5. Multiple Controls

Use several legitimate PNG files with different sizes.

This would make it easier to demonstrate why file-size-only detection would overfit the original samples.

### 6. Additional Positive Samples

Test different payload contents and carrier sizes.

A detection should be validated against variation rather than one artifact.

---

# Limitations

This project has several deliberate limitations.

### Not True Pixel Steganography

The controlled data was appended to the PNG.

It was not hidden inside pixel values.

### Known Marker Dependency

Detection V2 searches for:

```text
STEGOLAB_TEST_MARKER_2026
```

Unknown content would not necessarily trigger this rule.

### HTTP

The experiment used unencrypted HTTP.

HTTPS would materially change network-content visibility without decryption.

### File Size Is Not a Detector

The 77-byte difference was useful experimental evidence.

It should not become:

```text
PNG larger than 17,824 bytes = suspicious
```

Normal images vary widely in size.

### HTTP POST Is Broad

Detection V1 intentionally demonstrated this.

POST is common legitimate behavior.

A production detection would require additional context and tuning.

---

# Skills Demonstrated

This project exercised:

- SOC investigation methodology
- baseline establishment
- control testing
- hypothesis-driven investigation
- network telemetry analysis
- Suricata EVE JSON analysis
- custom Suricata detection development
- positive testing
- negative testing
- detection tuning
- rule validation
- detection troubleshooting
- service troubleshooting
- ground-truth validation
- SHA256 verification
- HTTP analysis
- documentation of intentional silence
- evidence-based reporting
- detection limitation analysis

---

# Detection Rules

The custom rules are stored in:

```text
rules/
├── detection-v1.rules
└── detection-v2.rules
```

### Detection V1

```text
alert http 192.168.64.17 any -> 192.168.64.12 8081 (msg:"LAB Possible Data Upload via HTTP POST"; flow:established,to_server; http.method; content:"POST"; sid:1000010; rev:1;)
```

### Detection V2

```text
alert http 192.168.64.17 any -> 192.168.64.12 8081 (msg:"LAB Hidden Marker in HTTP Upload"; flow:established,to_server; http.request_body; content:"STEGOLAB_TEST_MARKER_2026"; sid:1000011; rev:1;)
```

---

# Evidence

```text
evidence/
├── 01-baseline-control-transfer.png
├── 02-modified-carrier-transfer.png
├── 03-existing-detection-comparison.png
├── 04-detection-v1-validation.png
├── 05-detection-v2-negative-test.png
└── 06-detection-v2-positive-test.png
```

Every screenshot in this repository comes from the actual lab.

Generated terminal output is not used as evidence.

---

# How I Would Explain This in an Interview

> I wanted to understand the difference between network visibility and useful detection, so I built a controlled image-carrier exfiltration experiment.
>
> I established a clean PNG as my baseline, created a modified copy containing a known test marker, transferred both over the same HTTP path, and monitored them with Suricata.
>
> The existing alert fired on both transfers but only identified the Python HTTP server. My first custom detection identified the POST behavior, but the control showed that it was too broad because both samples triggered it.
>
> I then created a second lab validation rule using the known marker. The clean control remained silent and the modified sample alerted.
>
> The important lesson was not that I had created a universal steganography detector, because I hadn't. It was learning how to move from a question to ground truth, telemetry, detection, negative testing, tuning, and evidence-backed conclusions.

---

# Repository Structure

```text
hidden-data-exfiltration-detection-lab/
│
├── README.md
│
├── architecture/
│   └── lab-architecture.png
│
├── evidence/
│   ├── 01-baseline-control-transfer.png
│   ├── 02-modified-carrier-transfer.png
│   ├── 03-existing-detection-comparison.png
│   ├── 04-detection-v1-validation.png
│   ├── 05-detection-v2-negative-test.png
│   └── 06-detection-v2-positive-test.png
│
├── rules/
│   ├── detection-v1.rules
│   └── detection-v2.rules
│
└── docs/
    └── investigation-notes.md
```

---

# Disclaimer

This project was conducted in an isolated home lab using systems and network traffic under my control.

The project is intended for defensive security research, SOC training, and detection engineering practice.

---

## Final Takeaway

```text
Seeing the traffic
        ≠
Understanding the behavior
        ≠
Detecting the condition
        ≠
Having a useful detection
```

For me, the value of this project was learning to prove each of those stages separately.

**Baseline it. Generate it. Observe it. Detect it. Test what should stay silent. Tune from evidence.**
