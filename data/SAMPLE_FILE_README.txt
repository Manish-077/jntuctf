UPLOAD THIS FILE IN THE APP
----------------------------
File: upload_this_sample.csv (same folder as this file)

How to analyze in BEC Shield:
1. Open the app → Sidebar → "Input hub"
2. Tab "Upload CSV"
3. Choose upload_this_sample.csv
4. Click "Queue CSV row for analysis" — choose **Row to analyze** (0 = first data row), then queue and go to Processing.

COLUMN MEANINGS (headers the app recognizes)
---------------------------------------------
login_time_delta_hours   Hours since last known login (impossible travel signal)
location_distance_km     Distance in km from user's usual location
emails_per_hour          Approximate send rate in the observation window
recipient_count          Number of recipients on the message / batch
inbox_rule_changes       Count of inbox rule changes in the window
subject                  Email subject (used for text/entropy features)
body                     Email body text

Alternate header names (auto-mapped when similar):
  time_delta, hours_since_last → login_time_delta_hours
  distance_km, geo_distance → location_distance_km
  email_rate → emails_per_hour
  recipients, num_recipients → recipient_count
  rule_changes → inbox_rule_changes
  email_subject → subject
  content, email_body → body

EMAIL CONNECTION (IMPORTANT)
----------------------------
This demo does NOT connect to Gmail or Outlook directly.

What the UI means:
- "Connect Email (demo)" only opens the same Input hub — there is no OAuth or mailbox sync.

Ways to use "email-like" data:
1) API / Email (demo) tab: paste JSON with the numeric fields (see README.md in project root).
2) Export logs from your org (SIEM, IdP, secure gateway) to CSV with the columns above.
3) Production-style integration (you would build separately):
   - Microsoft 365: Microsoft Graph API (sign-in logs, message trace, inbox rules) → your ETL → POST to /analyze
   - Google Workspace: Gmail API / Admin SDK reports → ETL → POST to /analyze
   - Forward normalized events from Splunk, Sentinel, etc. to the FastAPI server (server.py).
