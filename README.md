🛡️ AccessMonitor 360: Multi-Agent IAM Anomaly Analyzer
AccessMonitor 360 is an autonomous multi-agent system built using CrewAI and OpenAI's GPT-4. It detects and interprets suspicious IAM login behaviors by fusing identity telemetry with environmental context.

📌 Key Features
- Anomaly Detection: Flags login events with low Wilson scores indicating rare or suspicious behavior.

- GenAI Risk Assessment: Uses LLMs to assess whether anomalous activity is truly malicious based on contextual metadata (e.g., environment, application).

- Explanation Agent: Converts technical analysis into analyst-friendly summaries.

- Remediation Agent: Recommends actionable steps like disabling accounts or alerting SOC teams.

📁 Input Files
File	Description
login_events.csv	Contains login attempts with src_ip, username, wilson_score
context_data.csv	Contains src_ip mapped to hostname, application_id, environment_type

🧠 CrewAI Agents
Agent	Role & Purpose
Data Ingestion Specialist	Merges telemetry and context to produce enriched data
Anomaly Detector	Flags records with low Wilson scores as potential risks
GenAI Risk Assessor	Uses LLM to assess risk level for each flagged anomaly
Explanation Agent	Summarizes risk findings for Tier-1 SOC analysts
Remediation Agent	Recommends next actions (e.g. enforce MFA, disable account, investigate)

🚀 How to Run
Install dependencies

bash
Copy
Edit
pip install -r requirements.txt
Set your OpenAI API Key

Create a .env file or set the variable in your shell:

bash
Copy
Edit
export OPENAI_API_KEY=your_openai_key_here
Prepare your input files

Place login_events.csv and context_data.csv in the project directory.

Run the script

bash
Copy
Edit
python accessmonitor_agents.py
✅ Output
Results are printed to console.

Also saved as iam_analysis_results.json (optional enhancement).

Each entry contains:

Risk assessment

Explanation summary

Remediation recommendation

🧪 Sample Output
json
Copy
Edit
{
  "username": "alice",
  "src_ip": "192.168.1.10",
  "wilson_score": 0.15,
  "analysis_result": "This login appears abnormal due to access from a high-privilege environment with rare frequency...",
  "explanation_summary": "Alice's login from a prod host with low historical access makes this a potential outlier worth review.",
  "remediation_recommendation": "Temporarily restrict account and notify IAM team for validation."
}
📚 Requirements
Python 3.8+

OpenAI SDK ≥ 1.0

CrewAI ≥ 0.10

pandas