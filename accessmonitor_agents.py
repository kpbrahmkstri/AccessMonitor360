# accessmonitor_agents.py using CrewAI (Extended with Explanation & Remediation Agents)

import pandas as pd
import json
import openai
import os
from crewai import Agent, Task, Crew
from typing import Dict, List, Any
import logging
from scipy.stats import norm
import math

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IAMDataPipeline:
    def __init__(self, login_file: str, context_file: str, api_key: str):
        self.login_file = login_file
        self.context_file = context_file
        self.api_key = api_key
        self.client = openai.OpenAI(api_key=api_key)
        self.pipeline_data = {}
        self.wilson_threshold = 0.2
        self._initialize_agents()

    def _initialize_agents(self):
        self.ingestion_agent = Agent(
            role="Data Ingestion Specialist",
            goal="Load and merge login and context data to provide enriched security access records",
            backstory="Expert in parsing and preparing cybersecurity telemetry from various sources.",
            verbose=True
        )

        self.anomaly_agent = Agent(
            role="Anomaly Detector",
            goal="Calculate Wilson scores and identify login records that may indicate suspicious access",
            backstory="Skilled in identifying unusual patterns in identity access logs.",
            verbose=True
        )

        self.genai_agent = Agent(
            role="GenAI Risk Assessor",
            goal="Use contextual data to evaluate if login activity is truly suspicious",
            backstory="AI analyst trained in IAM threat detection using contextual reasoning.",
            verbose=True
        )

        self.explanation_agent = Agent(
            role="Explanation Agent",
            goal="Summarize the risk analysis into a concise explanation for security analysts",
            backstory="Helps translate technical analysis into easy-to-understand summaries.",
            verbose=True
        )

        self.remediation_agent = Agent(
            role="Remediation Agent",
            goal="Recommend security actions based on anomaly insights",
            backstory="Provides actionable steps to address risks and suspicious activities.",
            verbose=True
        )

    def _ingest_data(self):
        login_df = pd.read_csv(self.login_file)
        context_df = pd.read_csv(self.context_file)
        enriched_df = pd.merge(login_df, context_df, on="src_ip", how="left")
        self.pipeline_data['enriched_data'] = enriched_df
        return "Ingested and enriched data with context."

    def _calculate_wilson_score(self, success: int, total: int, z: float = 1.96) -> float:
        if total == 0:
            return 0.0
        phat = success / total
        denominator = 1 + z**2 / total
        numerator = phat + z**2 / (2 * total) - z * math.sqrt((phat * (1 - phat) + z**2 / (4 * total)) / total)
        return numerator / denominator

    def _detect_anomalies(self):
        df = self.pipeline_data.get('enriched_data')
        if df is None:
            return "No enriched data found."

        # Calculate Wilson score dynamically
        if 'successes' in df.columns and 'total_attempts' in df.columns:
            df['wilson_score'] = df.apply(lambda row: self._calculate_wilson_score(row['successes'], row['total_attempts']), axis=1)
        elif 'wilson_score' not in df.columns:
            return "Required columns for Wilson score calculation not found."

        anomalies = df[df['wilson_score'] < self.wilson_threshold].copy()
        self.pipeline_data['anomalies'] = anomalies
        return f"Detected {len(anomalies)} anomalies."

    def _assess_risk_with_genai(self):
        anomalies = self.pipeline_data.get('anomalies')
        if anomalies is None or anomalies.empty:
            self.pipeline_data['final_results'] = []
            return "No anomalies to assess."

        results = []
        for idx, (_, row) in enumerate(anomalies.iterrows(), start=1):
            prompt = f"""
            You are an IAM security analyst. Analyze the login event below and determine if it is suspicious:

            - Username: {row['username']}
            - Source IP: {row['src_ip']}
            - Wilson Score: {row['wilson_score']}
            - Hostname: {row.get('hostname', 'N/A')}
            - Application ID: {row.get('application_id', 'N/A')}
            - Environment: {row.get('environment_type', 'N/A')}

            Consider if this behavior aligns with expected patterns based on typical access.
            """
            try:
                response = self.client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity analyst specializing in IAM anomaly detection."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=300
                )
                result_text = response.choices[0].message.content.strip()
                results.append({
                    "username": row["username"],
                    "src_ip": row["src_ip"],
                    "wilson_score": row["wilson_score"],
                    "application_id": row.get("application_id", "N/A"),
                    "environment_type": row.get("environment_type", "N/A"),
                    "hostname": row.get("hostname", "N/A"),
                    "analysis_result": result_text
                })
            except Exception as e:
                print(f"[Error in LLM call for anomaly {idx}]: {e}")

        self.pipeline_data['final_results'] = results
        return f"Evaluated {len(results)} anomalies with GenAI."

    def _generate_explanations(self):
        summaries = []
        for item in self.pipeline_data.get('final_results', []):
            prompt = f"""
            Summarize the following IAM anomaly analysis in one paragraph for a SOC analyst:

            {item['analysis_result']}
            """
            try:
                response = self.client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a SOC assistant summarizing IAM risk assessments."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=150
                )
                item['explanation_summary'] = response.choices[0].message.content.strip()
            except Exception as e:
                item['explanation_summary'] = f"Summary generation failed: {e}"
        return "Generated explanations for all anomalies."

    def _recommend_remediations(self):
        for item in self.pipeline_data.get('final_results', []):
            prompt = f"""
            Based on the IAM analysis below, suggest a remediation action (e.g. disable account, enforce MFA, alert SOC):

            {item['analysis_result']}
            """
            try:
                response = self.client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity operations assistant."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    max_tokens=100
                )
                item['remediation_recommendation'] = response.choices[0].message.content.strip()
            except Exception as e:
                item['remediation_recommendation'] = f"Remediation suggestion failed: {e}"
        return "Generated remediation recommendations."

    def run(self) -> List[Dict[str, Any]]:
        ingestion_task = Task(
            description="Confirm that login and context data have been loaded and merged in pandas. Do not print sample records.",
            expected_output="Confirmation message that data was loaded and merged.",
            agent=self.ingestion_agent
        )


        anomaly_task = Task(
            description=f"Calculate Wilson scores and filter records with wilson_score < {self.wilson_threshold}.",
            expected_output="Subset of enriched records flagged as anomalies.",
            agent=self.anomaly_agent
        )

        genai_task = Task(
            description="Use LLM to evaluate risk level of each anomaly.",
            expected_output="List of anomalies with GenAI-based risk assessment and rationale.",
            agent=self.genai_agent
        )

        explanation_task = Task(
            description="Summarize analysis results into analyst-friendly explanations.",
            expected_output="SOC-ready explanation summaries for each anomaly.",
            agent=self.explanation_agent
        )

        remediation_task = Task(
            description="Generate remediation steps based on IAM anomaly analysis.",
            expected_output="Actionable recommendations to mitigate risks.",
            agent=self.remediation_agent
        )

        crew = Crew(
            agents=[
                self.ingestion_agent,
                self.anomaly_agent,
                self.genai_agent,
                self.explanation_agent,
                self.remediation_agent
            ],
            tasks=[
                ingestion_task,
                anomaly_task,
                genai_task,
                explanation_task,
                remediation_task
            ],
            verbose=True
        )

        self._ingest_data()
        self._detect_anomalies()
        self._assess_risk_with_genai()
        self._generate_explanations()
        self._recommend_remediations()

        crew.kickoff()
        return self.pipeline_data.get('final_results', [])


def main():
    login_file = "login_events.csv"
    context_file = "context_data.csv"
    openai_api_key = os.getenv("OPENAI_API_KEY")

    if not openai_api_key:
        raise EnvironmentError("OPENAI_API_KEY not found in environment variables.")

    pipeline = IAMDataPipeline(login_file, context_file, openai_api_key)
    results = pipeline.run()

    if not results:
        print("\n⚠️ No final results were returned. Please check anomaly threshold or LLM responses.")
    else:
        print("\n✅ Final Decisions:")
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
