import streamlit as st
import pandas as pd

from analyzer import analyze_message
from database import initialize_database, save_analysis, get_history

# PAGE CONFIGURATION
st.set_page_config(page_title="AI Scam Detection System", page_icon="🛡️", layout="wide")


# INITIALIZE DATABASE
initialize_database()


# APPLICATION HEADER
st.title("🛡️ AI Security Analysis System")
st.caption("Machine Learning | Rule-Based Risk Analysis | SQLite Database | Virustotal")


# SIDEBAR NAVIGATION
st.sidebar.title("Navigation")

page = st.sidebar.radio(
    "Select Module",
    [
        "Message Analyzer",
        "URL Threat Scanner",
        "File Malware Scanner",
        "Dashboard",
        "Analysis History",
        "Model Performance",
        "About Project",
    ],
)


# ----------------------------------
# MESSAGE ANALYZER
# ----------------------------------


if page == "Message Analyzer":

    st.header("📩 Analyze a Message")

    message = st.text_area(
        "Enter SMS or message", height=150, placeholder="Paste your message here..."
    )

    if st.button("Analyze Message", type="primary"):

        if not message.strip():

            st.warning("Please enter a message.")

        else:

            try:

                result = analyze_message(message)

                save_analysis(result)

                st.subheader("Analysis Results")

                # FINAL VERDICT

                if result["risk_score"] >= 70:
                    st.error("🚨 FINAL VERDICT: CRITICAL RISK")

                elif result["risk_score"] >= 50:
                    st.error("⚠️ FINAL VERDICT: HIGH RISK")

                elif result["risk_score"] >= 25:
                    st.warning("⚠️ FINAL VERDICT: SUSPICIOUS MESSAGE")

                else:
                    st.success("✅ FINAL VERDICT: LOW RISK")

                # RESULT METRICS

                col1, col2, col3 = st.columns(3)

                col1.metric("ML Prediction", result["ml_prediction"])

                col2.metric("Risk Score", str(result["risk_score"]) + "/100")

                col3.metric("Risk Level", result["risk_level"])

                st.progress(result["risk_score"] / 100)

                # DETECTION REASONS

                st.subheader("Detection Reasons")

                for reason in result["reasons"]:
                    st.write("•", reason)

                # INTELLIGENT EXPLANATION

                st.divider()

                st.subheader("🔍 Intelligent Message Explanation")

                if result["ml_prediction"] == "Spam":

                    st.write(
                        "The machine learning model identified "
                        "this message as Spam based on learned text patterns."
                    )

                else:

                    st.write(
                        "The machine learning model classified "
                        "this message as Not Spam. However, "
                        "rule-based indicators may still identify "
                        "suspicious content."
                    )

                # SAFETY RECOMMENDATIONS

                st.subheader("🛡️ Safety Recommendations")

                for recommendation in result["recommendations"]:
                    st.write("•", recommendation)

                # URL DETECTION

                if result["urls"]:

                    st.subheader("Detected URLs")

                    for url in result["urls"]:
                        st.code(url)

                # DISCLAIMER

                st.info(
                    "Risk score is a heuristic assessment, "
                    "not a confirmed probability of fraud. "
                    "Do not trust or open suspicious links."
                )

            except Exception as error:

                st.error("Analysis failed: " + str(error))


# ----------------------------------
# URL THREAT SCANNER
# ----------------------------------

elif page == "URL Threat Scanner":

    from vt_scanner import scan_url, get_analysis_result

    st.header("🌐 VirusTotal URL Threat Scanner")

    st.write("Analyze URLs using VirusTotal's security intelligence.")

    url = st.text_input("Enter URL", placeholder="https://example.com")

    if st.button("Submit URL for Scanning", type="primary"):

        if not url.strip():

            st.warning("Please enter a URL.")

        else:

            try:

                with st.spinner("Submitting URL to VirusTotal..."):

                    result = scan_url(url)

                st.session_state["vt_url_analysis"] = result

                st.success("URL submitted successfully.")

            except Exception as error:

                st.error(str(error))

    # RETRIEVE SAVED ANALYSIS

    saved = st.session_state.get("vt_url_analysis")

    if saved:

        st.divider()

        st.subheader("Submitted URL")

        st.write(saved["target"])

        st.code(saved["analysis_id"])

        st.write("Submission status:", saved["status"])

        if st.button("Get URL Analysis Report"):

            try:

                with st.spinner("Retrieving VirusTotal report..."):

                    report = get_analysis_result(saved["analysis_id"])

                st.session_state["vt_url_report"] = report

            except Exception as error:

                st.error(str(error))

        report = st.session_state.get("vt_url_report")

        if report:

            st.subheader("URL Security Report")

            st.subheader("Antivirus Engine Results")

            if report["engine_results"]:

                engine_df = pd.DataFrame(report["engine_results"])

                st.dataframe(engine_df, use_container_width=True, hide_index=True)

            else:

                st.info("Individual engine results are not available yet.")

            st.metric("Detection Ratio", report["detection_ratio"])

            st.write("Analysis Status:", report["status"])

            st.write("Verdict:", report["verdict"])

            col1, col2, col3 = st.columns(3)

            col1.metric("Malicious", report["malicious"])

            col2.metric("Suspicious", report["suspicious"])

            col3.metric("Harmless", report["harmless"])

            col4, col5 = st.columns(2)

            col4.metric("Undetected", report["undetected"])

            col5.metric("Timeout", report["timeout"])

            if report["status"] != "completed":

                st.warning("Analysis is not complete. Check again later.")

            elif report["malicious"] > 0:

                st.error("Potentially malicious URL detected.")

            elif report["suspicious"] > 0:

                st.warning("Suspicious URL indicators detected.")

            else:

                st.success(
                    "No malicious or suspicious detections "
                    "were reported by the available engines."
                )

            st.info(
                "A clean VirusTotal report does not guarantee " "that a URL is safe."
            )


# ----------------------------------
# FILE MALWARE SCANNER
# ----------------------------------

elif page == "File Malware Scanner":

    from vt_scanner import scan_file, get_analysis_result

    st.header("📁 VirusTotal File Malware Scanner")

    st.write("Upload a file to analyze it using VirusTotal.")

    st.warning(
        "Uploaded files may be shared with VirusTotal's "
        "security community. Never upload confidential or "
        "personal files."
    )

    uploaded_file = st.file_uploader("Choose a file", accept_multiple_files=False)

    if st.button("Submit File for Scanning", type="primary"):

        if uploaded_file is None:

            st.warning("Please select a file.")

        else:

            try:

                with st.spinner("Uploading file to VirusTotal..."):

                    result = scan_file(uploaded_file)

                st.session_state["vt_file_analysis"] = result

                st.success("File submitted successfully.")

            except Exception as error:

                st.error(str(error))

    # RETRIEVE SAVED FILE ANALYSIS

    saved = st.session_state.get("vt_file_analysis")

    if saved:

        st.divider()

        st.subheader("Uploaded File Details")

        st.write("Filename:", saved["target"])

        st.write("File size:", round(saved["size"] / 1024, 2), "KB")

        st.write("SHA-256:")

        st.code(saved["sha256"])

        st.write("Submission status:", saved["status"])

        st.code(saved["analysis_id"])

        if st.button("Get File Analysis Report"):

            try:

                with st.spinner("Retrieving file analysis..."):

                    report = get_analysis_result(saved["analysis_id"])

                st.session_state["vt_file_report"] = report

            except Exception as error:

                st.error(str(error))

        report = st.session_state.get("vt_file_report")

        if report:

            st.subheader("File Security Report")

            st.subheader("Antivirus Engine Results")

            if report["engine_results"]:

                engine_df = pd.DataFrame(report["engine_results"])

                st.dataframe(engine_df, use_container_width=True, hide_index=True)

            else:

                st.info("Individual engine results are not available yet.")

            st.metric("Detection Ratio", report["detection_ratio"])

            st.write("Analysis Status:", report["status"])

            st.write("Verdict:", report["verdict"])

            col1, col2, col3 = st.columns(3)

            col1.metric("Malicious", report["malicious"])

            col2.metric("Suspicious", report["suspicious"])

            col3.metric("Harmless", report["harmless"])

            col4, col5 = st.columns(2)

            col4.metric("Undetected", report["undetected"])

            col5.metric("Timeout", report["timeout"])

            if report["status"] != "completed":

                st.warning("File analysis is still pending. Check again later.")

            elif report["malicious"] > 0:

                st.error("Potentially malicious file detected.")

            elif report["suspicious"] > 0:

                st.warning("Suspicious file indicators detected.")

            else:

                st.success(
                    "No malicious or suspicious detections "
                    "were reported by the available engines."
                )

            st.info("A clean report does not guarantee that a file is safe.")


elif page == "Dashboard":

    st.header("📊 Analysis Dashboard")

    records = get_history()

    if not records:

        st.info("No analysis records available yet. " "Analyze some messages first.")

    else:

        df = pd.DataFrame(
            records,
            columns=[
                "ID",
                "Message",
                "ML Prediction",
                "Risk Score",
                "Risk Level",
                "Reasons",
                "Analyzed At",
            ],
        )

        # SUMMARY METRICS

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Messages", len(df))

        col2.metric("Spam Messages", int((df["ML Prediction"] == "Spam").sum()))

        col3.metric("Not Spam", int((df["ML Prediction"] == "Not Spam").sum()))

        col4.metric(
            "High/Critical Risk", int(df["Risk Level"].isin(["High", "Critical"]).sum())
        )

        # RISK DISTRIBUTION

        st.subheader("Risk Level Distribution")

        risk_counts = (
            df["Risk Level"]
            .value_counts()
            .reindex(["Low", "Moderate", "High", "Critical"], fill_value=0)
        )

        st.bar_chart(risk_counts)

        # SPAM DISTRIBUTION

        st.subheader("Spam vs Not Spam")

        prediction_counts = df["ML Prediction"].value_counts()

        st.bar_chart(prediction_counts)

        # RISK SCORE DISTRIBUTION

        st.subheader("Risk Score Distribution")

        st.bar_chart(df["Risk Score"].value_counts().sort_index())


# ----------------------------------
# ANALYSIS HISTORY
# ----------------------------------

elif page == "Analysis History":

    st.header("📜 Analysis History")

    records = get_history()

    if not records:

        st.info("No analysis history found.")

    else:

        df = pd.DataFrame(
            records,
            columns=[
                "ID",
                "Message",
                "ML Prediction",
                "Risk Score",
                "Risk Level",
                "Reasons",
                "Analyzed At",
            ],
        )

        st.dataframe(df, use_container_width=True, hide_index=True)

        # CSV EXPORT

        csv = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="📥 Download History as CSV",
            data=csv,
            file_name="analysis_history.csv",
            mime="text/csv",
        )


elif page == "Model Performance":

    st.header("📊 Model Performance Analysis")

    st.write("Improved SMS Spam Detection Model Evaluation")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Accuracy", "98.32%")
    col2.metric("Precision", "94.74%")
    col3.metric("Recall", "91.84%")
    col4.metric("F1 Score", "93.26%")

    st.divider()

    st.subheader("Confusion Matrix")

    confusion_data = pd.DataFrame(
        [[672, 5], [8, 90]],
        index=["Actual Not Spam", "Actual Spam"],
        columns=["Predicted Not Spam", "Predicted Spam"],
    )

    st.dataframe(confusion_data, use_container_width=True)

    st.divider()

    st.subheader("Classification Metrics")

    metrics_data = pd.DataFrame(
        {
            "Metric": ["Precision", "Recall", "F1 Score"],
            "Score": [0.9474, 0.9184, 0.9326],
        }
    )

    st.bar_chart(metrics_data.set_index("Metric"))

    st.divider()

    st.subheader("Dataset Distribution")

    dataset_data = pd.DataFrame(
        {"Category": ["Not Spam", "Spam"], "Messages": [4516, 653]}
    )

    st.bar_chart(dataset_data.set_index("Category"))

    st.divider()

    st.subheader("Model Configuration")

    st.write("""
    - Algorithm: Logistic Regression
    - Feature Extraction: Word + Character TF-IDF
    - Word N-grams: 1–2
    - Character N-grams: 3–5
    - Class Weight: Balanced
    - Decision Threshold: 0.4777
    - Train/Validation/Test: 70/15/15
    """)

    st.info("Results are from the held-out test dataset.")


# ----------------------------------
# ABOUT PROJECT
# ----------------------------------

elif page == "About Project":

    st.header("ℹ️ About the Project")

    st.write("""
    The AI-Based SMS Scam Detection and Intelligent
    Risk Analysis System is designed to analyze SMS
    messages and identify potentially suspicious content.

    It combines a machine learning classifier with
    rule-based analysis to assess message risk.
    """)

    st.subheader("Technologies Used")

    st.write("""
    - Python
    - Scikit-learn
    - Pandas
    - NumPy
    - NLTK
    - Streamlit
    - SQLite
    """)

    st.subheader("Major Features")

    st.write("""
    1. Machine Learning-Based Spam Classification
    2. Suspicious Keyword Detection
    3. Financial and Credential Risk Detection
    4. Delivery Scam Indicator Detection
    5. URL Risk Analysis
    6. Risk Score Calculation
    7. Final Safety Verdict
    8. SQLite Analysis History
    9. Interactive Dashboard
    10. CSV Export
    """)

    st.subheader("Risk Classification")

    st.write("""
    - 0–24: Low Risk
    - 25–49: Moderate Risk
    - 50–69: High Risk
    - 70–100: Critical Risk
    """)

    st.warning(
        "This system provides automated risk indicators. "
        "It cannot guarantee that a message or URL is safe."
    )

    st.subheader("Project Developer")

    st.write("Developed as an academic major project.")
