import streamlit as st
import pandas as pd
import re

# Severity rules
severity_rules = {
    "HIGH": [r"ring broken"],
    "MEDIUM": [r"link_(dn)", r"zcip"],
    "LOW": [r"Renew IP"]
}

# Function to categorize logs
def categorize_log(line):
    for severity, patterns in severity_rules.items():
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return severity
    return "UNKNOWN"

# Streamlit UI
st.title("📄 Log File Analyzer with Severity Categories")

# File uploader
uploaded_file = st.file_uploader("Upload a .log or .txt file", type=[])

if uploaded_file is not None:
    st.success("✅ File uploaded successfully!")

    # Read and categorize
    lines = uploaded_file.read().decode("utf-8").splitlines()
    high_logs, medium_logs, low_logs = [], [], []

    for line in lines:
        severity = categorize_log(line)
        log_entry = {"Log Message": line.strip()}
        if severity == "HIGH":
            high_logs.append(log_entry)
        elif severity == "MEDIUM":
            medium_logs.append(log_entry)
        elif severity == "LOW":
            low_logs.append(log_entry)

    # Display tables using tabs
    tab1, tab2, tab3 = st.tabs(["🔴 High", "🟠 Medium", "🟢 Low"])

    with tab1:
        st.subheader("🔴 High Severity Alarms")
        if high_logs:
            st.dataframe(pd.DataFrame(high_logs))
        else:
            st.info("No high severity logs found.")

    with tab2:
        st.subheader("🟠 Medium Severity Alarms")
        if medium_logs:
            st.dataframe(pd.DataFrame(medium_logs))
        else:
            st.info("No medium severity logs found.")

    with tab3:
        st.subheader("🟢 Low Severity Alarms")
        if low_logs:
            st.dataframe(pd.DataFrame(low_logs))
        else:
            st.info("No low severity logs found.")
