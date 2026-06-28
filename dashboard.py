import streamlit as st
import pandas as pd
from collections import Counter

st.set_page_config(
    page_title="ML Intrusion Detection System",
    layout="wide"
)

st.title("Machine Learning Intrusion Detection System")

# Store attack counts
if "attack_counts" not in st.session_state:
    st.session_state.attack_counts = Counter()

if "history" not in st.session_state:
    st.session_state.history = []

# Read latest predictions
try:

    with open("predictions.log", "r") as f:

        lines = f.readlines()

        for line in lines:

            parts = line.strip().split(",")

            # Expected format:
            # timestamp,method,path,attack_name,confidence
            if len(parts) != 5:
                continue

            timestamp = parts[0]
            method = parts[1]
            path = parts[2]
            attack = parts[3]
            confidence = float(parts[4])

            entry = (
                timestamp,
                method,
                path,
                attack,
                confidence
            )

            if entry not in st.session_state.history:

                st.session_state.history.append(entry)

                st.session_state.attack_counts[attack] += 1

except FileNotFoundError:
    pass


# Latest Event
st.header("Latest Event")

if len(st.session_state.history) > 0:

    latest = st.session_state.history[-1]

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Prediction",
            latest[3]
        )

    with col2:
        st.metric(
            "Confidence",
            f"{latest[4]:.2f}%"
        )

    st.write("**Method:**", latest[1])
    st.write("**Path:**", latest[2])

else:

    st.write("No events yet.")


# Attack Statistics
st.header("Attack Statistics")

counts_df = pd.DataFrame(
    st.session_state.attack_counts.items(),
    columns=["Attack Type", "Count"]
)

if len(counts_df) > 0:

    st.bar_chart(
        counts_df.set_index("Attack Type")
    )

else:

    st.write("No attack statistics available.")


# Event History
st.header("Recent Events")

if len(st.session_state.history) > 0:

    history_df = pd.DataFrame(
        st.session_state.history,
        columns=[
            "Time",
            "Method",
            "Path",
            "Prediction",
            "Confidence"
        ]
    )

    st.dataframe(
        history_df.iloc[::-1],
        use_container_width=True
    )

else:

    st.write("No events yet.")
