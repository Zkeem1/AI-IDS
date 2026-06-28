import joblib
import pandas as pd
import numpy as np
import re
import urllib.parse

class_names = [
    "Command Injection",
    "Normal",
    "Other Anomalous",
    "Path Traversal",
    "SQL Injection",
    "XSS"
]

model = joblib.load("HTTP_Request_RF_Model.pkl")
imputer = joblib.load("HTTP_Request_Imputer.pkl")
scaler = joblib.load("HTTP_Request_Scaler.pkl")

ml_features = [
    'request_length',
    'num_parameters',
    'has_sql_keywords',
    'has_xss_patterns',
    'has_path_traversal',
    'has_command_injection',
    'special_char_count',
    'encoded_char_count',
    'path_depth',
    'digit_count',
    'uppercase_count'
]

def extract_features(raw_request):

    raw_lower = raw_request.lower()

    features = {

        'request_length': len(raw_request),

        'num_parameters':
            raw_request.count("="),

        'has_sql_keywords':
            int(any(
                keyword in raw_lower
                for keyword in [
                    "select",
                    "union",
                    "drop",
                    "insert",
                    "update",
                    "or 1=1",
                    "--"
                ]
            )),

        'has_xss_patterns':
            int(any(
                x in raw_lower
                for x in [
                    "<script",
                    "alert(",
                    "onerror"
                ]
            )),

        'has_path_traversal':
            int("../" in raw_request),

        'has_command_injection':
            int(any(
                x in raw_request
                for x in [
                    ";",
                    "|",
                    "&&"
                ]
            )),

        'special_char_count':
            len(
                re.findall(
                    r"[<>'\";=&|]",
                    raw_request
                )
            ),

        'encoded_char_count':
            raw_request.count("%"),

        'path_depth':
            raw_request.count("/"),

        'digit_count':
            sum(
                c.isdigit()
                for c in raw_request
            ),

        'uppercase_count':
            sum(
                c.isupper()
                for c in raw_request
            )

    }

    return features

def predict_http_request(raw_row_dict):

    row_df = pd.DataFrame([raw_row_dict])

    # Add missing columns
    for col in ml_features:
        if col not in row_df.columns:
            row_df[col] = 0

    # Ensure correct order
    row_df = row_df[ml_features]

    # Impute missing values
    row_imp = imputer.transform(row_df)

    # Scale features
    row_scaled = scaler.transform(row_imp)

    # Predict class
    prediction = model.predict(row_scaled)[0]

    attack_name = class_names[prediction]

    # Predict probabilities
    probabilities = model.predict_proba(row_scaled)[0]

    confidence = np.max(probabilities)

    # Print results
    print()
    print("Prediction:", attack_name)
    print("Confidence:", round(confidence * 100, 2), "%")
    print()

    for i, p in enumerate(probabilities):
        print(
            f"{class_names[i]:20s}",
            f"{p:.3f}"
        )
    return attack_name, round(confidence * 100, 2)

sample_request = {
    'request_length': 100,
    'num_parameters': 1,
    'has_sql_keywords': 1,
    'has_xss_patterns': 0,
    'has_path_traversal': 0,
    'has_command_injection': 0,
    'special_char_count': 15,
    'encoded_char_count': 0,
    'path_depth': 2,
    'digit_count': 2,
    'uppercase_count': 1
}

predict_http_request(sample_request)

raw_request = """
{"email":"' OR 1=1--","password":"never"}"""

features = extract_features(raw_request)

print(features)

predict_http_request(features)