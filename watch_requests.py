import time
from datetime import datetime
import pandas as pd
from io import StringIO

from predictor import extract_features, predict_http_request

BURP_FILE = "burp_log.csv"
PREDICTION_FILE = "predictions.log"

print("\n" + "=" * 70)
print("ML IDS MONITOR STARTED")
print("=" * 70)

last_row = 0


def read_burp_csv(path):
    """Read Logger++ CSV and fix missing empty fields (no leading commas)."""
    with open(path, "r") as f:
        lines = f.readlines()

    if not lines:
        return pd.DataFrame()

    header = lines[0].strip()
    num_cols = len(header.split(","))
    fixed_lines = [header]

    for line in lines[1:]:
        fields = line.strip().split(",")
        # Pad with empty strings if row is shorter than header
        while len(fields) < num_cols:
            fields.insert(0, "")
        fixed_lines.append(",".join(fields))

    return pd.read_csv(StringIO("\n".join(fixed_lines)))


while True:

    try:

        df = read_burp_csv(BURP_FILE)

        if len(df) > last_row:

            new_rows = df.iloc[last_row:]

            for _, row in new_rows.iterrows():

                method = str(row["Request.Method"])
                path = str(row["Request.Path"])
                query = str(row["Request.Query"])
                body = str(row["Request.Body"])

                if query != "nan":
                    request_line = f"{method} {path}?{query}"
                else:
                    request_line = f"{method} {path}"

                if body != "nan":
                    raw_request = request_line + "\n" + body
                else:
                    raw_request = request_line

                features = extract_features(raw_request)

                attack_name, confidence = predict_http_request(
                    features
                )

                print("\n" + "=" * 70)
                print("🚨 ML IDS ALERT")
                print("=" * 70)

                print("REQUEST    :", request_line)

                if body != "nan":
                    print("BODY       :", body)

                print("PREDICTION :", attack_name)
                print("CONFIDENCE :", f"{confidence}%")

                print("=" * 70)

                timestamp = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                with open(PREDICTION_FILE, "a") as logfile:

                    logfile.write(
                        f"{timestamp},{method},{path},{attack_name},{confidence}\n"
                    )

            last_row = len(df)

        time.sleep(1)

    except Exception as e:

        print("Error:", e)

        time.sleep(1)