import re
import pickle

from preprocessing import text_preprocessing

# ----------------------------------
# LOAD IMPROVED ML MODEL
# ----------------------------------

with open("spam_model_improved.pkl", "rb") as file:
    model = pickle.load(file)

with open("label_encoder_improved.pkl", "rb") as file:
    encoder = pickle.load(file)

with open("model_threshold.pkl", "rb") as file:
    threshold = pickle.load(file)


# ----------------------------------
# SUSPICIOUS KEYWORD GROUPS
# ----------------------------------

SCAM_KEYWORDS = [
    "winner",
    "won",
    "prize",
    "lottery",
    "claim",
    "congratulations",
    "reward",
    "free gift",
    "cashback",
    "urgent",
    "immediately",
    "limited time",
]

FINANCIAL_KEYWORDS = [
    "bank",
    "account",
    "credit card",
    "debit card",
    "payment",
    "refund",
    "transaction",
    "upi",
    "wallet",
    "money",
    "loan",
]

CREDENTIAL_KEYWORDS = [
    "password",
    "otp",
    "pin",
    "cvv",
    "verify account",
    "login",
    "credentials",
    "verification code",
]

THREAT_KEYWORDS = [
    "blocked",
    "suspended",
    "expire",
    "deactivated",
    "legal action",
    "penalty",
    "arrest",
]

DELIVERY_KEYWORDS = [
    "parcel is on hold",
    "unpaid charges",
    "release your delivery",
    "delivery failed",
    "customs fee",
    "shipping fee",
    "reschedule delivery",
    "tracking number",
]

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"]


# ----------------------------------
# MAIN MESSAGE ANALYSIS FUNCTION
# ----------------------------------


def analyze_message(message):

    if not message or not message.strip():
        raise ValueError("Message cannot be empty.")

    message_lower = message.lower()

    # TEXT PREPROCESSING

    cleaned_message = text_preprocessing(message)

    # ML PREDICTION

    model_score = model.decision_function([cleaned_message])[0]

    predicted_label = int(model_score >= threshold)

    ml_result = encoder.inverse_transform([predicted_label])[0]

    # INITIALIZE RISK SCORE

    score = 0
    reasons = []

    # ML DETECTION

    if ml_result == "Spam":

        score += 40

        reasons.append("Machine learning model classified this message as spam.")

    # KEYWORD ANALYSIS

    keyword_groups = [
        (SCAM_KEYWORDS, 15, "Suspicious prize, reward or urgency-related language"),
        (FINANCIAL_KEYWORDS, 10, "Financial or payment-related language"),
        (CREDENTIAL_KEYWORDS, 20, "Possible request for sensitive credentials"),
        (THREAT_KEYWORDS, 15, "Threatening or account-warning language"),
        (DELIVERY_KEYWORDS, 25, "Suspicious delivery or parcel-related language"),
    ]

    for keywords, points, reason in keyword_groups:

        matched = [word for word in keywords if word in message_lower]

        if matched:

            score += points

            reasons.append(reason + ": " + ", ".join(matched))

    # URL ANALYSIS

    urls = re.findall(r"https?://[^\s]+|www\.[^\s]+", message, re.I)

    if urls:

        score += 15

        reasons.append("Message contains a URL.")

    for url in urls:

        url_lower = url.lower()

        if any(shortener in url_lower for shortener in SHORTENERS):

            score += 15

            reasons.append("URL uses a known shortening service.")

        if url_lower.startswith("http://"):

            score += 10

            reasons.append("URL uses unencrypted HTTP.")

        if len(url) > 100:

            score += 5

            reasons.append("URL is unusually long.")

        if re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", url_lower):

            score += 15

            reasons.append("URL appears to use an IP address.")

    # LIMIT RISK SCORE

    score = min(score, 100)

    # RISK CLASSIFICATION

    if score >= 70:

        risk_level = "Critical"

    elif score >= 50:

        risk_level = "High"

    elif score >= 25:

        risk_level = "Moderate"

    else:

        risk_level = "Low"

    # DEFAULT REASON

    if not reasons:

        reasons.append("No major suspicious indicators were detected.")

    # ----------------------------------
    # SAFETY RECOMMENDATIONS
    # ----------------------------------

    recommendations = []

    if score >= 70:

        recommendations.append(
            "Do not respond to this message or interact with its links."
        )

        recommendations.append("Never share OTPs, passwords or banking credentials.")

        recommendations.append("Report this message as suspicious.")

    elif score >= 50:

        recommendations.append("Treat this message with extreme caution.")

        recommendations.append("Verify the sender through an official channel.")

        recommendations.append("Do not share sensitive personal information.")

    elif score >= 25:

        recommendations.append("Verify the message before taking any action.")

        recommendations.append("Avoid clicking unexpected links.")

    else:

        recommendations.append("No major suspicious indicators were detected.")

        recommendations.append("Still verify unexpected requests independently.")

    # ----------------------------------
    # RETURN COMPLETE ANALYSIS
    # ----------------------------------

    return {
        "message": message,
        "ml_prediction": ml_result,
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "urls": urls,
        "recommendations": recommendations,
    }
