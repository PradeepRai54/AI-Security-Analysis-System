import requests
import streamlit as st
import hashlib

BASE_URL = "https://www.virustotal.com/api/v3"

MAX_FILE_SIZE = 32 * 1024 * 1024


# ----------------------------------
# API CONFIGURATION
# ----------------------------------


def get_headers():

    try:
        api_key = st.secrets["VT_API_KEY"]

    except Exception:
        raise ValueError(
            "VirusTotal API key not found. " "Check .streamlit/secrets.toml"
        )

    if not api_key:
        raise ValueError("VirusTotal API key is empty.")

    return {"x-apikey": api_key, "accept": "application/json"}


# ----------------------------------
# HANDLE API RESPONSES
# ----------------------------------


def handle_response(response):

    if response.status_code == 401:
        raise ValueError("Invalid VirusTotal API key.")

    if response.status_code == 403:
        raise ValueError(
            "API access forbidden. Check your VirusTotal account permissions."
        )

    if response.status_code == 404:
        raise ValueError("Analysis report not found.")

    if response.status_code == 429:
        raise ValueError("VirusTotal API rate limit reached. Try again later.")

    if response.status_code >= 400:
        raise ValueError("VirusTotal API error: " + str(response.status_code))

    return response.json()


# ----------------------------------
# URL SCANNING
# ----------------------------------


def scan_url(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        raise ValueError("Enter a complete URL beginning with http:// or https://")

    response = requests.post(
        BASE_URL + "/urls", headers=get_headers(), data={"url": url}, timeout=30
    )

    data = handle_response(response)

    return {
        "type": "URL",
        "target": url,
        "analysis_id": data["data"]["id"],
        "status": "Submitted",
    }


# ----------------------------------
# FILE SCANNING
# ----------------------------------


def scan_file(uploaded_file):

    file_bytes = uploaded_file.getvalue()

    if not file_bytes:
        raise ValueError("The uploaded file is empty.")

    if len(file_bytes) > MAX_FILE_SIZE:
        raise ValueError(
            "File exceeds 32 MB. " "This module currently supports files up to 32 MB."
        )

    file_hash = hashlib.sha256(file_bytes).hexdigest()

    files = {"file": (uploaded_file.name, file_bytes, "application/octet-stream")}

    response = requests.post(
        BASE_URL + "/files", headers=get_headers(), files=files, timeout=120
    )

    data = handle_response(response)

    return {
        "type": "File",
        "target": uploaded_file.name,
        "sha256": file_hash,
        "size": len(file_bytes),
        "analysis_id": data["data"]["id"],
        "status": "Submitted",
    }


# ----------------------------------
# GET ANALYSIS RESULTS
# ----------------------------------


def get_analysis_result(analysis_id):

    response = requests.get(
        BASE_URL + "/analyses/" + analysis_id, headers=get_headers(), timeout=30
    )

    data = handle_response(response)

    attributes = data["data"]["attributes"]

    stats = attributes.get("stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)

    total = malicious + suspicious + harmless + undetected + timeout

    if attributes.get("status") != "completed":

        verdict = "Analysis Pending"

    elif malicious > 0:

        verdict = "Malicious"

    elif suspicious > 0:

        verdict = "Suspicious"

    elif total > 0:

        verdict = "No Detection Reported"

    else:

        verdict = "No Verdict Available"

    # INDIVIDUAL ANTIVIRUS ENGINE RESULTS

    engine_results = []

    results = attributes.get("results", {})

    for engine, details in results.items():

        category = details.get("category", "unknown")

        detection = details.get("result")

        if detection:
            detection_status = category.title() + " - " + detection
        else:
            detection_status = category.title()

        engine_results.append(
            {
                "Antivirus Engine": details.get("engine_name", engine),
                "Detection": detection_status,
            }
        )

    engine_results.sort(key=lambda item: item["Antivirus Engine"].lower())

    return {
        "status": attributes.get("status", "unknown"),
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "total": total,
        "detection_ratio": f"{malicious + suspicious}/{total}",
        "analysis_stats": stats,
        "engine_results": engine_results,
    }
