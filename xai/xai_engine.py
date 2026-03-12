from queue import Queue

xai_queue = Queue()

def generate_explanation(src, dst, result, features):

    explanation = []

    if "entropy" in features:
        if features["entropy"] > 7.5:
            explanation.append(
                f"High payload entropy ({features['entropy']})"
            )

    if "packet_size" in features:
        if features["packet_size"] > 1200:
            explanation.append(
                f"Large packet size ({features['packet_size']})"
            )

    if "keyword" in features:
        explanation.append(
            f"Suspicious keyword detected: {features['keyword']}"
        )

    if result == "SQL_INJECTION":
        explanation.append("SQL injection pattern matched")

    if result == "XSS_ATTACK":
        explanation.append("Cross-site scripting detected")

    if result == "COMMAND_INJECTION":
        explanation.append("Command injection behaviour")

    if result == "BASE64_MALWARE":
        explanation.append("Encoded malware payload")

    xai_queue.put((
        src,
        dst,
        result,
        ", ".join(explanation)
    ))