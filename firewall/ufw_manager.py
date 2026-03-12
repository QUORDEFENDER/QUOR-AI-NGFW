import subprocess


# ---------------- GET UFW RULES ----------------

def get_ufw_rules():

    result = subprocess.run(
        ["sudo", "ufw", "status", "numbered"],
        capture_output=True,
        text=True
    )

    rules = []

    for line in result.stdout.split("\n"):

        if "[" in line and "]" in line:

            parts = line.split()

            rule_num = parts[0].strip("[]")
            action = parts[1]
            port_proto = parts[2]

            if "/" in port_proto:
                port, proto = port_proto.split("/")
            else:
                port = port_proto
                proto = ""

            source = parts[-1]

            rules.append((rule_num, action, port, proto, source))

    return rules


# ---------------- ENABLE FIREWALL ----------------

def enable_ufw():

    subprocess.run(
        ["sudo", "ufw", "--force", "enable"]
    )


# ---------------- DISABLE FIREWALL ----------------

def disable_ufw():

    subprocess.run(
        ["sudo", "ufw", "disable"]
    )