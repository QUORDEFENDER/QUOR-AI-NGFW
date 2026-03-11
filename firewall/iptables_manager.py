import subprocess

def get_iptables_rules():

    try:

        out=subprocess.check_output(
            ["iptables","-L","-n","--line-numbers"]
        )

        return out.decode().splitlines()

    except:

        return ["iptables not available"]