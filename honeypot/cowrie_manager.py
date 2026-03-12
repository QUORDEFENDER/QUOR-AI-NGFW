import subprocess

COWRIE_DIR = "/home/cowrie/cowrie"
COWRIE_PY = f"{COWRIE_DIR}/src/cowrie/scripts/cowrie.py"
COWRIE_PYTHON = f"{COWRIE_DIR}/cowrie-env/bin/python"

def start_honeypot():

    subprocess.Popen([
        "sudo","-u","cowrie","env",
        "PATH=/home/cowrie/cowrie/cowrie-env/bin:/usr/bin:/bin",
        COWRIE_PYTHON,
        COWRIE_PY,
        "start"
    ])

def stop_honeypot():

    subprocess.Popen([
        "sudo","-u","cowrie","env",
        "PATH=/home/cowrie/cowrie/cowrie-env/bin:/usr/bin:/bin",
        COWRIE_PYTHON,
        COWRIE_PY,
        "stop"
    ])