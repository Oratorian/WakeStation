import os

secret_key = "your_secret_key_here"
DB_DIR = os.path.join(
    ".", "db"
)  # Directory where all confugurations and databases are stored
USERS_FILE = os.path.join(DB_DIR, "users.json")  # Name of the users file
PC_DATA_DIR = os.path.join(
    DB_DIR, "pcs"
)  # Directory where user-specific JSON files will be stored
STATIC_DIR = os.path.join(
    "."
)  # Must be set to whereever wol_server.py is stored, to serve static files in /template
KEY_DIR = os.path.join(DB_DIR, "enc.bin")
SD_DAEMON_PORT = "8080"  # Port on which the shutdown-daemon process runs
interface = "eno1"  # 	The Network interface the Magic-Packet gets send to
# 	run : sudo lshw -C network | awk '/logical name:/ {name=$3} /ip=/ {ip=$2} /link=yes/ {print name, ip}'
# 	to find the active network adapter with your internal IP.
