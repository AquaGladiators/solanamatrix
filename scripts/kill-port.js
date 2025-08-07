import { exec } from 'child_process';
const port = process.argv[2] || 3000;
exec(`netstat -ano | findstr :${port}`, (err, stdout) => {
  if (err || !stdout.trim()) {
    console.log(`No process on port ${port}`);
    return;
  }
  const lines = stdout.trim().split(/\r?\n/);
  const pids = new Set();
  for (const l of lines) {
    const parts = l.trim().split(/\s+/);
    const pid = parts[parts.length - 1];
    pids.add(pid);
  }
  for (const pid of pids) {
    exec(`taskkill /PID ${pid} /F`, () => console.log(`Killed PID ${pid}`));
  }
});
