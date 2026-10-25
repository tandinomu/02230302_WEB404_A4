<!DOCTYPE html>
<!--
  vulnerable.php  ——  INSECURE ON PURPOSE. Teaching example only.

  This page is a "DNS lookup" tool. The user types a host, and we look it up
  with the system command `getent hosts <host>`.

  The security flaw: we build the command by GLUING the raw user input into a
  command STRING and handing that whole string to a shell (shell_exec).
  The shell then parses our text looking for its own special characters
  (; && | $() ` etc.). So the user can smuggle in extra commands.
-->
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Vulnerable DNS Lookup</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 640px; margin: 40px auto; padding: 0 16px; }
    pre  { background: #111; color: #0f0; padding: 12px; border-radius: 6px; white-space: pre-wrap; }
    input{ padding: 6px; width: 320px; }
    .tag { color: #c0392b; font-weight: bold; }
  </style>
</head>
<body>
  <h1>DNS Lookup <span class="tag">(vulnerable)</span></h1>
  <form method="get">
    <label>Host to look up:
      <input type="text" name="host" value="<?php echo htmlspecialchars($_GET['host'] ?? '', ENT_QUOTES); ?>">
    </label>
    <button type="submit">Look up</button>
  </form>

<?php
// Only act when the form was submitted with a "host" field.
if (isset($_GET['host']) && $_GET['host'] !== '') {

    // Take the user input EXACTLY as typed — no checks, no escaping.
    $host = $_GET['host'];

    // Build the command by concatenating the raw input into a string.
    // THIS is the vulnerability: $host can contain shell metacharacters.
    $cmd = "getent hosts " . $host;

    // shell_exec() runs the string through /bin/sh, which interprets
    // any shell syntax inside $host. We capture and show the output.
    $output = shell_exec($cmd . " 2>&1");

    // Show the exact command we ran, then its output, so the lab is clear.
    echo "<h2>Command executed on the server:</h2>";
    echo "<pre>" . htmlspecialchars($cmd, ENT_QUOTES) . "</pre>";
    echo "<h2>Output:</h2>";
    echo "<pre>" . htmlspecialchars($output ?? '(no output)', ENT_QUOTES) . "</pre>";
}
?>
</body>
</html>
