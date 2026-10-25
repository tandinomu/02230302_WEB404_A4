<!DOCTYPE html>
<!--
  secure.php  ——  The hardened version of the DNS lookup tool.

  Two safeguards, strongest first:

  (1) NO SHELL. We never build a command string for /bin/sh. Instead we pass
      the program and its arguments as a LIST to proc_open(). PHP launches the
      binary directly, so the shell never runs and never interprets
      metacharacters (; | && $() ``). Whatever the user typed is delivered to
      getent as ONE literal hostname argument.

  (2) STRICT WHITELIST VALIDATION. Before we run anything, the input must match
      a valid IPv4 address OR a valid hostname. If it does not match, we reject
      it and run nothing at all.
-->
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure DNS Lookup</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 640px; margin: 40px auto; padding: 0 16px; }
    pre  { background: #111; color: #0f0; padding: 12px; border-radius: 6px; white-space: pre-wrap; }
    input{ padding: 6px; width: 320px; }
    .tag { color: #27ae60; font-weight: bold; }
    .reject { background: #fdecea; color: #c0392b; padding: 12px; border-radius: 6px; font-weight: bold; }
  </style>
</head>
<body>
  <h1>DNS Lookup <span class="tag">(secure)</span></h1>
  <form method="get">
    <label>Host to look up:
      <input type="text" name="host" value="<?php echo htmlspecialchars($_GET['host'] ?? '', ENT_QUOTES); ?>">
    </label>
    <button type="submit">Look up</button>
  </form>

<?php
/**
 * Safeguard 2: whitelist validation.
 * Returns true ONLY for a valid IPv4 address or a valid hostname.
 */
function is_valid_host(string $host): bool {
    // Accept a well-formed IPv4 address, e.g. 127.0.0.1
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return true;
    }
    // Accept a hostname: letters/digits/hyphens in dot-separated labels,
    // e.g. localhost or www.example.com. No spaces, no shell characters,
    // nothing but the characters a real hostname is allowed to contain.
    $pattern = '/^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
             . '(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/';
    return (bool) preg_match($pattern, $host);
}

/**
 * Safeguard 1: run the lookup WITHOUT a shell.
 * The command is an ARRAY, so proc_open executes getent directly and the
 * hostname is passed as a single literal argument — no shell parsing.
 */
function run_lookup(string $host): string {
    $descriptors = [
        1 => ['pipe', 'w'],  // capture stdout
        2 => ['pipe', 'w'],  // capture stderr
    ];
    // NOTE: an ARRAY here, not a string. This is what avoids /bin/sh.
    $proc = proc_open(['getent', 'hosts', $host], $descriptors, $pipes);
    if (!is_resource($proc)) {
        return '(could not start lookup)';
    }
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
    $result = trim($out . $err);
    return $result === '' ? '(no matching host found)' : $result;
}

if (isset($_GET['host']) && $_GET['host'] !== '') {
    $host = $_GET['host'];

    if (!is_valid_host($host)) {
        // Rejected by the whitelist: we run NOTHING.
        echo '<p class="reject">Rejected: that is not a valid IP address or '
           . 'hostname. Nothing was run.</p>';
    } else {
        $output = run_lookup($host);
        echo "<h2>Lookup ran safely (no shell) for:</h2>";
        echo "<pre>" . htmlspecialchars($host, ENT_QUOTES) . "</pre>";
        echo "<h2>Output:</h2>";
        echo "<pre>" . htmlspecialchars($output, ENT_QUOTES) . "</pre>";
    }
}
?>
</body>
</html>
