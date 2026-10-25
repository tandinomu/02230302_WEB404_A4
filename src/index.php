<!DOCTYPE html>
<!-- index.php : simple landing page linking to both versions of the tool. -->
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WEB404 A4 — Command Injection Lab</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 640px; margin: 40px auto; padding: 0 16px; }
    .card { border: 1px solid #ccc; border-radius: 8px; padding: 16px; margin: 16px 0; }
    .vuln { border-color: #c0392b; }
    .safe { border-color: #27ae60; }
    code { background: #f4f4f4; padding: 2px 4px; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>DNS Lookup Tool — Command Injection Lab</h1>
  <p>WEB404 Secure Coding Practices · Practical Assignment 4</p>

  <div class="card vuln">
    <h2>🔴 Vulnerable version</h2>
    <p>Passes your input straight to the system shell. <strong>Do not copy this pattern.</strong></p>
    <p><a href="vulnerable.php">Open vulnerable.php</a></p>
  </div>

  <div class="card safe">
    <h2>🟢 Secure version</h2>
    <p>No shell, plus strict whitelist validation.</p>
    <p><a href="secure.php">Open secure.php</a></p>
  </div>
</body>
</html>
