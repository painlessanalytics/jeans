package main

import "html/template"

var tmplLayout = template.Must(template.New("layout").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Denims — Account Manager</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
    }
    header {
      background: #1e293b;
      border-bottom: 1px solid #334155;
      padding: 1rem 2rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    header h1 { font-size: 1.25rem; font-weight: 600; color: #f1f5f9; }
    header span.badge {
      font-size: 0.7rem;
      background: #3b82f6;
      color: #fff;
      padding: 0.15rem 0.5rem;
      border-radius: 9999px;
      font-weight: 600;
      letter-spacing: 0.05em;
    }
    main { max-width: 900px; margin: 2rem auto; padding: 0 1rem; }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 0.75rem;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .card h2 {
      font-size: 1rem;
      font-weight: 600;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 1rem;
    }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 0.6rem 0.75rem; }
    th {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #64748b;
      border-bottom: 1px solid #334155;
    }
    tr:not(:last-child) td { border-bottom: 1px solid #1e293b; }
    td code { font-family: monospace; color: #7dd3fc; font-size: 0.9rem; }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.4rem 0.9rem;
      border-radius: 0.4rem;
      border: none;
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 500;
      transition: opacity 0.15s;
    }
    .btn:hover { opacity: 0.85; }
    .btn-danger { background: #ef4444; color: #fff; }
    .btn-primary { background: #3b82f6; color: #fff; }
    form.inline { display: inline; }
    .add-form { display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: flex-end; }
    .field { display: flex; flex-direction: column; gap: 0.3rem; }
    .field label { font-size: 0.8rem; color: #94a3b8; font-weight: 500; }
    .field input {
      background: #0f172a;
      border: 1px solid #475569;
      border-radius: 0.4rem;
      color: #f1f5f9;
      padding: 0.45rem 0.75rem;
      font-size: 0.9rem;
      outline: none;
      transition: border-color 0.15s;
    }
    .field input:focus { border-color: #3b82f6; }
    .alert {
      padding: 0.75rem 1rem;
      border-radius: 0.5rem;
      margin-bottom: 1rem;
      font-size: 0.9rem;
    }
    .alert-error { background: #450a0a; border: 1px solid #7f1d1d; color: #fca5a5; }
    .alert-success { background: #052e16; border: 1px solid #14532d; color: #86efac; }
    .empty { color: #475569; font-style: italic; padding: 0.5rem 0; }
  </style>
</head>
<body>
  <header>
    <h1>Denims</h1>
    <span class="badge">Account Manager</span>
  </header>
  <main>
    {{template "content" .}}
  </main>
</body>
</html>
`))

var tmplUsers = template.Must(template.Must(tmplLayout.Clone()).New("content").Parse(`
{{if .Error}}
<div class="alert alert-error">{{.Error}}</div>
{{end}}
{{if .Success}}
<div class="alert alert-success">{{.Success}}</div>
{{end}}

<div class="card">
  <h2>Add User</h2>
  <form class="add-form" method="POST" action="/users">
    <div class="field">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" placeholder="e.g. jsmith" required
             pattern="[a-zA-Z0-9_\-\.]+" maxlength="32" autocomplete="off">
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" placeholder="Initial password" required
             minlength="8" autocomplete="new-password">
    </div>
    <button class="btn btn-primary" type="submit">Add User</button>
  </form>
</div>

<div class="card">
  <h2>Users in /home</h2>
  {{if .Users}}
  <table>
    <thead>
      <tr>
        <th>Username</th>
        <th>Home Directory</th>
        <th>Shell</th>
        <th>Action</th>
      </tr>
    </thead>
    <tbody>
    {{range .Users}}
      <tr>
        <td><code>{{.Username}}</code></td>
        <td><code>{{.HomeDir}}</code></td>
        <td><code>{{.Shell}}</code></td>
        <td>
          <form class="inline" method="POST" action="/users/delete"
                onsubmit="return confirm('Delete user {{.Username}} and their home directory?')">
            <input type="hidden" name="username" value="{{.Username}}">
            <button class="btn btn-danger" type="submit">Delete</button>
          </form>
        </td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{else}}
  <p class="empty">No user home directories found.</p>
  {{end}}
</div>
`))
