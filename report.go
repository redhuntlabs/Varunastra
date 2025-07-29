package main

var tmpl = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Varunastra Scan Report</title>
	<style>
		:root {
			--bg-color: #111827;
			--text-color: #f9fafb;
			--muted-text: #9ca3af;
			--border-color: #374151;
			--accent-color: #3b82f6;
		}

		body {
			font-family: system-ui, sans-serif;
			background-color: var(--bg-color);
			color: var(--text-color);
			margin: 0;
			padding: 40px 20px;
			line-height: 1.7;
			margin-left: auto;
			margin-right: auto;
		}

		.header-logos {
			display: flex;
			align-items: center;
			gap: 10px;
			margin-bottom: 24px;
		}

		.main-logo {
			height: 48px;
		}

		.small-logo {
			height: 38px;
		}

		.by-text {
			font-size: 1.1rem;
			color: var(--muted-text);
			font-weight: 500;
		}

		h1 {
			font-size: 2rem;
			font-weight: 600;
			border-bottom: 1px solid var(--border-color);
			padding-bottom: 0.75rem;
			margin-bottom: 2rem;
		}

		h2 {
			font-size: 1.5rem;
			color: var(--accent-color);
			margin: 2.5rem 0 1rem;
			font-weight: 500;
		}

		h3, h4 {
			font-size: 1.125rem;
			margin: 2rem 0 0.5rem;
			font-weight: 500;
			color: var(--text-color);
		}

		.table {
			width: 100%;
			border-collapse: collapse;
			margin-top: 0.75rem;
			font-size: 0.95rem;
		}

		.table th, .table td {
			border: 1px solid var(--border-color);
			padding: 12px;
			text-align: left;
			vertical-align: top;
		}

		.table th {
			background-color: #1f2937;
			font-weight: 500;
		}

		ul {
			padding-left: 1.25rem;
			margin-top: 0.5rem;
		}

		li {
			margin-bottom: 0.4rem;
		}

		p.empty-message {
			color: var(--muted-text);
			font-style: italic;
			font-size: 1rem;
			margin-top: 0.5rem;
		}
	</style>
</head>
<body>
	<div class="header-logos">
		<img class="main-logo" src="https://camo.githubusercontent.com/5c386f6789aaea2f3bc11ab1f2c5d3570170e0eb43c98f6195257b332e45a404/68747470733a2f2f646576616e676861636b732e696e2f766172756e61737472612f63726f7065645f6c6f676f2e706e67" alt="Devang Hacks Logo">
		<span class="by-text">by</span>
		<img class="small-logo" src="https://redhuntlabs.com/wp-content/uploads/2023/02/footer-logo.png" alt="RedHunt Labs Logo">
	</div>

	<h1>Varunastra Scan Results</h1>

	<div class="section">
		<h2>Target: {{.Target}}</h2>

		<h3>Secrets Found:</h3>
		{{if .Secrets}}
		<table class="table">
			<tr>
				<th>Issue</th>
				<th>Path</th>
				<th>Type</th>
				<th>Secret</th>
			</tr>
			{{range .Secrets}}
			<tr>
				<td>{{.Issue}}</td>
				<td>{{.Path}}</td>
				<td>{{.Type}}</td>
				<td>{{.Secret}}</td>
			</tr>
			{{end}}
		</table>
		{{else}}
		<p class="empty-message">No secrets found.</p>
		{{end}}

		<h3>Vulnerabilities Found:</h3>
		{{if .Vulnerability}}
		<table class="table">
			<tr>
				<th>Title</th>
				<th>Issue</th>
			</tr>
			{{range .Vulnerability}}
			<tr>
				<td>{{.Title}}</td>
				<td>{{.Issue}}</td>
			</tr>
			{{end}}
		</table>
		{{else}}
		<p class="empty-message">No vulnerabilities found.</p>
		{{end}}

		<h3>Assets:</h3>

		<h4>Domains:</h4>
		{{if .Assets.Domains}}
		<table class="table">
			<tr>
				<th>Domain</th>
				<th>Subdomains</th>
			</tr>
			{{range .Assets.Domains}}
			<tr>
				<td>{{.Domain}}</td>
				<td>{{range .Subdomains}}{{.}}<br>{{end}}</td>
			</tr>
			{{end}}
		</table>
		{{else}}
		<p class="empty-message">No domains found.</p>
		{{end}}

		<h4>URLs:</h4>
		{{if .Assets.Urls}}
		<ul>
			{{range .Assets.Urls}}
			<li>{{.}}</li>
			{{end}}
		</ul>
		{{else}}
		<p class="empty-message">No URLs found.</p>
		{{end}}

	</div>
</body>
</html>
`
