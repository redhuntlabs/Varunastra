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
			--bg-color: #f0f4f8;
			--card-bg: #ffffff;
			--text-color: #2e3a59;
			--muted-text: #6b7280;
			--table-header: #e5eaf1;
			--border-color: #d1d5db;
			--accent-color: #3b82f6;
		}

		body {
			font-family: 'Helvetica Neue', sans-serif;
			background-color: var(--bg-color);
			color: var(--text-color);
			margin: 0;
			padding: 40px 20px;
			line-height: 1.6;
		}

		h1, h2, h3, h4 {
			margin-top: 0;
		}

		h1 {
			font-size: 2rem;
			margin-bottom: 30px;
			border-bottom: 2px solid var(--border-color);
			padding-bottom: 10px;
		}

		.section {
			background-color: var(--card-bg);
			border-radius: 10px;
			box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
			padding: 25px 30px;
			margin-bottom: 30px;
			transition: background-color 0.3s;
		}

		.section:hover {
			background-color: #fdfefe;
		}

		.table {
			width: 100%;
			border-collapse: collapse;
			margin-top: 10px;
			border-radius: 6px;
			overflow: hidden;
		}

		.table th, .table td {
			border: 1px solid var(--border-color);
			padding: 12px 14px;
			text-align: left;
		}

		.table th {
			background-color: var(--table-header);
			color: var(--text-color);
			font-weight: 600;
		}

		ul {
			padding-left: 20px;
			margin-top: 10px;
		}

		li {
			margin-bottom: 6px;
		}

		p.empty-message {
			color: var(--muted-text);
			font-style: italic;
			margin-top: 5px;
		}

		h2 {
			color: var(--accent-color);
			margin-bottom: 15px;
		}

		h3, h4 {
			margin-top: 20px;
			color: #374151;
		}
	</style>
</head>
<body>
	<h1>Scan Results</h1>
	{{range .}}
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
	{{end}}
</body>
</html>
`
