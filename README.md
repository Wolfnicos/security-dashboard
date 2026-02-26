# Security Dashboard

A web-based security monitoring dashboard built with Flask. Aggregates, analyzes, and visualizes security events from multiple sources into a single pane of glass.

## Features

- Real-time security event ingestion and display
- SQLite-backed event storage with search and filtering
- Threat severity classification and alerting
- Data analysis and reporting with Pandas
- External threat feed integration via REST APIs
- Responsive web UI

## Project Structure

```
security-dashboard/
├── app/
│   ├── routes/          # Flask route blueprints
│   ├── models/          # Database models
│   ├── services/        # Business logic
│   ├── templates/       # Jinja2 HTML templates
│   └── static/          # CSS, JS, images
├── tests/               # Unit and integration tests
├── migrations/          # Database migrations
├── config/              # Environment-specific config
├── scripts/             # Utility and maintenance scripts
├── docs/                # Documentation
├── requirements.txt
└── run.py               # Application entry point
```

## Quick Start

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

## License

MIT
