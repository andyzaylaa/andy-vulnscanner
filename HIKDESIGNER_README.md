# HikDesigner AI - Security & Building Systems Design Tool

AI-powered software for designing and planning security system installations using Hikvision products. Upload architectural drawings, get AI-powered analysis, and generate comprehensive project reports.

## Features

- **AI Drawing Analysis** - Upload floor plans (PDF/images) and let AI identify areas needing CCTV, access control, fire, sound, and gate systems
- **Product Catalog** - Built-in Hikvision product database with 30+ products across all system types, plus online search
- **BOQ Import** - Import Bill of Quantities from Excel/CSV files with auto-matching to products
- **Symbol Placement** - Place device symbols directly on drawings with drag-and-click positioning
- **Cable & Accessory Calculator** - Automatic calculation of all cables, connectors, brackets, and accessories needed
- **Excel Report Generator** - Professional multi-sheet Excel reports with pricing, cable schedules, and system breakdowns
- **Project Management** - Organize work project-by-project with full tracking

## System Types Supported

| System | Products |
|--------|----------|
| CCTV / Surveillance | Dome, Bullet, PTZ, Fisheye cameras, NVRs, Monitors, Switches |
| Access Control | Face recognition terminals, Card readers, Controllers, Electric locks |
| Gate / Barrier | Boom barriers, Road blockers |
| Video Door Phone | Door stations, Indoor stations, Keypad modules |
| Fire Detection | Smoke detectors, Heat detectors, Manual call points, Sounders, Panels |
| Sound / PA | Ceiling speakers, Horn speakers, Amplifiers |

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- (Optional) OpenAI API key for AI drawing analysis

### Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
pip install -e .
cp .env.example .env
# Edit .env to add your OpenAI API key (optional)
uvicorn app.main:app --reload --port 8000
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The app will be available at `http://localhost:5173`.

## Usage

1. **Create a Project** - Click "New Project" and fill in project details
2. **Upload Drawings** - Upload PDF/image floor plans to your project
3. **AI Analysis** - Click "AI Analyze" on each drawing for automatic system recommendations
4. **Browse Products** - Search and add Hikvision products from the built-in catalog
5. **Import BOQ** - Upload an existing BOQ (Excel/CSV) to import product lists
6. **Place Symbols** - Click on drawings to place device symbols in correct locations
7. **View Cables & Accessories** - See automatically calculated cable runs and accessories
8. **Export Report** - Download a comprehensive Excel report with all project details

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/projects` | Create a new project |
| `POST /api/drawings/upload/{project_id}` | Upload a drawing file |
| `POST /api/drawings/{id}/analyze` | Run AI analysis on a drawing |
| `POST /api/products/search` | Search product catalog |
| `GET /api/products/search-online?q=...` | Search Hikvision website |
| `POST /api/boq/upload/{project_id}` | Import BOQ file |
| `GET /api/reports/{project_id}/excel` | Download Excel report |
| `GET /api/reports/{project_id}/cables` | Calculate cable requirements |
| `GET /api/reports/{project_id}/accessories` | Calculate accessories |

## Tech Stack

- **Backend**: Python, FastAPI, SQLAlchemy, OpenAI API, PyMuPDF, openpyxl
- **Frontend**: React, Vite, React Router, Axios, Lucide Icons
- **Database**: SQLite (can be configured for PostgreSQL)
- **AI**: OpenAI GPT-4o Vision for drawing analysis

## Project Structure

```
hikvision-system-designer/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── config.py            # Configuration
│   │   ├── database.py          # Database setup
│   │   ├── models/
│   │   │   ├── schemas.py       # SQLAlchemy models
│   │   │   └── pydantic_models.py # API schemas
│   │   ├── routers/
│   │   │   ├── projects.py      # Project CRUD
│   │   │   ├── drawings.py      # Drawing upload & analysis
│   │   │   ├── products.py      # Product catalog
│   │   │   ├── boq.py           # BOQ import
│   │   │   └── reports.py       # Report generation
│   │   └── services/
│   │       ├── ai_analyzer.py   # AI drawing analysis
│   │       ├── product_catalog.py # Product database
│   │       ├── drawing_processor.py # File processing
│   │       ├── boq_importer.py  # BOQ file import
│   │       ├── cable_calculator.py # Cable & accessory calc
│   │       └── report_generator.py # Excel report generation
│   └── pyproject.toml
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── ProjectView.jsx
│   │   │   ├── DrawingView.jsx
│   │   │   └── ProductSearch.jsx
│   │   ├── components/
│   │   │   └── Layout.jsx
│   │   └── services/
│   │       └── api.js
│   ├── package.json
│   └── index.html
└── README.md
```
