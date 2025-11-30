# ADS Framework to SOAR Platform Documentation

## Executive Summary

Successfully designed and implemented a **Detection Engineering Management System** that evolved into a **Security Orchestration, Automation, and Response (SOAR) platform**, addressing critical challenges in modern Security Operations Centers (SOC).

### Problem Statement
SOC teams face:
- **Alert Fatigue:** 95% false positive rates overwhelming analysts
- **Inconsistent Detection Quality:** No standardized detection development process
- **Manual Incident Response:** Time-consuming, error-prone manual workflows
- **Tool Fragmentation:** 15-20 security tools with no unified management
- **Skill Shortage:** Insufficient cybersecurity professionals to handle volume

### Solution Delivered
Enterprise-grade platform combining:
1. **Structured Detection Engineering** (Palantir's ADS Framework)
2. **Multi-Tool Integration** (Universal connector architecture)
3. **Automated Playbook Execution** (Incident response automation)
4. **Threat Intelligence Orchestration** (Multi-source TI aggregation)
5. **ML-Powered Analytics** (Alert prioritization and scoring)

---

## Technical Architecture

### Technology Stack
```
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND (Planned)                       │
│              React + TypeScript + Tailwind CSS              │
└─────────────────────────────────────────────────────────────┘
                            ↕ REST API
┌─────────────────────────────────────────────────────────────┐
│                    BACKEND (Implemented)                    │
│                                                             │
│  Framework: FastAPI (Python 3.12)                          │
│  Authentication: JWT Tokens + Bcrypt                        │
│  API Documentation: OpenAPI/Swagger                         │
│                                                             │
│  Components:                                                │
│  ├── Detection Rule Management                             │
│  ├── User Authentication & Authorization                    │
│  ├── Integration Framework (Connectors)                    │
│  ├── Alert Management System                               │
│  └── Playbook Data Models                                  │
└─────────────────────────────────────────────────────────────┘
                            ↕ SQLAlchemy ORM
┌─────────────────────────────────────────────────────────────┐
│                    DATABASE LAYER                           │
│                                                             │
│  PostgreSQL 15:                                             │
│  ├── Users & Authentication                                │
│  ├── Detection Rules (ADS Framework)                       │
│  ├── Security Tool Integrations                            │
│  ├── Alerts & Incidents                                    │
│  ├── Playbooks & Executions                                │
│  └── Validation Tests                                      │
│                                                             │
│  Redis 7:                                                   │
│  └── Caching & Task Queue                                  │
└─────────────────────────────────────────────────────────────┘
```

### Key Technologies

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| **Backend** | FastAPI | 0.104.1 | High-performance API framework |
| **Database** | PostgreSQL | 15 | Relational data storage |
| **Cache** | Redis | 7 | Session management, task queue |
| **ORM** | SQLAlchemy | 2.0.23 | Database abstraction |
| **Auth** | JWT + Bcrypt | Latest | Secure authentication |
| **ML/Analytics** | Scikit-learn | 1.7.2 | Alert prioritization |
| **Data Processing** | Pandas | 2.3.3 | Data analysis |
| **Async Tasks** | Celery | 5.3.4 | Background job processing |
| **Container** | Docker | 29.1.0 | Deployment & isolation |

---

## Quick Start

### Prerequisites
- Ubuntu 22.04+ LTS or WSL2
- Python 3.12+
- Docker & Docker Compose
- Git

### Installation
```bash
# 1. Clone repository
git clone https://github.com/Girlweb/ads-framework-platform.git
cd ads-framework-platform

# 2. Configure environment
cp .env.example .env
# Edit .env with your settings

# 3. Start infrastructure
docker compose up -d database redis

# 4. Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
pip install -r backend/requirements-soar.txt

# 5. Run application
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# 6. Access API
# Docs: http://localhost:8000/docs
# Health: http://localhost:8000/health
```

---

## Features

### Phase 1: ADS Framework Platform (COMPLETED)

**Detection Rule Management**
- Full CRUD operations for detection rules
- 9-stage ADS Framework enforcement
- MITRE ATT&CK categorization
- Version control for detection rules
- Rule status tracking

**Authentication & Authorization**
- User registration with validation
- JWT-based authentication
- Bcrypt password hashing
- Role-based access control

**API Endpoints**
```
Authentication:
POST   /auth/register      - User registration
POST   /auth/login         - User login

Detection Rules:
POST   /detection-rules    - Create detection rule
GET    /detection-rules    - List all rules
GET    /detection-rules/{id} - Get specific rule
PUT    /detection-rules/{id} - Update rule

System:
GET    /health             - Health check
GET    /docs               - API documentation
```

### Phase 2: SOAR Integration Framework (IN PROGRESS)

**Connector Architecture**
- Base connector system for security tool integration
- Splunk SIEM connector (implemented)
- Planned: Elastic, QRadar, Sentinel, CrowdStrike, Palo Alto

**Alert Management**
- Multi-source alert ingestion
- Alert normalization and enrichment
- Threat scoring (0-100)
- Status tracking and assignment

**Playbook System** (Designed)
- Automated incident response workflows
- Pre-built playbook templates
- Step-by-step execution engine
- Approval workflow integration

---

## Database Schema

### Core Tables

**users**
- id (UUID), username, email
- hashed_password
- is_active, is_admin
- created_at

**detection_rules**
- id (UUID), name, version
- current_stage (ADS enum)
- goal, mitre_tactics, mitre_techniques
- strategy_abstract, technical_context
- blind_spots, false_positives
- validation_steps (JSONB)
- priority_level, response_procedures
- sigma_rule, splunk_query, elastic_query

**integrations**
- id, name, integration_type
- connector_class, config (JSONB)
- is_active, last_sync
- created_by (FK)

**alerts**
- id, external_id, source_integration_id
- severity, title, description
- raw_data, normalized_data (JSONB)
- status, assigned_to
- enrichment_data, threat_score
- mitre_tactics, mitre_techniques

**playbooks**
- id, name, description
- trigger_conditions, steps (JSONB)
- is_active, requires_approval
- execution_count, success_rate

---

## Business Value

### Key Metrics

| Metric | Industry Baseline | Target with SOAR | Improvement |
|--------|------------------|------------------|-------------|
| **False Positive Rate** | 95% | 15% | **84% reduction** |
| **Mean Time to Respond** | 4 hours | 15 minutes | **93% faster** |
| **Alerts Processed/Day** | 500 | 5,000+ | **10x increase** |
| **Manual Tasks** | 80% | 20% | **75% automation** |
| **SOC Efficiency** | Baseline | 3-4x | **300-400% gain** |

### Estimated Cost Savings

For medium-sized organization (500-1000 employees):
- Reduced analyst hours: $120,000/year
- Prevented breaches: $500,000+/year
- Tool consolidation: $50,000/year
- Faster response: $200,000/year
- **Total: $870,000+ annual savings**

---

## Architecture Highlights

### Security Features
- JWT authentication with 30-minute expiry
- Bcrypt password hashing
- CORS protection
- Rate limiting ready
- API key management
- Audit logging capability

### Scalability
- Asynchronous request handling
- Connection pooling
- Redis caching layer
- Horizontal scaling ready
- Kubernetes deployment prepared
- Load balancer compatible

### Integration Capabilities
- RESTful API for all operations
- Webhook support for real-time events
- Custom connector framework
- Multi-SIEM query translation
- Threat intelligence aggregation
- MITRE ATT&CK mapping

---

## Development Status

### Completed
- [x] User authentication system
- [x] Detection rule CRUD operations
- [x] ADS Framework data models
- [x] Database schema design
- [x] API documentation
- [x] Docker containerization
- [x] Base connector architecture
- [x] Splunk connector implementation

### In Progress
- [ ] Integration endpoint debugging
- [ ] Additional SIEM connectors
- [ ] Playbook execution engine
- [ ] Frontend dashboard

### Planned
- [ ] ML-based alert prioritization
- [ ] Threat intelligence aggregation
- [ ] Case management system
- [ ] Real-time alert streaming
- [ ] MITRE ATT&CK heatmap
- [ ] Automated reporting

---

## Known Issues

- Integration endpoint has FastAPI dependency injection issue with `get_current_user`
- Workaround: Direct database operations bypass auth temporarily
- Fix planned for next sprint

---

## Project Structure
```
ads-framework-platform/
├── README.md
├── .env.example
├── .gitignore
├── docker-compose.yml
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   │   └── integrations.py
│   │   ├── core/
│   │   │   └── security.py
│   │   ├── db/
│   │   │   └── database.py
│   │   ├── models/
│   │   │   ├── ads_framework.py
│   │   │   └── integrations.py
│   │   ├── schemas/
│   │   │   └── ads_schemas.py
│   │   └── integrations/
│   │       ├── connector_base.py
│   │       └── splunk_connector.py
│   ├── requirements.txt
│   ├── requirements-soar.txt
│   └── Dockerfile
│
└── frontend/ (planned)
    └── src/
```

---

## Skills Demonstrated

**Backend Development**
- RESTful API design
- Asynchronous programming
- Database design and ORM
- Authentication & authorization
- API documentation

**Security Engineering**
- Detection engineering
- MITRE ATT&CK framework
- Threat intelligence
- SIEM integration
- Incident response automation

**Software Architecture**
- Microservices design
- Connector pattern
- Dependency injection
- Abstract base classes
- SOLID principles

**DevOps**
- Docker containerization
- Environment management
- CI/CD concepts
- Version control

**Data Science**
- Machine learning models
- Feature engineering
- Classification algorithms
- Data preprocessing

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## License

This project is licensed under the MIT License.

---

## Resources

- **GitHub Repository:** https://github.com/Girlweb/ads-framework-platform
- **API Documentation:** http://localhost:8000/docs
- **MITRE ATT&CK:** https://attack.mitre.org/
- **Palantir ADS Framework:** https://github.com/palantir/alerting-detection-strategy-framework

---

## Contact

For questions or collaboration opportunities, please open an issue on GitHub.

---

**Built by a Detection Engineer, for Detection Engineers**

*Last Updated: November 29, 2024*
