# JoustLM - LLM Knowledge Extractor

A prototype LLM knowledge extractor that takes unstructured text input and uses an LLM to produce both summaries and structured data. Built with Go backend and vanilla JavaScript frontend as a take-home assignment.

> **Assignment**: This project was built as a 90-minute take-home assignment for a Software Engineer position. It demonstrates core functionality for text analysis, LLM integration, and data persistence while maintaining simplicity and clarity over feature completeness.

## Features

- **LLM Knowledge Extraction**: Extract structured knowledge from unstructured text via LLM API
- **Text Analysis**: Accept unstructured text input (articles, blog posts, updates)
- **Structured Data Extraction**: Generate 1-2 sentence summaries and extract metadata (title, topics, sentiment, keywords)
- **Custom Keyword Extraction**: Custom implementation to find the 3 most frequent nouns
- **Knowledge Base Management**: Store, update, and query extracted knowledge entries
- **User Management**: JWT-based authentication system with secure session handling
- **Modern Frontend**: Responsive web UI for exploring and managing extracted knowledge
- **Real-Time Updates**: Live updates for new extractions and knowledge entries
- **Enhanced UI**: Pronounced hover effects, shadows, and smooth animations
- **Docker Support**: Fully containerized with Docker Compose
- **SQLite Database**: Lightweight data persistence with proper NULL handling
- **Configuration Management**: YAML-based configuration system with configurable frontend paths
- **Comprehensive Logging**: Structured logging with configurable levels
- **Testing Suite**: Unit and integration tests using Go testing package and testcontainers
- **Development Tools**: Git hooks, commitlint, and golangci-lint for code quality
- **Complete API Documentation**: OpenAPI 3.0.3 specification with interactive Swagger UI
- **Interactive API Testing**: Built-in Swagger UI for testing all endpoints
- **Error Handling**: Robust handling of empty input and LLM API failures

## Architecture

### Backend (Go)
- REST API server with JWT authentication
- LLM extraction endpoints for submitting prompts and receiving structured knowledge
- Static file server for frontend assets with configurable paths
- SQLite database integration for storing extracted knowledge and user data
- YAML-based configuration management
- Structured logging system
- Health check endpoints with JSON responses
- Comprehensive testing with Go testing package
- Complete OpenAPI 3.0.3 documentation with interactive Swagger UI
- Advanced knowledge management endpoints
- Input validation and error handling for LLM extraction requests
- Custom keyword extraction algorithm to find frequent nouns

### Frontend (Vanilla JS)
- Modern, responsive web interface for managing and visualizing extracted knowledge
- JWT-based authentication with secure token handling
- Real-time updates for new extractions and knowledge entries
- Advanced knowledge operations (create, update, delete, query)
- Pagination and filtering support for large knowledge bases
- Copy-to-clipboard functionality for extracted results
- Dark theme and enhanced UI with smooth animations
- Enhanced hover effects and visual feedback
- Configuration-driven API endpoints

### Infrastructure
- Docker Compose for local development
- SQLite database for data persistence
- Health monitoring and checks
- Testcontainers for integration testing

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Go 1.25+ (for local development)

### Using Docker Compose (Recommended)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/shashank-priyadarshi/joustlm.git
   cd joustlm
   ```

2. **Start all services**:
```bash
   docker-compose -f build/compose.yml up -d
   ```

3. **Access the application**:
   - Frontend: http://localhost:8080
   - Backend API: http://localhost:8080/api/
   - Swagger UI: http://localhost:8080/swagger/

### Local Development

1. **Start the application**:
   ```bash
   go run cmd/joustlm.go
   ```

2. **Access the application**:
   - Frontend: http://localhost:8080
   - Backend API: http://localhost:8080/api
   - Swagger UI: http://localhost:8080/swagger/

## Configuration

The application uses YAML configuration files:

- `config/config.yml`: Main application configuration

### Key Configuration Options

```yaml
server:
  port: "8080"
  host: "127.0.0.1"
  frontend_assets_path: ""  # Empty for development, set to "frontend" for production
  logging:
    level: "debug"  # Options: debug, info, warn, error
    format: "json"  # Options: json, text
    output: "stdout"  # Options: stdout, stderr, file
    caller_depth:
      backend: 8
      frontend: 8
  cors:
    allowed_origins: ["*"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_headers: ["*"]
    allow_credentials: true
    expose_headers: ["*"]
    max_age: 3600
  database:
    dsn:
      users: "file:joustlm.db?cache=shared&mode=rwc"
      analyses: "file:joustlm.db?cache=shared&mode=rwc"
  security:
    jwt_secret: "your-jwt-secret-key-change-in-production"
    password_salt: "your-password-salt-change-in-production"
    token_expiry_hours: 24
  llm:
    tokenizer:
      model: "bert-base-uncased"
      config: "tokenizer.json"
      max_length: 4000
      stride: 512
      padding: "max_length"
    summarizer:
      base_url: "https://generativelanguage.googleapis.com/v1beta/models"
      endpoint: "/gemini-2.0-flash:generateContent"
      api_key: "your-gemini-api-key"
      model: "gemini-2.0-flash"
```

### API Key Configuration

The application uses Google's Gemini AI for text analysis. To get your API key:

1. Visit [Google AI Studio](https://aistudio.google.com/)
2. Sign in with your Google account
3. Navigate to the API key section
4. Generate a new API key for Gemini
5. Configure the API key in your `config/config.yml` file under the `llm.summarizer.api_key` field

> **Note**: The API key used in this project has been generated from the Google Gemini AI Studio playground at [https://aistudio.google.com/](https://aistudio.google.com/)

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/signup` - User signup
- `POST /api/v1/auth/logout` - User logout

### LLM Extraction (Assignment Core)
- `POST /api/v1/extract` - Submit prompt to LLM and extract knowledge (assignment requirement)
- `GET /api/v1/extract/:id` - Get extraction result by ID

### Knowledge Base Management
- `GET /api/v1/knowledge?page=1&limit=10` - List extracted knowledge entries
- `POST /api/v1/knowledge` - Add new knowledge entry manually
- `PUT /api/v1/knowledge/:id` - Update knowledge entry
- `DELETE /api/v1/knowledge/:id` - Delete knowledge entry

### Health & Documentation
- `GET /health` - Health check endpoint (JSON response)
- `GET /api` - OpenAPI 3.0.3 specification
- `GET /swagger/` - Interactive Swagger UI for API testing

## API Testing with Swagger UI

The application provides an interactive Swagger UI for testing all API endpoints:

### Accessing Swagger UI
- **URL**: http://localhost:8080/swagger/
- **Features**: Interactive API documentation with "Try it out" functionality

### Testing Workflow

1. **Start the application** (Docker Compose or local development)
2. **Open Swagger UI** in your browser: http://localhost:8080/swagger/
3. **Authentication Flow**:
   - Use `POST /api/v1/auth/signup` to create a new user
   - Use `POST /api/v1/auth/login` to authenticate and get JWT token
   - Click "Authorize" button in Swagger UI and enter: `Bearer <your-jwt-token>`
4. **Test LLM Extraction (Assignment Core)**:
   - `POST /api/v1/extract` - Submit a prompt and receive extracted knowledge
   - `GET /api/v1/extract/{id}` - Retrieve extraction results
5. **Test Knowledge Management**:
   - `POST /api/v1/knowledge` - Add new knowledge entry
   - `GET /api/v1/knowledge` - List knowledge entries
   - `PUT /api/v1/knowledge/{id}` - Update entry
   - `DELETE /api/v1/knowledge/{id}` - Delete entry

## Demo Credentials

- **Username**: `demo`
- **Password**: `demo123`

> **Note**: Demo mode has been removed from the frontend. All functionality now requires actual user registration and authentication.

## Project Structure

```
joustlm/
├── build/
│   ├── compose.yml          # Docker Compose configuration
│   └── Dockerfile           # Backend container definition
├── config/
│   ├── config.go            # Configuration management
│   └── config.yml           # Application configuration
├── frontend/
│   ├── index.html           # Main HTML file
│   ├── styles.css           # CSS styling with dark theme
│   ├── script.js            # JavaScript functionality
│   ├── config.js            # Configuration loader
│   └── config.json          # Frontend configuration
├── assets/
│   └── openapi.json         # OpenAPI 3.0.3 specification
├── logger/
│   └── logger.go            # Logging utilities
├── scripts/
│   └── setup.sh             # Setup script
├── cmd/
│   └── joustlm.go           # Application entry point
├── .githooks/               # Git hooks for code quality
├── go.mod                   # Go module dependencies
├── go.sum                   # Go module checksums
└── README.md
```

## Design Choices

I chose Go for the backend because it provides excellent performance, built-in concurrency support, and strong typing which helps prevent runtime errors. The SQLite database was selected for its simplicity and zero-configuration setup, perfect for a prototype. I implemented custom keyword extraction using Go's text processing libraries rather than relying on the LLM to ensure the most frequent nouns are accurately identified. The vanilla JavaScript frontend keeps the system lightweight and avoids complex build processes, while Docker Compose ensures easy deployment and consistent environments across different systems.

## Development

### Backend Development
The backend is built with Go and uses:
- SQLite database for data persistence
- YAML configuration management
- Structured logging
- JWT authentication
- Go testing package for unit tests
- LLM integration for text analysis
- Custom keyword extraction algorithm
- Error handling for edge cases

### Frontend Development
The frontend uses vanilla JavaScript with:
- Modern ES6+ features and async/await
- Fetch API for HTTP requests with proper error handling
- Local storage for JWT tokens and user data
- Responsive CSS Grid/Flexbox layout
- Dark theme for knowledge blocks with smooth animations
- Enhanced hover effects and visual feedback
- Configuration-driven API endpoints

### Development Tools
- **Git Hooks**: Pre-commit hooks for code quality (see `.githooks/` directory)
- **Commitlint**: Conventional commit message validation
- **Golangci-lint**: Comprehensive Go linting
- **Go Testing**: Unit tests using Go's built-in testing package
- **Setup Script**: `scripts/setup.sh` for initial development environment setup

### Testing
Run the test suite:
```bash
go test ./...

go test -v ./...

go test -cover ./...

go test ./internal/...
```

## Trade-offs Made Due to Time Constraints

Given the 90-minute timebox, I focused on demonstrating the core assignment requirements while maintaining professional development practices. While the system includes comprehensive features like JWT authentication, Swagger UI, git hooks, and testing infrastructure, I prioritized the core LLM text analysis functionality. The custom keyword extraction algorithm was implemented to meet the assignment requirement of finding frequent nouns without LLM assistance. I maintained the existing professional structure and best practices to show understanding of production-ready development, but focused implementation time on the core text analysis, structured data extraction, and search functionality as specified in the assignment requirements.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

**Shashank Priyadarshi** - [email@ssnk.in](mailto:email@ssnk.in)
