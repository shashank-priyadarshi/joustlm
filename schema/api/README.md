# API Schema Documentation

This directory contains the API schema definitions for the JoustLM LLM Knowledge Extractor application, focused exclusively on LLM text analysis functionality.

## Schema Files

### Core Schemas

#### `auth.go` - Authentication
- **LoginRequest/LoginResponse**: User login with JWT tokens
- **SignupRequest/SignupResponse**: User registration with JWT tokens

#### `common.go` - Common Types
- **CommonResponse**: Standard API response wrapper
- **NoContentResponse**: Empty response type
- **ErrorResponse**: Error handling

#### `errors.go` - Error Handling
- **ErrorResponse**: Standardized error response format

#### `health.go` - Health Checks
- **HealthResponse**: Application health status
- Health status constants (OK, ERROR, WARNING)

#### `llm.go` - LLM Text Analysis (Assignment Core)
- **LLMAnalysisRequest/LLMAnalysisResponse**: Core LLM text analysis
- **KnowledgeBaseEntry**: Knowledge storage structure
- **CreateKnowledgeRequest/UpdateKnowledgeRequest**: Knowledge management
- **GetKnowledgeResponse**: Knowledge retrieval with pagination
- **SearchRequest/SearchResponse**: Search functionality by topic/keyword

#### `metrics.go` - Application Metrics
- **MetricsResponse**: Application performance metrics
- **Metrics**: LLM analysis metrics (analyses, users, confidence scores)

## API Endpoints Alignment

The schemas support the following API endpoints as defined in the README:

### Authentication
- `POST /api/v1/auth/login` → `LoginRequest/LoginResponse`
- `POST /api/v1/auth/signup` → `SignupRequest/SignupResponse`
- `POST /api/v1/auth/logout` → `NoContentResponse`

### LLM Extraction (Assignment Core)
- `POST /api/v1/extract` → `LLMAnalysisRequest/LLMAnalysisResponse`
- `GET /api/v1/extract/:id` → `LLMAnalysisResponse`

### Knowledge Base Management
- `GET /api/v1/knowledge` → `GetKnowledgeResponse`
- `POST /api/v1/knowledge` → `CreateKnowledgeRequest/KnowledgeBaseEntry`
- `PUT /api/v1/knowledge/:id` → `UpdateKnowledgeRequest/KnowledgeBaseEntry`
- `DELETE /api/v1/knowledge/:id` → `NoContentResponse`

### Search Functionality (Assignment Requirement)
- `GET /api/search?topic=xyz` → `SearchRequest/SearchResponse`

### Health & Documentation
- `GET /health` → `HealthResponse`
- `GET /api` → OpenAPI specification
- `GET /swagger/` → Interactive Swagger UI

## Assignment Requirements Met

The API schemas directly support the assignment requirements:
- ✅ **Text Analysis**: `LLMAnalysisRequest` for unstructured text input
- ✅ **LLM Processing**: `LLMAnalysisResponse` with summary and structured data
- ✅ **Structured Data**: Fields for title, topics, sentiment, keywords
- ✅ **Custom Keywords**: Keywords field for 3 most frequent nouns
- ✅ **Data Persistence**: `KnowledgeBaseEntry` for storage
- ✅ **Search Functionality**: `SearchRequest/Response` for topic/keyword search
- ✅ **User Authentication**: JWT-based auth schemas
- ✅ **Error Handling**: Comprehensive error response types

## Data Types

### Core Analysis Fields
- **Text**: Original unstructured input
- **Title**: Extracted title (optional)
- **Summary**: 1-2 sentence LLM-generated summary
- **Topics**: Array of 3 key topics
- **Sentiment**: positive/neutral/negative
- **Keywords**: Array of 3 most frequent nouns
- **Confidence**: Analysis confidence score

### UUID Usage
All entities use UUID primary keys for better scalability and security.

### Timestamps
All entities include `created_at` and `updated_at` timestamps for audit trails.
