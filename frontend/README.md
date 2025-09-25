# Frontend Assets

This directory contains the frontend assets for the JoustLM service - an AI-powered knowledge extraction platform.

## Files

- `index.html` - Main HTML file with responsive layout for knowledge extraction
- `styles.css` - CSS styling with modern design and enhanced animations
- `script.js` - JavaScript functionality for LLM analysis and knowledge management
- `config.js` - Configuration loader and API endpoint management
- `config.json` - Configuration file for API endpoints and UI settings

## Features

### AI-Powered Text Analysis
- **LLM Integration**: Analyze text using Gemini 2.0 Flash model
- **Knowledge Extraction**: Extract topics, keywords, sentiment, and summaries
- **Confidence Scoring**: Display analysis confidence levels
- **Real-time Results**: Immediate display of analysis results
- **Auto-Save**: All analyses are automatically saved to knowledge base

### Knowledge Base Management
- **Automatic Storage**: Every text analysis is automatically saved
- **Search & Filter**: Search by topic, keyword, or sentiment
- **CRUD Operations**: View, update, and delete knowledge entries
- **Pagination**: Navigate through large knowledge collections

### Enhanced User Interface
- **Modern Design**: Clean, professional interface with gradient backgrounds
- **Responsive Layout**: Mobile-friendly design with adaptive components
- **Visual Feedback**: Success/error messages with auto-dismiss timers
- **Interactive Elements**: Hover effects and smooth transitions
- **Tag System**: Visual representation of topics and keywords

### Configuration System
The frontend uses `config.json` to manage:
- **API Endpoints**: All backend API endpoints with parameter substitution
- **UI Settings**: Pagination, timeouts, and loading delays
- **Application Metadata**: App name, version, and branding
- **Error Handling**: Centralized error message timeouts

## API Integration

### Endpoints Used
- `POST /api/v1/auth/login` - User authentication
- `POST /api/v1/auth/signup` - User registration
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/extract` - Analyze text using LLM
- `GET /api/v1/extract/:id` - Get specific analysis result
- `GET /api/v1/knowledge` - Get paginated knowledge entries
- `POST /api/v1/knowledge` - Create new knowledge entry
- `PUT /api/v1/knowledge/:id` - Update knowledge entry
- `DELETE /api/v1/knowledge/:id` - Delete knowledge entry
- `GET /api/search` - Search knowledge base

### Authentication
- JWT token-based authentication
- Automatic token validation on page load and visibility change
- Secure token storage in localStorage
- Automatic logout on token expiration

## UI Components

### Text Analysis Form
- **Text Input**: Large textarea for input text
- **Model Selection**: Choose LLM model (currently Gemini 2.0 Flash)
- **Analysis Button**: Submit text for AI analysis

### Analysis Results Display
- **Title**: Generated title for the analysis
- **Summary**: AI-generated summary of the text
- **Topics**: Extracted topics as visual tags
- **Keywords**: Important keywords as highlighted tags
- **Sentiment**: Sentiment analysis with color-coded badges
- **Confidence**: Analysis confidence percentage
- **Original Text**: Source text in formatted display

### Knowledge Base Interface
- **Entry List**: Paginated list of saved knowledge entries
- **Search Form**: Filter by topic, keyword, or sentiment
- **Entry Actions**: View, edit, and delete operations
- **Metadata Display**: Creation and update timestamps

### Visual Elements
- **Confidence Badges**: Green badges showing analysis confidence
- **Sentiment Badges**: Color-coded sentiment indicators
- **Topic Tags**: Gray tags for extracted topics
- **Keyword Tags**: Blue tags for important keywords
- **Action Buttons**: Color-coded buttons for different operations

## Configuration Options

### API Configuration
```json
{
  "api": {
    "baseUrl": "http://localhost:8080/api",
    "version": "v1",
    "endpoints": {
      "auth": { "login": "/auth/login", "signup": "/auth/signup", "logout": "/auth/logout" },
      "extract": { "analyze": "/extract", "getResult": "/extract/:id" },
      "knowledge": { "list": "/knowledge", "create": "/knowledge", "update": "/knowledge/:id", "delete": "/knowledge/:id" },
      "search": { "knowledge": "/search" }
    }
  }
}
```

### UI Configuration
```json
{
  "ui": {
    "pagination": { "itemsPerPage": 10 },
    "messages": { "timeout": { "error": 5000, "success": 3000 } },
    "loading": { "delay": 500 }
  }
}
```

## Usage

The frontend is served by the Go backend server with configurable asset paths. See the main README for setup instructions.

### Development
- Frontend files are served from the configured `frontend_assets_path` in `config.yml`
- Default path is `frontend/` but can be changed to `dist/` for production builds
- All API calls are configuration-driven through `config.js`

### Production
- Frontend can be built and minified using the included Go-based minifier
- Assets are served from the configured path in the server configuration
- Requires actual user registration and authentication for full functionality

### Key Workflows
1. **User Registration/Login**: Create account or sign in
2. **Text Analysis**: Enter text and select LLM model for analysis
3. **Review Results**: View extracted knowledge, topics, keywords, and sentiment
4. **Automatic Storage**: Analysis is automatically saved to knowledge base
5. **Search & Manage**: Search through saved knowledge entries
6. **Export/Share**: Copy analysis results to clipboard
