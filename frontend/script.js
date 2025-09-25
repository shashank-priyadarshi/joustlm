let currentUser = null;
let currentPage = 1;
let totalPages = 1;
let knowledgeData = [];
let currentAnalysis = null;

const loginPage = document.getElementById('loginPage');
const signupPage = document.getElementById('signupPage');
const dashboardPage = document.getElementById('dashboardPage');
const loginForm = document.getElementById('loginForm');
const signupForm = document.getElementById('signupForm');
const analysisForm = document.getElementById('analysisForm');
const logoutBtn = document.getElementById('logoutBtn');
const welcomeUser = document.getElementById('welcomeUser');
const knowledgeList = document.getElementById('knowledgeList');
const prevPageBtn = document.getElementById('prevPage');
const nextPageBtn = document.getElementById('nextPage');
const pageInfo = document.getElementById('pageInfo');
const loadingSpinner = document.getElementById('loadingSpinner');
const showSignupLink = document.getElementById('showSignup');
const showLoginLink = document.getElementById('showLogin');
const analysisResults = document.getElementById('analysisResults');
const resultsContent = document.getElementById('resultsContent');
const refreshKnowledgeBtn = document.getElementById('refreshKnowledge');
const searchKnowledgeBtn = document.getElementById('searchKnowledge');
const searchForm = document.getElementById('searchForm');
const knowledgeSearchForm = document.getElementById('knowledgeSearchForm');
const clearSearchBtn = document.getElementById('clearSearch');

document.addEventListener('DOMContentLoaded', async function() {
    await window.appConfig.load();
    initializeApp();
});

async function initializeApp() {
    showLoading();

    const token = localStorage.getItem('jwt_token');
    if (token) {
        try {
            const isValid = await verifyToken(token);
            if (isValid) {
                currentUser = JSON.parse(localStorage.getItem('user_data'));
                showDashboard();
                await loadKnowledge();
            } else {
                clearAuthData();
                showLogin();
            }
        } catch (error) {
            console.error('Token verification failed:', error);
            clearAuthData();
            showLogin();
        }
    } else {
        showLogin();
    }

    hideLoading();
}

async function signup(username, password) {
    try {
        const response = await fetch(window.appConfig.getFullApiUrl('auth', 'signup'), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Signup failed');
        }

        const data = await response.json();

        localStorage.setItem('jwt_token', data.token);
        localStorage.setItem('user_data', JSON.stringify({ username: username }));

        currentUser = { username: username };
        showDashboard();
        await loadKnowledge();

        return true;
    } catch (error) {
        console.error('Signup error:', error);
        showError('signupError', error.message || 'Signup failed. Please try again.');
        return false;
    }
}

async function login(username, password) {
    try {
        const response = await fetch(window.appConfig.getFullApiUrl('auth', 'login'), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Login failed');
        }

        const data = await response.json();

        localStorage.setItem('jwt_token', data.token);
        localStorage.setItem('user_data', JSON.stringify({ username: username }));

        currentUser = { username: username };
        showDashboard();
        await loadKnowledge();

        return true;
    } catch (error) {
        console.error('Login error:', error);
        showError('loginError', error.message || 'Login failed. Please check your credentials.');
        return false;
    }
}

async function verifyToken(token) {
    if (!token) {
        return false;
    }
    return true;
}

async function logout() {
    try {
        const token = localStorage.getItem('jwt_token');
        if (token) {
            await fetch(window.appConfig.getFullApiUrl('auth', 'logout'), {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
        }
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        clearAuthData();
        currentUser = null;
        showLogin();
    }
}

function clearAuthData() {
    localStorage.removeItem('jwt_token');
    localStorage.removeItem('user_data');
}

function showLogin() {
    loginPage.classList.remove('hidden');
    signupPage.classList.add('hidden');
    dashboardPage.classList.add('hidden');
    clearMessages();
}

function showSignup() {
    signupPage.classList.remove('hidden');
    loginPage.classList.add('hidden');
    dashboardPage.classList.add('hidden');
    clearMessages();
}

function showDashboard() {
    loginPage.classList.add('hidden');
    signupPage.classList.add('hidden');
    dashboardPage.classList.remove('hidden');
    welcomeUser.textContent = `Welcome, ${currentUser?.username || 'User'}!`;
    clearMessages();
}

function showLoading() {
    loadingSpinner.classList.remove('hidden');
}

function hideLoading() {
    loadingSpinner.classList.add('hidden');
}

function showError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    errorElement.textContent = message;
    errorElement.classList.add('show');
    setTimeout(() => {
        errorElement.classList.remove('show');
    }, window.appConfig.getMessageTimeout('error'));
}

function showSuccess(elementId, message) {
    const successElement = document.getElementById(elementId);
    successElement.textContent = message;
    successElement.classList.add('show');
    setTimeout(() => {
        successElement.classList.remove('show');
    }, window.appConfig.getMessageTimeout('success'));
}

function clearMessages() {
    document.querySelectorAll('.error-message, .success-message').forEach(el => {
        el.classList.remove('show');
        el.textContent = '';
    });
}

async function analyzeText(text, model) {
    try {
        showLoading();
        const token = localStorage.getItem('jwt_token');
        const response = await fetch(window.appConfig.getFullApiUrl('extract', 'analyze'), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ text, model })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Analysis failed');
        }

        const data = await response.json();
        currentAnalysis = data;
        displayAnalysisResults(data);
        showSuccess('analysisSuccess', 'Text analysis completed and saved to knowledge base!');

        // Refresh knowledge base to show the new entry
        await loadKnowledge();

        return true;
    } catch (error) {
        console.error('Analysis error:', error);
        showError('analysisError', error.message || 'Analysis failed. Please try again.');
        return false;
    } finally {
        hideLoading();
    }
}

function displayAnalysisResults(analysis) {
    resultsContent.innerHTML = `
        <div class="analysis-result">
            <div class="result-header">
                <h3>${analysis.title || 'Analysis Result'}</h3>
                <span class="confidence-badge">Confidence: ${(analysis.confidence * 100).toFixed(1)}%</span>
            </div>

            <div class="result-section">
                <h4>Summary</h4>
                <p>${analysis.summary}</p>
            </div>

            <div class="result-section">
                <h4>Topics</h4>
                <div class="tags">
                    ${analysis.topics.map(topic => `<span class="tag">${topic}</span>`).join('')}
                </div>
            </div>

            <div class="result-section">
                <h4>Keywords</h4>
                <div class="tags">
                    ${analysis.keywords.map(keyword => `<span class="tag keyword">${keyword}</span>`).join('')}
                </div>
            </div>

            <div class="result-section">
                <h4>Sentiment</h4>
                <span class="sentiment-badge sentiment-${analysis.sentiment}">${analysis.sentiment}</span>
            </div>

            <div class="result-section">
                <h4>Original Text</h4>
                <div class="original-text">${analysis.text}</div>
            </div>

            <div class="result-actions">
                <button class="btn-secondary" onclick="copyAnalysis('${analysis.id}')">Copy Analysis</button>
                <button class="btn-secondary" onclick="viewInKnowledgeBase('${analysis.id}')">View in Knowledge Base</button>
            </div>
        </div>
    `;

    analysisResults.classList.remove('hidden');
}

async function loadKnowledge(page = 1) {
    try {
        showLoading();
        const token = localStorage.getItem('jwt_token');
        const limit = window.appConfig.getItemsPerPage();
        const response = await fetch(`${window.appConfig.getFullApiUrl('knowledge', 'list')}?page=${page}&limit=${limit}`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load knowledge entries');
        }

        const data = await response.json();
        knowledgeData = data.knowledge || [];
        currentPage = data.currentPage || 1;
        totalPages = data.totalPages || 1;

        renderKnowledge();
        updatePagination();
    } catch (error) {
        console.error('Error loading knowledge:', error);
        showError('analysisError', 'Failed to load knowledge entries. Please try again.');
    } finally {
        hideLoading();
    }
}

function renderKnowledge() {
    if (knowledgeData.length === 0) {
        knowledgeList.innerHTML = '<p class="no-knowledge">No knowledge entries found. Analyze some text to get started!</p>';
        return;
    }

    knowledgeList.innerHTML = knowledgeData.map(entry => `
        <div class="knowledge-item" data-entry-id="${entry.id}">
            <div class="knowledge-header">
                <h3>${entry.title || 'Untitled'}</h3>
                <div class="knowledge-meta">
                    <span class="confidence-badge">${(entry.confidence * 100).toFixed(1)}%</span>
                    <span class="sentiment-badge sentiment-${entry.sentiment}">${entry.sentiment}</span>
                </div>
            </div>

            <div class="knowledge-summary">
                <p>${entry.summary}</p>
            </div>

            <div class="knowledge-details">
                <div class="topics">
                    <strong>Topics:</strong>
                    <div class="tags">
                        ${entry.topics.map(topic => `<span class="tag">${topic}</span>`).join('')}
                    </div>
                </div>

                <div class="keywords">
                    <strong>Keywords:</strong>
                    <div class="tags">
                        ${entry.keywords.map(keyword => `<span class="tag keyword">${keyword}</span>`).join('')}
                    </div>
                </div>
            </div>

            <div class="knowledge-actions">
                <button class="btn-small btn-view" onclick="viewKnowledge('${entry.id}')">View</button>
                <button class="btn-small btn-edit" onclick="editKnowledge('${entry.id}')">Edit</button>
                <button class="btn-small btn-delete" onclick="deleteKnowledge('${entry.id}')">Delete</button>
            </div>

            <div class="knowledge-footer">
                <span>Created: ${formatDate(entry.created_at)}</span>
                ${entry.updated_at !== entry.created_at ? `<span>Updated: ${formatDate(entry.updated_at)}</span>` : ''}
            </div>
        </div>
    `).join('');
}

async function searchKnowledge(searchParams) {
    try {
        showLoading();
        const token = localStorage.getItem('jwt_token');
        const limit = window.appConfig.getItemsPerPage();

        const queryParams = new URLSearchParams({
            page: currentPage,
            limit: limit,
            ...searchParams
        });

        const response = await fetch(`${window.appConfig.getFullApiUrl('search', 'knowledge')}?${queryParams}`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error('Search failed');
        }

        const data = await response.json();
        knowledgeData = data.results || [];
        currentPage = data.currentPage || 1;
        totalPages = data.totalPages || 1;

        renderKnowledge();
        updatePagination();
    } catch (error) {
        console.error('Search error:', error);
        showError('analysisError', 'Search failed. Please try again.');
    } finally {
        hideLoading();
    }
}

function viewInKnowledgeBase(analysisId) {
    // Scroll to the knowledge base section and highlight the entry
    const knowledgeSection = document.querySelector('.knowledge-section');
    if (knowledgeSection) {
        knowledgeSection.scrollIntoView({ behavior: 'smooth' });

        // Find and highlight the specific entry
        const entry = document.querySelector(`[data-entry-id="${analysisId}"]`);
        if (entry) {
            entry.style.border = '2px solid #667eea';
            entry.style.boxShadow = '0 0 20px rgba(102, 126, 234, 0.3)';

            // Remove highlight after 3 seconds
            setTimeout(() => {
                entry.style.border = '';
                entry.style.boxShadow = '';
            }, 3000);
        }
    }
}

async function deleteKnowledge(entryId) {
    if (!confirm('Are you sure you want to delete this knowledge entry?')) {
        return;
    }

    try {
        showLoading();
        const token = localStorage.getItem('jwt_token');
        const response = await fetch(window.appConfig.getFullApiUrl('knowledge', 'delete', { id: entryId }), {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Failed to delete knowledge entry');
        }

        showSuccess('analysisSuccess', 'Knowledge entry deleted successfully!');
        await loadKnowledge(currentPage);
    } catch (error) {
        console.error('Delete error:', error);
        showError('analysisError', error.message || 'Failed to delete knowledge entry. Please try again.');
    } finally {
        hideLoading();
    }
}

function viewKnowledge(entryId) {
    const entry = knowledgeData.find(e => e.id === entryId);
    if (entry) {
        // Convert knowledge entry to analysis format for display
        const analysisData = {
            id: entry.id,
            text: entry.text,
            title: entry.title,
            summary: entry.summary,
            topics: entry.topics,
            sentiment: entry.sentiment,
            keywords: entry.keywords,
            confidence: entry.confidence,
            created_at: entry.created_at
        };
        currentAnalysis = analysisData;
        displayAnalysisResults(analysisData);

        // Scroll to results section
        const resultsSection = document.getElementById('analysisResults');
        if (resultsSection) {
            resultsSection.scrollIntoView({ behavior: 'smooth' });
        }
    } else {
        showError('analysisError', 'Knowledge entry not found');
    }
}

function editKnowledge(entryId) {
    const entry = knowledgeData.find(e => e.id === entryId);
    if (!entry) {
        showError('analysisError', 'Knowledge entry not found');
        return;
    }

    // Create edit form
    const editForm = `
        <div class="edit-form-overlay">
            <div class="edit-form-container">
                <h3>Edit Knowledge Entry</h3>
                <form id="editKnowledgeForm">
                    <div class="form-group">
                        <label for="editTitle">Title:</label>
                        <input type="text" id="editTitle" value="${entry.title || ''}" required>
                    </div>
                    <div class="form-group">
                        <label for="editSummary">Summary:</label>
                        <textarea id="editSummary" rows="4" required>${entry.summary || ''}</textarea>
                    </div>
                    <div class="form-group">
                        <label for="editTopics">Topics (comma-separated):</label>
                        <input type="text" id="editTopics" value="${entry.topics ? entry.topics.join(', ') : ''}">
                    </div>
                    <div class="form-group">
                        <label for="editKeywords">Keywords (comma-separated):</label>
                        <input type="text" id="editKeywords" value="${entry.keywords ? entry.keywords.join(', ') : ''}">
                    </div>
                    <div class="form-group">
                        <label for="editSentiment">Sentiment:</label>
                        <select id="editSentiment">
                            <option value="positive" ${entry.sentiment === 'positive' ? 'selected' : ''}>Positive</option>
                            <option value="negative" ${entry.sentiment === 'negative' ? 'selected' : ''}>Negative</option>
                            <option value="neutral" ${entry.sentiment === 'neutral' ? 'selected' : ''}>Neutral</option>
                        </select>
                    </div>
                    <div class="form-actions">
                        <button type="submit" class="btn-primary">Save Changes</button>
                        <button type="button" class="btn-secondary" onclick="closeEditForm()">Cancel</button>
                    </div>
                </form>
            </div>
        </div>
    `;

    // Add form to page
    document.body.insertAdjacentHTML('beforeend', editForm);

    // Handle form submission
    document.getElementById('editKnowledgeForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        await saveKnowledgeEdit(entryId);
    });
}

function closeEditForm() {
    const overlay = document.querySelector('.edit-form-overlay');
    if (overlay) {
        overlay.remove();
    }
}

async function saveKnowledgeEdit(entryId) {
    try {
        showLoading();
        const token = localStorage.getItem('jwt_token');

        const title = document.getElementById('editTitle').value;
        const summary = document.getElementById('editSummary').value;
        const topics = document.getElementById('editTopics').value.split(',').map(t => t.trim()).filter(t => t);
        const keywords = document.getElementById('editKeywords').value.split(',').map(k => k.trim()).filter(k => k);
        const sentiment = document.getElementById('editSentiment').value;

        const response = await fetch(window.appConfig.getFullApiUrl('knowledge', 'update', { id: entryId }), {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                title: title,
                summary: summary,
                topics: topics,
                keywords: keywords,
                sentiment: sentiment
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Failed to update knowledge entry');
        }

        showSuccess('analysisSuccess', 'Knowledge entry updated successfully!');
        closeEditForm();
        await loadKnowledge(currentPage);
    } catch (error) {
        console.error('Update error:', error);
        showError('analysisError', error.message || 'Failed to update knowledge entry. Please try again.');
    } finally {
        hideLoading();
    }
}

function copyAnalysis(analysisId) {
    if (!currentAnalysis) {
        showError('analysisError', 'No analysis to copy');
        return;
    }

    const analysisText = `
Title: ${currentAnalysis.title}
Summary: ${currentAnalysis.summary}
Topics: ${currentAnalysis.topics.join(', ')}
Keywords: ${currentAnalysis.keywords.join(', ')}
Sentiment: ${currentAnalysis.sentiment}
Confidence: ${(currentAnalysis.confidence * 100).toFixed(1)}%
    `.trim();

    navigator.clipboard.writeText(analysisText).then(() => {
        showSuccess('analysisSuccess', 'Analysis copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy analysis:', err);
        showError('analysisError', 'Failed to copy analysis to clipboard.');
    });
}

function updatePagination() {
    prevPageBtn.disabled = currentPage <= 1;
    nextPageBtn.disabled = currentPage >= totalPages;
    pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
}

async function goToPreviousPage() {
    if (currentPage > 1) {
        await loadKnowledge(currentPage - 1);
    }
}

async function goToNextPage() {
    if (currentPage < totalPages) {
        await loadKnowledge(currentPage + 1);
    }
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function toggleSearchForm() {
    searchForm.classList.toggle('hidden');
}

function clearSearch() {
    document.getElementById('searchTopic').value = '';
    document.getElementById('searchKeyword').value = '';
    document.getElementById('searchSentiment').value = '';
    searchForm.classList.add('hidden');
    loadKnowledge(1);
}

// Event Listeners
loginForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    await login(username, password);
});

signupForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    const username = document.getElementById('signupUsername').value;
    const password = document.getElementById('signupPassword').value;
    await signup(username, password);
});

analysisForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    const text = document.getElementById('textInput').value;
    const model = document.getElementById('modelSelect').value;

    if (!text.trim()) {
        showError('analysisError', 'Please enter text to analyze.');
        return;
    }

    await analyzeText(text, model);
});

knowledgeSearchForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    const topic = document.getElementById('searchTopic').value;
    const keyword = document.getElementById('searchKeyword').value;
    const sentiment = document.getElementById('searchSentiment').value;

    const searchParams = {};
    if (topic) searchParams.topic = topic;
    if (keyword) searchParams.keyword = keyword;
    if (sentiment) searchParams.sentiment = sentiment;

    await searchKnowledge(searchParams);
});

showSignupLink.addEventListener('click', function(e) {
    e.preventDefault();
    showSignup();
});

showLoginLink.addEventListener('click', function(e) {
    e.preventDefault();
    showLogin();
});

logoutBtn.addEventListener('click', logout);
refreshKnowledgeBtn.addEventListener('click', () => loadKnowledge(1));
searchKnowledgeBtn.addEventListener('click', toggleSearchForm);
clearSearchBtn.addEventListener('click', clearSearch);
prevPageBtn.addEventListener('click', goToPreviousPage);
nextPageBtn.addEventListener('click', goToNextPage);

document.addEventListener('visibilitychange', async function() {
    if (!document.hidden && currentUser) {
        const token = localStorage.getItem('jwt_token');
        if (token) {
            const isValid = await verifyToken(token);
            if (!isValid) {
                clearAuthData();
                currentUser = null;
                showLogin();
            }
        }
    }
});
