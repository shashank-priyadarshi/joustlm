class Config {
    constructor() {
        this.config = null;
        this.loaded = false;
    }

    async load() {
        if (this.loaded) {
            return this.config;
        }

        try {
            const response = await fetch('./config.json');
            if (!response.ok) {
                throw new Error(`Failed to load config: ${response.status}`);
            }
            this.config = await response.json();
            this.loaded = true;
            return this.config;
        } catch (error) {
            console.error('Error loading configuration:', error);
            this.config = this.getDefaultConfig();
            this.loaded = true;
            return this.config;
        }
    }

    getDefaultConfig() {
        return {
            api: {
                baseUrl: 'http://localhost:8080/api',
                version: 'v1',
                endpoints: {
                    auth: {
                        login: '/auth/login',
                        signup: '/auth/signup',
                        logout: '/auth/logout',
                        verify: '/auth/verify'
                    },
                    extract: {
                        analyze: '/extract',
                        getResult: '/extract/:id'
                    },
                    knowledge: {
                        list: '/knowledge',
                        create: '/knowledge',
                        update: '/knowledge/:id',
                        delete: '/knowledge/:id'
                    },
                    search: {
                        knowledge: '/search'
                    },
                    health: {
                        check: '/health'
                    }
                }
            },
            demo: {
                enabled: false,
                credentials: {
                    username: 'demo',
                    password: 'demo123'
                },
                data: {
                    user: '/assets/data/user.json',
                    knowledge: '/assets/data/knowledge.json'
                }
            },
            ui: {
                pagination: {
                    itemsPerPage: 10
                },
                messages: {
                    timeout: {
                        error: 5000,
                        success: 3000
                    }
                },
                loading: {
                    delay: 500
                }
            },
            app: {
                name: 'JoustLM',
                version: '1.0.0'
            }
        };
    }

    getApiBaseUrl() {
        return this.config?.api?.baseUrl || 'http://localhost:8080/api';
    }

    getApiVersion() {
        return this.config?.api?.version || 'v1';
    }

    getEndpoint(category, endpoint) {
        return this.config?.api?.endpoints?.[category]?.[endpoint] || '';
    }

    getFullApiUrl(category, endpoint, params = {}) {
        const baseUrl = this.getApiBaseUrl();
        const version = this.getApiVersion();
        let endpointPath = this.getEndpoint(category, endpoint);

        Object.keys(params).forEach(key => {
            endpointPath = endpointPath.replace(`:${key}`, params[key]);
        });

        return `${baseUrl}/${version}${endpointPath}`;
    }

    isDemoMode() {
        return this.config?.demo?.enabled || false;
    }

    getDemoCredentials() {
        return this.config?.demo?.credentials || { username: 'demo', password: 'demo123' };
    }

    getDemoDataPath(type) {
        return this.config?.demo?.data?.[type] || `/assets/data/${type}.json`;
    }

    getItemsPerPage() {
        return this.config?.ui?.pagination?.itemsPerPage || 5;
    }

    getMessageTimeout(type) {
        return this.config?.ui?.messages?.timeout?.[type] || (type === 'error' ? 5000 : 3000);
    }

    getLoadingDelay() {
        return this.config?.ui?.loading?.delay || 500;
    }

    getAppName() {
        return this.config?.app?.name || 'JoustLM';
    }

    getAppVersion() {
        return this.config?.app?.version || '1.0.0';
    }

    getRedirectUrl(encodedUrl) {
        const baseUrl = this.getApiBaseUrl(); // Keep the full API base URL
        const version = this.getApiVersion();
        return `${baseUrl}/${version}?url=${encodedUrl}`;
    }

    getHealthCheckUrl() {
        const baseUrl = this.getApiBaseUrl().replace('/api', ''); // Remove /api from base URL
        return `${baseUrl}${this.getEndpoint('health', 'check')}`;
    }
}

window.appConfig = new Config();
