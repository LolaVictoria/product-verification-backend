const AppState = {
    user: null,
    isAuthenticated: false,
    products: [],
    currentPage: 'home'
};
// Authentication Management
function checkAuthStatus() {
    const token = localStorage.getItem('authToken');
    if (token) {
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            const now = Date.now() / 1000;
            
            if (payload.exp > now) {
                AppState.isAuthenticated = true;
                AppState.user = {
                    id: payload.sub,
                    email: payload.email,
                    role: payload.role
                };
                updateUIForAuthentication();
                return true
            } else {
                logout();
                return false
            }
        } catch (error) {
            console.error('Invalid token:', error);
            logout();
        }
    }
}



function updateUIForAuthentication() {
    const navMenu = document.querySelector('.nav-menu');
    if (navMenu && AppState.isAuthenticated) {
        // Update navigation for logged-in users
        navMenu.innerHTML = `
            <a href="/" class="nav-link">Home</a>
            <a href="/verify" class="nav-link">Verify Product</a>
            ${AppState.user.role === 'manufacturer' ? '<a href="/dashboard" class="nav-link">Dashboard</a>' : ''}
            <a href="#" class="nav-link" onclick="logout()">Logout</a>
        `;
    }
}
//caching strategies
class CacheManager {
    constructor() {
        this.endpoints = {
            products: '/manufacturer/products',
            stats: '/manufacturer/dashboard-stats',
            profile: '/manufacturer/profile'
        };
        this.cacheKeys = {
            products: 'productData',
            stats: 'statsData',
            profile: 'profileData'
        };
    }

    async isCacheValid(dataType) {
        const token = localStorage.getItem('authToken');
        if (!token) return false;

        const cachedData = this.getCachedData(this.cacheKeys[dataType]);
        if (!cachedData) return false;

        let lastUpdateTimes = localStorage.getItem('lastUpdateTimes');
        if (!lastUpdateTimes) {
            try {
                const response = await axios.get('/manufacturer/last-update-times?types=' + dataType, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                lastUpdateTimes = response.data.last_updates;
                localStorage.setItem('lastUpdateTimes', JSON.stringify({
                    data: lastUpdateTimes,
                    timestamp: new Date()
                }));
            } catch (error) {
                console.error(`Error fetching last-update-times for ${dataType}:`, error);
                return false;
            }
        } else {
            try {
                lastUpdateTimes = JSON.parse(lastUpdateTimes).data;
            } catch (error) {
                console.error('Error parsing lastUpdateTimes:', error);
                localStorage.removeItem('lastUpdateTimes');
                return false;
            }
        }

        const serverLastUpdate = lastUpdateTimes[dataType];
        if (serverLastUpdate === null) {
            return cachedData.isEmpty && (Date.now() - new Date(cachedData.timestamp).getTime()) < 60 * 1000;
        }

        return new Date(cachedData.timestamp) >= new Date(serverLastUpdate);
    }

    async loadDataWithCache(dataType, displayFunction, forceRefresh = false) {
        const token = localStorage.getItem('authToken');
        if (!token) {
            console.log(`No auth token, skipping ${dataType} data load`);
            return [];
        }

        try {
            if (!forceRefresh && await this.isCacheValid(dataType)) {
                const cachedData = this.getCachedData(this.cacheKeys[dataType]);
                if (cachedData) {
                    console.log(`Using cached ${dataType} data`);
                    if (!cachedData.isEmpty) {
                        displayFunction(cachedData.data);
                        return cachedData.data;
                    }
                    displayFunction([]);
                    return [];
                }
            }

            const response = await axios.get(this.endpoints[dataType], {
                headers: { 'Authorization': `Bearer ${token}` }
            });

            if (response.data.status === 'success') {
                const data = response.data[this.getDataKey(dataType)];
                if (data && (Array.isArray(data) ? data.length > 0 : Object.keys(data).length > 0)) {
                    this.setCachedData(this.cacheKeys[dataType], data);
                    displayFunction(data);
                    return data;
                } else {
                    this.setCachedData(this.cacheKeys[dataType], [], true);
                    displayFunction([]);
                    return [];
                }
            }
            return [];
        } catch (error) {
            console.error(`Error loading ${dataType}:`, error);
            const cachedData = this.getCachedData(this.cacheKeys[dataType]);
            if (cachedData && !cachedData.isEmpty) {
                displayFunction(cachedData.data);
                return cachedData.data;
            }
            if (error.response?.status === 401) {
                logout();
            }
            return [];
        }
    }

    async loadMultipleDataWithCache(dataTypesConfig, forceRefresh = false) {
        const promises = Object.keys(dataTypesConfig).map(dataType =>
            this.loadDataWithCache(dataType, dataTypesConfig[dataType].displayFunction, forceRefresh)
                .catch(error => {
                    console.error(`Failed to load ${dataType}:`, error);
                    return [];
                })
        );
        return Promise.all(promises);
    }

    setCachedData(key, data, isEmpty = false) {
        const cacheItem = { data, timestamp: new Date(), isEmpty };
        localStorage.setItem(key, JSON.stringify(cacheItem));
    }

    getCachedData(key) {
        const cached = localStorage.getItem(key);
        if (!cached) return null;
        try {
            return JSON.parse(cached);
        } catch (error) {
            console.error(`Error parsing ${key}:`, error);
            localStorage.removeItem(key);
            return null;
        }
    }

    getDataKey(dataType) {
        const keyMap = { products: 'products', stats: 'stats', profile: 'user' };
        return keyMap[dataType] || dataType;
    }

    clearCache(dataType) {
        localStorage.removeItem(this.cacheKeys[dataType]);
        console.log(`Cleared ${dataType} cache`);
    }

    clearAllCaches() {
        Object.values(this.cacheKeys).forEach(key => localStorage.removeItem(key));
        localStorage.removeItem('lastUpdateTimes');
        console.log('Cleared all caches');
    }

    smartCacheClear(action) {
        const strategies = {
            product_registration: () => {
                this.clearCache('products');
                this.clearCache('stats');
            },
            profile_update: () => this.clearCache('profile'),
            wallet_verification: () => this.clearCache('profile'),
            company_name_change: () => {
                this.clearCache('profile');
                this.clearCache('products');
            },
            account_verification: () => this.clearAllCaches()
        };
        const strategy = strategies[action];
        if (strategy) strategy();
        else console.log(`No cache strategy for action: ${action}`);
    }
}
const cacheManager = new CacheManager();


function logout() {
    localStorage.removeItem('authToken');
    AppState.isAuthenticated = false;
    AppState.user = null;
    window.location.href = '/';
    localStorage.removeItem('user');
    cacheManager.clearAllCaches();;
}

// Set axios default authorization header
function setAuthHeader() {
    const token = localStorage.getItem('authToken');
    if (token) {
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
}


// Navigation functionality
function initializeNavigation() {
    const hamburger = document.getElementById('hamburger');
    const navMenu = document.getElementById('nav-menu');
    
    if (hamburger && navMenu) {
        hamburger.addEventListener('click', function() {
            navMenu.classList.toggle('active');
        });
    }
}



function initializeApp() {
    // Check if user is logged in
    checkAuthStatus();
    
    // Initialize navigation
    initializeNavigation();
    
    
    // Initialize page-specific functionality
    initializePageFunctionality();
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function createProductCard(product) {
    return `
        <div class="product-card">
            <div class="product-image")">
                ${product.blockchain_verified ? '<div class="blockchain-badge">🔗 Blockchain</div>' : ''}
            </div>
            <div class="product-info">
                <h3>${product.name}</h3>
                <div class="product-price">$${product.price.toFixed(2)}</div>
                <div class="product-details">
                    <p><strong>Category:</strong> ${product.category}</p>
                    <p><strong>Manufacturer:</strong> ${product.manufacturer_name}</p>
                    <p><strong>Serial:</strong> ${product.serial_number}</p>
                </div>
                <button class="verify-btn" onclick="initiateVerification('${product.serial_number}')">
                    ${product.blockchain_verified ? 'Verify on Blockchain' : 'Verify Authenticity'}
                </button>
                <div id="verification-${product.serial_number}" class="verification-result"></div>
            </div>
        </div>
    `;
}

// Enhanced verification system
function initiateVerification(serialNumber) {
    if (!AppState.isAuthenticated) {
        showAlert('Please log in to verify products', 'warning');
        setTimeout(() => {
            window.location.href = '/login';
        }, 2000);
        return;
    }
    
    verifyProductWithOverlay(serialNumber);
}

async function verifyProductWithOverlay(serialNumber) {
    const overlay = createVerificationOverlay();
    document.body.appendChild(overlay);
    overlay.style.display = 'flex';
    
    const modal = overlay.querySelector('.verification-modal');
    
    // Show loading state
    modal.innerHTML = `
        <button class="modal-close" onclick="closeVerificationOverlay()">&times;</button>
        <div class="verification-status">
            <div class="status-icon status-loading">⏳</div>
            <h3>Verifying Product...</h3>
            <p>Checking authenticity on blockchain and database</p>
        </div>
    `;
    
    try {
        const token = localStorage.getItem('authToken');
        const response = await axios.get(`/verify/${serialNumber}`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const result = response.data;
        displayVerificationResult(modal, result, serialNumber);
        
    } catch (error) {
        console.error('Verification error:', error);
        
        let errorMessage = 'Verification failed';
        let errorDetails = 'An unexpected error occurred';
        
        if (error.response) {
            errorMessage = error.response.data.message || 'Verification failed';
            errorDetails = error.response.data.error || 'Please try again later';
        }
        
        modal.innerHTML = `
            <button class="modal-close" onclick="closeVerificationOverlay()">&times;</button>
            <div class="verification-status">
                <div class="status-icon status-failed">❌</div>
                <h3>${errorMessage}</h3>
                <p>${errorDetails}</p>
            </div>
        `;
    }
}

function displayVerificationResult(modal, result, serialNumber) {
    const product = result.product;
    const isVerified = result.verified && result.status !== 'blockchain_not_found';
    
    let statusIcon, statusTitle, statusMessage;
    
    switch (result.status) {
        case 'blockchain_verified':
            statusIcon = '<div class="status-icon status-verified">✅</div>';
            statusTitle = 'Blockchain Verified';
            statusMessage = 'This product is authentic and verified on the blockchain';
            break;
        case 'database_verified':
            statusIcon = '<div class="status-icon status-verified">✅</div>';
            statusTitle = 'Database Verified';
            statusMessage = 'This product is verified in our database';
            break;
        case 'blockchain_not_found':
            statusIcon = '<div class="status-icon status-failed">⚠️</div>';
            statusTitle = 'Blockchain Verification Failed';
            statusMessage = 'Product found in database but not on blockchain';
            break;
        case 'not_found':
            statusIcon = '<div class="status-icon status-failed">❌</div>';
            statusTitle = 'Product Not Found';
            statusMessage = 'This product is not in our verification system';
            break;
        default:
            statusIcon = '<div class="status-icon status-failed">❌</div>';
            statusTitle = 'Verification Failed';
            statusMessage = result.message || 'Unable to verify product authenticity';
    }
    
    let modalContent = `
        <button class="modal-close" onclick="closeVerificationOverlay()">&times;</button>
        <div class="verification-status">
            ${statusIcon}
            <h3>${statusTitle}</h3>
            <p>${statusMessage}</p>
        </div>
    `;
    
    if (product) {
        modalContent += `
            <div class="verification-details">
                <h4>Product Details</h4>
                <div class="detail-row">
                    <span class="detail-label">Name:</span>
                    <span class="detail-value">${product.name}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Serial Number:</span>
                    <span class="detail-value">${product.serial_number}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Category:</span>
                    <span class="detail-value">${product.category}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Manufacturer:</span>
                    <span class="detail-value">${product.manufacturer}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Price:</span>
                    <span class="detail-value">$${product.price.toFixed(2)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Registered:</span>
                    <span class="detail-value">${new Date(product.registered_at).toLocaleDateString()}</span>
                </div>
            </div>
        `;
        
        // Add blockchain details if available
        if (result.blockchain_details) {
            modalContent += `
                <div class="blockchain-info">
                    <h4>🔗 Blockchain Information</h4>
                    <div class="blockchain-details">
                        <p><strong>Status:</strong> ${result.blockchain_status}</p>
                        <p><strong>Block Number:</strong> ${result.blockchain_details.block_number || 'N/A'}</p>
                        <p><strong>Transaction:</strong> ${result.blockchain_details.transaction_hash ? result.blockchain_details.transaction_hash.substring(0, 20) + '...' : 'N/A'}</p>
                        <p><strong>Blockchain Timestamp:</strong> ${result.blockchain_details.timestamp ? new Date(result.blockchain_details.timestamp * 1000).toLocaleString() : 'N/A'}</p>
                    </div>
                </div>
            `;
        }
    }
    
    modal.innerHTML = modalContent;
}

function createVerificationOverlay() {
    const overlay = document.createElement('div');
    overlay.className = 'verification-overlay';
    overlay.innerHTML = '<div class="verification-modal"></div>';
    return overlay;
}

function closeVerificationOverlay() {
    const overlay = document.querySelector('.verification-overlay');
    if (overlay) {
        overlay.remove();
    }
}

// Page-specific functionality
function initializePageFunctionality() {
    const path = window.location.pathname;
    
    switch (path) {
        case '/login':
            initializeLoginForm();
            break;
        case '/signup':
            initializeSignupForm();
            break;
        case '/dashboard':
            initializeDashboard();
            break;
        case '/verify':
            initializeVerifyPage();
            break;
    }
}

// Login form functionality
function initializeLoginForm() {
    const form = document.getElementById('Form');
    if (form) {
        form.addEventListener('submit', handle);
    }
}

// Signup form functionality
function initializeSignupForm() {
    const form = document.getElementById('signupForm');
    const roleSelect = document.getElementById('role');
    const walletField = document.getElementById('walletField');
    
    if (form) {
        form.addEventListener('submit', handleSignup);
    }
    
    if (roleSelect && walletField) {
        roleSelect.addEventListener('change', function() {
            if (this.value === 'manufacturer') {
                walletField.style.display = 'block';
            } else {
                walletField.style.display = 'none';
            }
        });
    }
}


// Verify page functionality
function initializeVerifyPage() {
    const form = document.getElementById('verify-form');
    if (form) {
        form.addEventListener('submit', handleManualVerification);
    }
}

async function handleSignup(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const signupData = {
        email: formData.get('email'),
        password: formData.get('password'),
        role: formData.get('role')
    };
    
    // Add manufacturer-specific fields
    if (signupData.role === 'manufacturer') {
        signupData.wallet_address = formData.get('wallet_address');
        signupData.company_name = formData.get('company_name');
    }
    
    const submitBtn = event.target.querySelector('.form-submit');
    const originalText = submitBtn.textContent;
    
    try {
        submitBtn.innerHTML = '<span class="spinner"></span>Creating account...';
        submitBtn.disabled = true;
        
        const response = await axios.post('/auth/signup', signupData);
        
        if (response.data.status === 'success') {
            showAlert('Account created successfully! Please log in.', 'success');
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        }
        
    } catch (error) {
        console.error('Signup error:', error);
        const errorMessage = error.response?.data?.error || 'Signup failed';
        showAlert(errorMessage, 'error');
        
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
}

// Dashboard functionality
function initializeDashboard() {
    if (AppState.isAuthenticated === false && AppState.user.role !== 'manufacturer') {
        window.location.href = '/';
        return;
    }
    
    loadDashboard();
}

//login form functionality
async function handleLogin(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const loginData = {
        email: formData.get('email'),
        password: formData.get('password')
    };

    // Basic validation
    if (!loginData.email || !loginData.password) {
        showAlert('Please enter both email and password', 'error');
        return;
    }

    const submitBtn = event.target.querySelector('.form-submit');
    const originalText = submitBtn.textContent;

    try {
        submitBtn.innerHTML = '<span class="spinner"></span>Signing in...';
        submitBtn.disabled = true;

        const response = await axios.post('/auth/login', loginData, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        if (response.data.status === 'success') {
            showAlert('Login successful! Redirecting...', 'success');
            AppState.isAuthenticated = true
            
            // Store JWT token and user info
            localStorage.setItem('authToken', response.data.token);
            localStorage.setItem('user', JSON.stringify(response.data.user));
            AppState.user = response.data.user;
            // Set Authorization header for future requests
            axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
            
            
                // Redirect based on user role
                const userRole = response.data.user.role;
                let redirectUrl;
                
                switch(userRole) {
                    case 'manufacturer':
                        redirectUrl = '/dashboard';
                        break;
                    case 'admin':
                        redirectUrl = '/admin';
                        break;
                    default:
                        redirectUrl = '/';
                }
                
                window.location.href = redirectUrl;
           
        }
    } catch (error) {
        console.error('Login error:', error);
        
        // Handle specific error cases
        if (error.response?.status === 400) {
            showAlert('Please provide both email and password', 'error');
        } else if (error.response?.status === 401) {
            showAlert('Invalid Credentials', 'error');
        } else {
            const errorMessage = error.response?.data?.error || 'Login failed. Please try again.';
            showAlert(errorMessage, 'error');
        }
    } finally {
        // Reset button state
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
}




async function loadDashboard(forceRefresh = false) {
    const token = localStorage.getItem('authToken');
    if (!token) {
        console.error('No auth token, redirecting to login');
        window.location.href = '/login';
        return;
    }

    try {
        await cacheManager.loadMultipleDataWithCache({
            products: { displayFunction: displayManufacturerProducts },
            stats: { displayFunction: updateDashboardStats }
        }, forceRefresh);
    } catch (error) {
        console.error('Dashboard loading error:', error);
    }
}


function setCachedDataWithTimestamp(key, data) {
    const cacheItem = {
        data: data,
        timestamp: new Date()
    };
    localStorage.setItem(key, JSON.stringify(cacheItem));
}

function getCachedDataWithTimestamp(key) {
    const cached = localStorage.getItem(key);
    if (!cached) return null;
    
    try {
        const cacheItem = JSON.parse(cached);
        return {
            data: cacheItem.data,
            timestamp: new Date(cacheItem.timestamp)
        };
    } catch (error) {
        localStorage.removeItem(key);
        return null;
    }
}

// Update dashboard stats with validationo
function updateDashboardStats(stats) {
    const statsContainer = document.getElementById('dashboard-stats');
    if (!statsContainer) return;

    const totalProducts = stats.total_products ?? 0;
    const blockchainVerified = stats.blockchain_verified ?? 0;
    const totalValue = stats.total_value ?? 0;
    const categoriesCount = stats.categories ? Object.keys(stats.categories).length : 0;

    statsContainer.innerHTML = `
        <div class="stat-card">
            <div class="stat-number">${totalProducts}</div>
            <div class="stat-label">Total Products</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">${blockchainVerified}</div>
            <div class="stat-label">Blockchain Verified</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">${totalValue.toLocaleString()}</div>
            <div class="stat-label">Total Value</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">${categoriesCount}</div>
            <div class="stat-label">Categories</div>
        </div>
    `;
}

function displayManufacturerProducts(products) {
    const container = document.getElementById('manufacturer-products');
    if (!container) return;
    
    if (products.length === 0) {
        container.innerHTML = '<p class="text-center">No products registered yet. Register your first product below!</p>';
        return;
    }
    
    container.innerHTML = products.map(product => `
        <div class="product-card">
            <div class="product-image">
                ${product.blockchain_verified ? '<div class="blockchain-badge">🔗 Blockchain</div>' : ''}
            </div>
            <div class="product-info">
                <h3>${product.name}</h3>
                <div class="product-price">${product.price.toFixed(2)}</div>
                <div class="product-details">
                    <p><strong>Serial:</strong> ${product.serial_number}</p>
                    <p><strong>Category:</strong> ${product.category}</p>
                    <p><strong>Status:</strong> ${product.verified ? 'Verified' : 'Pending'}</p>
                    ${product.blockchain_tx_hash ? `<p><strong>TX Hash:</strong> ${product.blockchain_tx_hash.substring(0, 20)}...</p>` : ''}
                </div>
            </div>
        </div>
    `).join('');
}

// Updated Frontend Product Registration
async function handleProductRegistration(event) {
    event.preventDefault(); // Prevent default form submission

    // Parse user data
    const userString = localStorage.getItem('user');
    let user;
    try {
        user = userString ? JSON.parse(userString) : null;
    } catch (error) {
        console.error('Error parsing user data:', error);
        showAlert('Invalid user data. Please log in again.', 'error');
        window.location.href = '/login';
        return;
    }

    // Check verification status
    if (!user || user.verification_status !== 'verified') {
        showAlert('Your account needs admin verification before you can register products.', 'warning');
        return;
    }

    // Get and validate form data
    const formData = new FormData(event.target);
    const productData = {
        serial_number: formData.get('serial_number')?.trim(),
        name: formData.get('name')?.trim(),
        category: formData.get('category')?.trim(),
        description: formData.get('description')?.trim() || '',
        price: parseFloat(formData.get('price'))
    };

    if (!productData.serial_number || !productData.name || !productData.category || isNaN(productData.price)) {
        showAlert('Please fill in all required fields (serial number, name, category, price).', 'error');
        return;
    }

    const submitBtn = event.target.querySelector('.form-submit');
    const originalText = submitBtn.textContent;

    try {
        submitBtn.innerHTML = '<span class="spinner"></span>Registering on blockchain...';
        submitBtn.disabled = true;

        const token = localStorage.getItem('authToken');
        if (!token) {
            showAlert('No authentication token. Please log in.', 'error');
            window.location.href = '/login';
            return;
        }

        const response = await axios.post('/manufacturer/register-product', productData, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.data.status === 'success') {
            showAlert('Product registered successfully on blockchain!', 'success');
            event.target.reset();
            cacheManager.smartCacheClear('product_registration');
            await loadDashboard(true); // Force refresh
        }
    } catch (error) {
        console.error('Product registration error:', error);
        const errorMessage = error.response?.data?.error || 'Registration failed';
        showAlert(errorMessage, errorMessage.includes('wallet') || errorMessage.includes('verified') ? 'info' : 'error');
        if (error.response?.status === 401) {
            window.location.href = '/login';
        }
    } finally {
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('product-registration-form');
    if (form) form.addEventListener('submit', handleProductRegistration);
});

async function handleManualVerification(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const serialNumber = formData.get('serial_number');
    
    if (!AppState.isAuthenticated) {
        showAlert('Please log in to verify products', 'warning');
        setTimeout(() => {
            window.location.href = '/';
        }, 2000);
        return;
    }
    
    verifyProductWithOverlay(serialNumber);
}

// Utility functions
function showAlert(message, type) {
    // Remove existing alerts
    const existingAlert = document.querySelector('.alert');
    if (existingAlert) {
        existingAlert.remove();
    }
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    
    // Insert at top of main content
    const main = document.querySelector('main') || document.body;
    main.insertBefore(alert, main.firstChild);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alert.parentNode) {
            alert.remove();
        }
    }, 30000);
}

// Generate random serial number for testing
function generateSerialNumber() {
    const prefix = 'TEST';
    const timestamp = Date.now().toString().slice(-6);
    const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    return `${prefix}${timestamp}${random}`;
}

// Utility function to validate Ethereum address
function isValidEthereumAddress(address) {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
}

// Close overlay when clicking outside
document.addEventListener('click', function(event) {
    const overlay = document.querySelector('.verification-overlay');
    if (overlay && event.target === overlay) {
        closeVerificationOverlay();
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeVerificationOverlay();
    }
});




 // Initialize authentication and blockchain config on page load
document.addEventListener('DOMContentLoaded', async function() {
    setAuthHeader();
});







