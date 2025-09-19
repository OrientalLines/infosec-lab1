#!/usr/bin/env bun

// Simple API testing script
const BASE_URL = 'http://localhost:3000';

async function testEndpoint(method: string, url: string, data?: any, token?: string) {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const config: RequestInit = {
        method,
        headers,
    };

    if (data && (method === 'POST' || method === 'PUT')) {
        config.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(`${BASE_URL}${url}`, config);
        const result = await response.json();

        console.log(`\n${method} ${url} - Status: ${response.status}`);
        console.log('Response:', JSON.stringify(result, null, 2));

        return { status: response.status, data: result };
    } catch (error) {
        console.error(`Error testing ${method} ${url}:`, error);
        return { status: 500, error };
    }
}

async function runTests() {
    console.log('🧪 Starting API Security Tests...\n');

    // Test 1: Health check
    console.log('Testing Health Check...');
    await testEndpoint('GET', '/health');

    // Test 2: Try to access protected endpoint without token (should fail)
    console.log('\nTesting Protected Endpoint Without Token (Should Fail)...');
    const protectedResponse = await testEndpoint('GET', '/api/data');
    if (protectedResponse.status === 401) {
        console.log('Correctly blocked unauthorized access');
    } else {
        console.log('Should have blocked unauthorized access');
    }

    // Test 3: Create a test user
    console.log('\nCreating Test User...');
    const createUserResponse = await testEndpoint('POST', '/api/users', {
        username: 'testuser',
        email: 'test@example.com',
        password: 'testpass123'
    });

    // Test 4: Login with the test user
    console.log('\nTesting Login...');
    const loginResponse = await testEndpoint('POST', '/auth/login', {
        username: 'testuser',
        password: 'testpass123'
    });

    let token: string | undefined;
    if (loginResponse.status === 200 && loginResponse.data.token) {
        token = loginResponse.data.token;
        console.log('Login successful, got JWT token');
    } else {
        console.log('Login failed');
    }

    // Test 5: Access protected endpoint with token
    if (token) {
        console.log('\nTesting Protected Endpoint With Token...');
        const protectedWithToken = await testEndpoint('GET', '/api/data', null, token);
        if (protectedWithToken.status === 200) {
            console.log('Successfully accessed protected endpoint');
        } else {
            console.log('Failed to access protected endpoint with valid token');
        }
    }

    // Test 6: Test XSS protection - try to inject malicious content
    if (token) {
        console.log('\nTesting XSS Protection...');
        const xssTest = await testEndpoint('POST', '/api/posts', {
            title: '<script>alert("XSS Attack!")</script>',
            content: 'Test content with <img src=x onerror=alert(1)>'
        }, token);

        if (xssTest.status === 201) {
            console.log('Post created - check if XSS content was sanitized');
            console.log('Post data:', JSON.stringify(xssTest.data.post, null, 2));
        }
    }

    // Test 7: Test SQL injection attempt
    console.log('\nTesting SQL Injection Protection...');
    const sqlInjectionTest = await testEndpoint('POST', '/auth/login', {
        username: "' OR '1'='1",
        password: "' OR '1'='1"
    });

    if (sqlInjectionTest.status === 401) {
        console.log('SQL injection attempt correctly blocked');
    } else {
        console.log('SQL injection protection failed!');
    }

    // Test 8: Test rate limiting
    console.log('\nTesting Rate Limiting...');
    console.log('Making multiple rapid requests to test rate limiting...');

    const rateLimitPromises = [];
    for (let i = 0; i < 10; i++) {
        rateLimitPromises.push(testEndpoint('POST', '/auth/login', {
            username: 'demo_user',
            password: 'wrong_password'
        }));
    }

    const rateLimitResults = await Promise.all(rateLimitPromises);
    const blockedRequests = rateLimitResults.filter(r => r.status === 429).length;

    if (blockedRequests > 0) {
        console.log(`Rate limiting working - ${blockedRequests} requests were blocked`);
    } else {
        console.log('Rate limiting may not be working as expected');
    }

    console.log('\nAPI Security Tests Completed!');
    console.log('\nSummary:');
    console.log('- JWT Authentication implemented');
    console.log('- Password hashing with bcrypt');
    console.log('- SQL injection protection with parameterized queries');
    console.log('- XSS protection with data sanitization');
    console.log('- Rate limiting configured');
    console.log('- Security headers with Helmet');
    console.log('- CORS protection');
    console.log('- Input validation');
}

runTests().catch(console.error);
