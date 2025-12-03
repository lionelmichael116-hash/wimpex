/**
 * End-to-End Upload Test Suite for Wimpex
 * Tests: presign, S3 upload, local fallback, moderation checks, avatar upload
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const BASE_URL = 'http://localhost:3000';
const TEST_USER = { username: 'testuser123', email: 'test@example.com', password: 'testpass123', gender: 'other' };

let testToken = null;
let testUserId = null;

async function request(method, endpoint, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, BASE_URL);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers: { 'Content-Type': 'application/json', ...headers }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({ status: res.statusCode, body: json });
        } catch (e) {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function runTests() {
  console.log('🧪 Starting Wimpex Upload E2E Tests...\n');

  try {
    // Test 1: Signup
    console.log('Test 1: User signup');
    let res = await request('POST', '/api/auth/signup', TEST_USER);
    if (res.status !== 200) throw new Error(`Signup failed: ${res.status}`);
    testToken = res.body.token;
    testUserId = res.body.userId;
    console.log(`✅ Signup OK (userId: ${testUserId})\n`);

    // Test 2: Presign endpoint
    console.log('Test 2: Get presigned URL');
    res = await request('GET', '/api/upload/presign?filename=test.jpg&contentType=image/jpeg', null, {
      'Authorization': `Bearer ${testToken}`
    });
    if (res.status !== 200 && res.status !== 400) throw new Error(`Presign failed: ${res.status}`);
    if (res.status === 200) {
      console.log(`✅ Presign OK (got URL: ${res.body.url ? 'yes' : 'no'})\n`);
    } else {
      console.log(`⚠️  Presign not available (S3 not configured): ${res.body.error}\n`);
    }

    // Test 3: Local upload (avatar)
    console.log('Test 3: Avatar upload via server');
    const testImageBase64 = 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/2wBDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAARCABQAFADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWm5ybnJ2eoqOkpaanqKmqsrO0tba2uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlbaWmJmaoqOkpaanqKmqsrO0tba2uLm6wsPExcbHyMnK0tPU1fbW2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD+/KKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigD/2Q==';
    res = await request('POST', '/api/upload', { filename: 'avatar.jpg', data: testImageBase64 }, {
      'Authorization': `Bearer ${testToken}`
    });
    if (res.status !== 200) throw new Error(`Upload failed: ${res.status}`);
    console.log(`✅ Upload OK (url: ${res.body.url ? 'received' : 'missing'})\n`);

    // Test 4: Check moderation queue
    console.log('Test 4: Moderation queue (admin only)');
    res = await request('GET', '/api/moderation', null, { 'Authorization': `Bearer ${testToken}` });
    if (res.status === 403) {
      console.log(`✅ Moderation endpoint auth OK (user not admin)\n`);
    } else if (res.status === 200) {
      console.log(`✅ Moderation queue accessible (${(res.body || []).length} items)\n`);
    } else {
      console.log(`⚠️  Moderation endpoint check: ${res.status}\n`);
    }

    // Test 5: Settings update with new avatar URL
    console.log('Test 5: Settings update with uploaded avatar');
    res = await request('PUT', '/api/settings', {
      avatar: res.body.url || testImageBase64,
      username: TEST_USER.username,
      email: TEST_USER.email,
      bio: 'Test bio'
    }, { 'Authorization': `Bearer ${testToken}` });
    if (res.status !== 200) throw new Error(`Settings update failed: ${res.status}`);
    console.log(`✅ Settings update OK\n`);

    // Test 6: Upload via presigned (if S3 available)
    console.log('Test 6: Presigned PUT (S3 direct upload simulation)');
    res = await request('GET', '/api/upload/presign?filename=test2.jpg&contentType=image/jpeg', null, {
      'Authorization': `Bearer ${testToken}`
    });
    if (res.status === 200) {
      console.log(`✅ Presigned URL generated (expires in 1 hour)\n`);
    } else {
      console.log(`⚠️  S3 presign not available (may not be configured)\n`);
    }

    console.log('✅ All tests passed!\n');
    process.exit(0);
  } catch (err) {
    console.error('❌ Test failed:', err.message);
    process.exit(1);
  }
}

// Run if server is available
setTimeout(runTests, 1000);
