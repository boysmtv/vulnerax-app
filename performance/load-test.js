import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const duration = new Trend('duration');

export const options = {
  stages: [
    { duration: '30s', target: 20 },
    { duration: '1m', target: 20 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],
    errors: ['rate<0.1'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

export default function () {
  // Test login endpoint
  const loginRes = http.post(`${BASE_URL}/api/v1/auth/login`, JSON.stringify({
    email: 'admin@vulnerax.io',
    password: 'password',
  }), {
    headers: { 'Content-Type': 'application/json' },
  });

  check(loginRes, {
    'login status is 200': (r) => r.status === 200,
    'login response time < 500ms': (r) => r.timings.duration < 500,
  });

  errorRate.add(loginRes.status !== 200);
  duration.add(loginRes.timings.duration);

  sleep(1);

  // Test dashboard endpoint (with auth token)
  if (loginRes.status === 200) {
    const token = loginRes.json('data.token');
    const headers = {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    };

    const dashboardRes = http.get(`${BASE_URL}/api/v1/dashboard/posture`, { headers });
    check(dashboardRes, {
      'dashboard status is 200': (r) => r.status === 200,
      'dashboard response time < 500ms': (r) => r.timings.duration < 500,
    });

    errorRate.add(dashboardRes.status !== 200);
    duration.add(dashboardRes.timings.duration);

    sleep(1);

    // Test findings endpoint
    const findingsRes = http.get(`${BASE_URL}/api/v1/findings?size=10`, { headers });
    check(findingsRes, {
      'findings status is 200': (r) => r.status === 200,
      'findings response time < 500ms': (r) => r.timings.duration < 500,
    });

    errorRate.add(findingsRes.status !== 200);
    duration.add(findingsRes.timings.duration);

    sleep(1);

    // Test scans endpoint
    const scansRes = http.get(`${BASE_URL}/api/v1/scans?size=10`, { headers });
    check(scansRes, {
      'scans status is 200': (r) => r.status === 200,
      'scans response time < 500ms': (r) => r.timings.duration < 500,
    });

    errorRate.add(scansRes.status !== 200);
    duration.add(scansRes.timings.duration);
  }

  sleep(1);
}

export function handleSummary(data) {
  return {
    'performance/summary.json': JSON.stringify(data, null, 2),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  // Simple text summary implementation
  return `\n=== Performance Test Summary ===
Requests: ${data.metrics.http_reqs?.values?.count || 0}
Duration: ${data.metrics.http_req_duration?.values?.avg?.toFixed(2) || 0}ms (avg)
Errors: ${((data.metrics.errors?.values?.rate || 0) * 100).toFixed(2)}%
`;
}
