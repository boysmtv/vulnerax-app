import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const reqDuration = new Trend('req_duration');

const BASE_URL = __ENV.TARGET_URL || 'http://localhost:8080';
const AUTH_TOKEN = __ENV.AUTH_TOKEN || '';

export const options = {
  stages: [
    { duration: '30s', target: 20 },   // ramp up
    { duration: '1m',  target: 50 },   // sustained load
    { duration: '30s', target: 100 },  // spike
    { duration: '1m',  target: 50 },   // recovery
    { duration: '30s', target: 0 },    // ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1500'],
    errors: ['rate<0.1'],
  },
};

const headers = {
  'Content-Type': 'application/json',
  ...(AUTH_TOKEN ? { Authorization: `Bearer ${AUTH_TOKEN}` } : {}),
};

export default function () {
  // 1. Health check
  let res = http.get(`${BASE_URL}/actuator/health`);
  check(res, { 'health 200': (r) => r.status === 200 });

  // 2. Login
  res = http.post(`${BASE_URL}/api/v1/auth/login`, JSON.stringify({
    email: 'admin@vulnerax.io',
    password: 'Admin123!',
  }), { headers: { 'Content-Type': 'application/json' } });

  const token = res.json('data.accessToken') || res.json('data.token');
  const authHeaders = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  check(res, { 'login success': (r) => r.status === 200 });

  // 3. Dashboard posture
  res = http.get(`${BASE_URL}/api/v1/dashboard/posture`, { headers: authHeaders });
  check(res, { 'dashboard 200': (r) => r.status === 200 });
  reqDuration.add(res.timings.duration);

  // 4. Findings list
  res = http.get(`${BASE_URL}/api/v1/findings?size=20`, { headers: authHeaders });
  check(res, { 'findings list 200': (r) => r.status === 200 });
  reqDuration.add(res.timings.duration);

  // 5. Assets list
  res = http.get(`${BASE_URL}/api/v1/assets?size=20`, { headers: authHeaders });
  check(res, { 'assets list 200': (r) => r.status === 200 });
  reqDuration.add(res.timings.duration);

  // 6. Scans list
  res = http.get(`${BASE_URL}/api/v1/scans?size=10`, { headers: authHeaders });
  check(res, { 'scans list 200': (r) => r.status === 200 });
  reqDuration.add(res.timings.duration);

  // 7. Compliance frameworks
  res = http.get(`${BASE_URL}/api/v1/compliance/frameworks`, { headers: authHeaders });
  check(res, { 'compliance 200': (r) => r.status === 200 });
  reqDuration.add(res.timings.duration);

  // 8. Cloud resources
  res = http.get(`${BASE_URL}/api/v1/cloud?size=10`, { headers: authHeaders });
  check(res, { 'cloud 200': (r) => r.status === 200 });
  reqDuration.add(res.timings.duration);

  // 9. K8s resources
  res = http.get(`${BASE_URL}/api/v1/k8s?size=10`, { headers: authHeaders });
  check(res, { 'k8s 200': (r) => r.status === 200 });
  reqDuration.add(res.timings.duration);

  // 10. Notifications
  res = http.get(`${BASE_URL}/api/v1/notifications?size=10`, { headers: authHeaders });
  check(res, { 'notifications 200': (r) => r.status === 200 });
  reqDuration.add(res.timings.duration);

  errorRate.add(res.status !== 200);
  sleep(1);
}

export function handleSummary(data) {
  return {
    'performance/summary.json': JSON.stringify(data, null, 2),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, opts) {
  const lines = [];
  lines.push('=== VulneraX Load Test Summary ===');
  lines.push(`Total Requests: ${data.metrics.http_reqs?.values?.count || 0}`);
  lines.push(`Avg Duration: ${(data.metrics.http_req_duration?.values?.avg || 0).toFixed(2)}ms`);
  lines.push(`p95 Duration: ${(data.metrics.http_req_duration?.values?.['p(95)'] || 0).toFixed(2)}ms`);
  lines.push(`p99 Duration: ${(data.metrics.http_req_duration?.values?.['p(99)'] || 0).toFixed(2)}ms`);
  lines.push(`Error Rate: ${((data.metrics.errors?.values?.rate || 0) * 100).toFixed(2)}%`);
  lines.push(`RPS: ${(data.metrics.http_reqs?.values?.rate || 0).toFixed(2)}`);
  return lines.join('\n');
}
