import { test, expect } from '@playwright/test';

test.describe('VulneraX E2E Tests', () => {
  test('should load login page', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/VulneraX/);
  });

  test('should display login form', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByLabel(/email/i)).toBeVisible();
    await expect(page.getByLabel(/password/i)).toBeVisible();
  });

  test('should navigate to dashboard after login', async ({ page }) => {
    await page.goto('/login');
    await page.getByLabel(/email/i).fill('admin@vulnerax.io');
    await page.getByLabel(/password/i).fill('password');
    await page.getByRole('button', { name: /login/i }).click();
    await expect(page).toHaveURL(/dashboard/);
  });

  test('should display dashboard metrics', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.getByText('Security Command Center')).toBeVisible();
  });

  test('should navigate to findings page', async ({ page }) => {
    await page.goto('/findings');
    await expect(page.getByText(/findings/i)).toBeVisible();
  });

  test('should navigate to reports page', async ({ page }) => {
    await page.goto('/reports');
    await expect(page.getByText(/reports/i)).toBeVisible();
  });

  test('should display one-click test page', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText(/Test Platform Apa Saja/i)).toBeVisible();
  });
});
