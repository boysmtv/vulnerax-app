import { test, expect } from '@playwright/test';

test.describe('VulneraX E2E Tests', () => {
  test('should load login page', async ({ page }) => {
    await page.goto('/login');
    await expect(page).toHaveTitle(/VulneraX/);
  });

  test('should display login form elements', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByPlaceholder('Email')).toBeVisible();
    await expect(page.getByPlaceholder('Password')).toBeVisible();
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible();
  });

  test('should show error on invalid login', async ({ page }) => {
    await page.goto('/login');
    await page.getByPlaceholder('Email').fill('wrong@email.com');
    await page.getByPlaceholder('Password').fill('wrongpassword');
    await page.getByRole('button', { name: /sign in/i }).click();
    await expect(page.locator('.bg-red-50, [role="alert"]')).toBeVisible({ timeout: 5000 });
  });

  test('should navigate to root and show app', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const url = page.url();
    expect(url).toMatch(/\/login|\/$/);
  });

  test('should have valid page title', async ({ page }) => {
    await page.goto('/login');
    const title = await page.title();
    expect(title).toBeTruthy();
  });
});
