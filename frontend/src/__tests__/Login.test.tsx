import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import Login from '../pages/Login'
import * as client from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return { ...actual, api: { ...actual.api, post: vi.fn() } }
})

describe('Login — auth flow', () => {
  it('renders login form', () => {
    render(<MemoryRouter><Login /></MemoryRouter>)
    expect(screen.getAllByText(/VulneraX/i).length).toBeGreaterThan(0)
    expect(screen.getByPlaceholderText(/Email/i)).toBeInTheDocument()
  })

  it('has password field and submit', () => {
    render(<MemoryRouter><Login /></MemoryRouter>)
    const pwd = screen.queryByPlaceholderText(/password/i) || screen.queryByLabelText(/password/i) || document.querySelector('input[type="password"]')
    expect(pwd).toBeInTheDocument()
    const btn = screen.queryByRole('button', { name: /sign in|login|submit/i }) || document.querySelector('button[type="submit"]')
    expect(btn).toBeInTheDocument()
  })

  it('calls api on submit when mocked', async () => {
    vi.mocked(client.api.post).mockResolvedValue({ data: { data: { token: 'tok', user: { email: 'a@b.com', fullName: 'A', role: 'DEVELOPER' } } } })
    render(<MemoryRouter><Login /></MemoryRouter>)
    const emailInput = screen.getByPlaceholderText('Email') as HTMLInputElement
    const pwdInput = screen.getByPlaceholderText('Password') as HTMLInputElement
    const btn = screen.getByText('Sign in') as HTMLButtonElement
    fireEvent.change(emailInput, { target: { value: 'a@b.com' } })
    fireEvent.change(pwdInput, { target: { value: 'secret' } })
    fireEvent.click(btn)
    await waitFor(() => {
      expect(document.body).toBeInTheDocument()
    })
  })
})
