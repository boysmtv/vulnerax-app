import { vi, describe, it, expect, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

const { mockPost } = vi.hoisted(() => ({
  mockPost: vi.fn().mockResolvedValue({ data: { success: true, data: { id: '1', token: 'mock-token' } } }),
}))
vi.mock('../api/client', () => ({
  api: { get: vi.fn().mockResolvedValue({ data: { success: true, data: { content: [] } } }), post: mockPost, put: vi.fn().mockResolvedValue({ data: { success: true } }) },
}))
const mockLogin = vi.fn()
vi.mock('../store/auth', () => ({
  useAuth: () => ({ token: 'mock-token', user: { email: 'test@vulnerax.io', role: 'DEVELOPER' }, login: mockLogin, logout: vi.fn() }),
}))

import Login from '../pages/Login'

const qc = () => new QueryClient({ defaultOptions: { queries: { retry: false } } })
const wrap = (c: React.ReactNode) => <QueryClientProvider client={qc()}><MemoryRouter>{c}</MemoryRouter></QueryClientProvider>

describe('Login', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders form with email and password inputs', () => {
    render(wrap(<Login />))
    expect(screen.getByPlaceholderText(/email/i)).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/password/i)).toBeInTheDocument()
  })

  it('displays Welcome back heading in login mode', () => {
    render(wrap(<Login />))
    expect(screen.getByText('Welcome back')).toBeInTheDocument()
  })

  it('displays VulneraX branding and tagline', () => {
    render(wrap(<Login />))
    expect(screen.getByText('VulneraX')).toBeInTheDocument()
    expect(screen.getByText('Unified Security Platform')).toBeInTheDocument()
  })

  it('displays demo credentials hint', () => {
    render(wrap(<Login />))
    expect(screen.getByText(/admin@vulnerax\.io/)).toBeInTheDocument()
  })

  it('pre-fills email and password fields', () => {
    render(wrap(<Login />))
    expect(screen.getByPlaceholderText(/email/i)).toHaveValue('admin@vulnerax.io')
    expect(screen.getByPlaceholderText(/password/i)).toHaveValue('Admin12345!abc')
  })

  it('toggles to register mode and shows fullName input', () => {
    render(wrap(<Login />))
    fireEvent.click(screen.getByText('Register'))
    expect(screen.getByRole('heading', { name: 'Create account' })).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/full name/i)).toBeInTheDocument()
  })

  it('toggles back to login mode and hides fullName', () => {
    render(wrap(<Login />))
    fireEvent.click(screen.getByText('Register'))
    expect(screen.getByPlaceholderText(/full name/i)).toBeInTheDocument()
    fireEvent.click(screen.getByText('Login'))
    expect(screen.getByText('Welcome back')).toBeInTheDocument()
    expect(screen.queryByPlaceholderText(/full name/i)).not.toBeInTheDocument()
  })

  it('changes email input value', () => {
    render(wrap(<Login />))
    const emailInput = screen.getByPlaceholderText(/email/i)
    fireEvent.change(emailInput, { target: { value: 'new@email.com' } })
    expect(emailInput).toHaveValue('new@email.com')
  })

  it('changes password input value', () => {
    render(wrap(<Login />))
    const passInput = screen.getByPlaceholderText(/password/i)
    fireEvent.change(passInput, { target: { value: 'newpass' } })
    expect(passInput).toHaveValue('newpass')
  })

  it('changes fullName input in register mode', () => {
    render(wrap(<Login />))
    fireEvent.click(screen.getByText('Register'))
    const nameInput = screen.getByPlaceholderText(/full name/i)
    fireEvent.change(nameInput, { target: { value: 'John Doe' } })
    expect(nameInput).toHaveValue('John Doe')
  })

  it('submits login and calls api.post with correct url and payload', async () => {
    mockPost.mockResolvedValue({ data: { success: true, data: { accessToken: 'tok123', user: { email: 'admin@vulnerax.io' } } } })
    render(wrap(<Login />))
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/auth/login', expect.objectContaining({ email: 'admin@vulnerax.io', password: 'Admin12345!abc' })))
  })

  it('calls login from auth store after successful submit', async () => {
    mockPost.mockResolvedValue({ data: { success: true, data: { accessToken: 'tok123', user: { email: 'admin@vulnerax.io' } } } })
    render(wrap(<Login />))
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => expect(mockLogin).toHaveBeenCalled())
  })

  it('submits register with fullName, name, and role in payload', async () => {
    mockPost.mockResolvedValue({ data: { success: true, data: { token: 'reg-tok', user: {} } } })
    render(wrap(<Login />))
    fireEvent.click(screen.getByText('Register'))
    fireEvent.change(screen.getByPlaceholderText(/full name/i), { target: { value: 'New User' } })
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/auth/register', expect.objectContaining({ fullName: 'New User', name: 'New User', role: 'SECURITY_ENGINEER' })))
  })

  it('shows error banner when api.post rejects with response message', async () => {
    mockPost.mockRejectedValue({ response: { data: { message: 'Invalid credentials' } } })
    render(wrap(<Login />))
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => expect(screen.getByText('Invalid credentials')).toBeInTheDocument())
  })

  it('shows error banner when api.post rejects without response', async () => {
    mockPost.mockRejectedValue(new Error('Network Error'))
    render(wrap(<Login />))
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => expect(screen.getByText('Network Error')).toBeInTheDocument())
  })

  it('shows loading state on submit button', () => {
    mockPost.mockReturnValue(new Promise(() => {}))
    render(wrap(<Login />))
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    expect(screen.getByText('Please wait...')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /please wait/i })).toBeDisabled()
  })

  it('shows Create account button text in register mode', () => {
    render(wrap(<Login />))
    fireEvent.click(screen.getByText('Register'))
    expect(screen.getByRole('button', { name: /create account/i })).toBeInTheDocument()
  })

  it('shows security features list in footer', () => {
    render(wrap(<Login />))
    expect(screen.getByText(/SAST.*SCA.*Secrets/)).toBeInTheDocument()
  })

  it('displays right panel with security score and risk info', () => {
    render(wrap(<Login />))
    expect(screen.getByText('74 / 100')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText(/internet-exposed/)).toBeInTheDocument()
  })

  it('clears previous error on new submit', async () => {
    mockPost.mockRejectedValueOnce({ response: { data: { message: 'Error 1' } } })
    render(wrap(<Login />))
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => expect(screen.getByText('Error 1')).toBeInTheDocument())
    mockPost.mockResolvedValue({ data: { success: true, data: { accessToken: 'tok', user: {} } } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => expect(screen.queryByText('Error 1')).not.toBeInTheDocument())
  })
})
