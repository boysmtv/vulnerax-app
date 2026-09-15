import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api } from '../api/client'

describe('api client', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  it('creates axios instance with json header', () => {
    expect(api.defaults.headers['Content-Type']).toBe('application/json')
  })

  it('attaches Authorization header when token exists', async () => {
    const token = 'tok123'
    // @ts-ignore
    localStorage.getItem = vi.fn().mockReturnValue(token)
    const cfg: any = { headers: {} }
    const interceptor = (api.interceptors.request as any).handlers[0].fulfilled
    const out = await interceptor(cfg)
    expect(out.headers.Authorization).toBe(`Bearer ${token}`)
  })

  it('does not attach auth when no token', async () => {
    // @ts-ignore
    localStorage.getItem = vi.fn().mockReturnValue(null)
    const cfg: any = { headers: {} }
    const interceptor = (api.interceptors.request as any).handlers[0].fulfilled
    const out = await interceptor(cfg)
    expect(out.headers.Authorization).toBeUndefined()
  })

  it('handles 401 error by clearing token', async () => {
    const handler = (api.interceptors.response as any).handlers[0].rejected
    const err = { response: { status: 401, data: { message: 'Unauthorized' } } }
    try { await handler(err) } catch {}
    expect(localStorage.getItem('vulnerax_token')).toBeFalsy()
  })

  it('handles 403 error with Forbidden message', async () => {
    const handler = (api.interceptors.response as any).handlers[0].rejected
    const err = { response: { status: 403, data: { message: 'Forbidden access' } } }
    try { await handler(err) } catch {}
    expect(localStorage.getItem('vulnerax_token')).toBeFalsy()
  })

  it('handles 401 error without message', async () => {
    const handler = (api.interceptors.response as any).handlers[0].rejected
    const err = { response: { status: 401, data: {} } }
    try { await handler(err) } catch {}
    expect(localStorage.getItem('vulnerax_token')).toBeFalsy()
  })

  it('skips redirect when already on /login', async () => {
    const realHref = location.href
    const mockLocation = { ...location, pathname: '/login', href: realHref }
    Object.defineProperty(window, 'location', { value: mockLocation, writable: true, configurable: true })
    const handler = (api.interceptors.response as any).handlers[0].rejected
    const err = { response: { status: 401, data: { message: 'Unauthorized' } } }
    try { await handler(err) } catch {}
    expect(localStorage.getItem('vulnerax_token')).toBeFalsy()
  })

  it('handles 401 error without message', async () => {
    const handler = (api.interceptors.response as any).handlers[0].rejected
    const err = { response: { status: 401, data: {} } }
    try { await handler(err) } catch {}
    expect(localStorage.getItem('vulnerax_token')).toBeFalsy()
  })

  it('handles 403 error without matching message', async () => {
    // @ts-ignore
    localStorage.getItem = vi.fn().mockReturnValue('tok123')
    const handler = (api.interceptors.response as any).handlers[0].rejected
    const err = { response: { status: 403, data: { message: 'Some other error' } } }
    try { await handler(err) } catch {}
    expect(localStorage.getItem('vulnerax_token')).toBeTruthy()
  })

  it('rejects non-401/403 errors without clearing token', async () => {
    // @ts-ignore
    localStorage.getItem = vi.fn().mockReturnValue('tok123')
    const handler = (api.interceptors.response as any).handlers[0].rejected
    const err = { response: { status: 500, data: { message: 'Server error' } } }
    try { await handler(err) } catch {}
    expect(localStorage.getItem('vulnerax_token')).toBeTruthy()
  })

  it('handles error without response object', async () => {
    // @ts-ignore
    localStorage.getItem = vi.fn().mockReturnValue('tok123')
    const handler = (api.interceptors.response as any).handlers[0].rejected
    const err = { message: 'Network error' }
    try { await handler(err) } catch {}
    expect(localStorage.getItem('vulnerax_token')).toBeTruthy()
  })

  it('handles successful response passthrough', async () => {
    const handler = (api.interceptors.response as any).handlers[0].fulfilled
    const res = { data: { success: true } }
    const out = await handler(res)
    expect(out).toBe(res)
  })
})
