import { describe, it, expect, vi, beforeEach } from 'vitest'
import axios from 'axios'

// we test the client interceptor logic directly
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
    // invoke request interceptor directly
    const cfg: any = { headers: {} }
    // @ts-ignore - reach interceptor
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
})
