import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useAuth } from '../store/auth'

const store = useAuth

describe('auth store', () => {
  beforeEach(() => {
    store.setState({ token: null, user: null })
  })

  it('has initial state with null token and user', () => {
    const state = store.getState()
    expect(state.token).toBeNull()
    expect(state.user).toBeNull()
  })

  it('login sets token and user in state', () => {
    const user = { id: 'u1', email: 'test@vulnerax.io', role: 'DEVELOPER', fullName: 'Test User' }
    store.getState().login('my-token', user)
    const state = store.getState()
    expect(state.token).toBe('my-token')
    expect(state.user).toEqual(user)
  })

  it('login persists to localStorage', () => {
    const user = { id: 'u1', email: 'a@b.com', role: 'ADMIN', fullName: 'Admin' }
    const setItemSpy = vi.spyOn(window.localStorage, 'setItem')
    store.getState().login('tok-abc', user)
    expect(setItemSpy).toHaveBeenCalledWith('vulnerax_token', 'tok-abc')
    expect(setItemSpy).toHaveBeenCalledWith('vulnerax_user', JSON.stringify(user))
    setItemSpy.mockRestore()
  })

  it('logout clears token and user from state', () => {
    const user = { id: 'u1', email: 'test@vulnerax.io', role: 'DEVELOPER', fullName: 'Test' }
    store.getState().login('token-123', user)
    store.getState().logout()
    const state = store.getState()
    expect(state.token).toBeNull()
    expect(state.user).toBeNull()
  })

  it('logout calls localStorage.removeItem', () => {
    const removeSpy = vi.spyOn(window.localStorage, 'removeItem')
    const user = { id: 'u1', email: 'x@y.com', role: 'DEV', fullName: 'X' }
    store.getState().login('tok', user)
    store.getState().logout()
    expect(removeSpy).toHaveBeenCalledWith('vulnerax_token')
    expect(removeSpy).toHaveBeenCalledWith('vulnerax_user')
    removeSpy.mockRestore()
  })

  it('setUser updates user in state', () => {
    const user = { id: 'u1', email: 'a@b.com', role: 'DEV', fullName: 'A' }
    store.getState().login('tok', user)
    const updated = { id: 'u1', email: 'new@b.com', role: 'ADMIN', fullName: 'Updated' }
    store.getState().setUser(updated)
    expect(store.getState().user).toEqual(updated)
  })

  it('setUser calls localStorage.setItem', () => {
    const setItemSpy = vi.spyOn(window.localStorage, 'setItem')
    const user = { id: 'u1', email: 'a@b.com', role: 'DEV', fullName: 'A' }
    store.getState().login('tok', user)
    setItemSpy.mockClear()
    const updated = { id: 'u1', email: 'new@b.com', role: 'ADMIN', fullName: 'New' }
    store.getState().setUser(updated)
    expect(setItemSpy).toHaveBeenCalledWith('vulnerax_user', JSON.stringify(updated))
    setItemSpy.mockRestore()
  })

  it('token remains unchanged after setUser', () => {
    const user = { id: 'u1', email: 'a@b.com', role: 'DEV', fullName: 'A' }
    store.getState().login('keep-this-token', user)
    store.getState().setUser({ ...user, fullName: 'Changed' })
    expect(store.getState().token).toBe('keep-this-token')
  })
})
