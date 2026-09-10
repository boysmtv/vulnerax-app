import { create } from 'zustand'

type User = { id: string; email: string; role: string; fullName: string }

type State = {
  user: User | null
  token: string | null
  login: (token: string, user: User) => void
  logout: () => void
  setUser: (u: User) => void
}

export const useAuth = create<State>((set) => ({
  user: JSON.parse(localStorage.getItem('vulnerax_user') || 'null'),
  token: localStorage.getItem('vulnerax_token'),
  login: (token, user) => {
    localStorage.setItem('vulnerax_token', token)
    localStorage.setItem('vulnerax_user', JSON.stringify(user))
    set({ token, user })
  },
  logout: () => {
    localStorage.removeItem('vulnerax_token')
    localStorage.removeItem('vulnerax_user')
    set({ token: null, user: null })
  },
  setUser: (user) => {
    localStorage.setItem('vulnerax_user', JSON.stringify(user))
    set({ user })
  }
}))
