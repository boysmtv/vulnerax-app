import axios from 'axios'

export const api = axios.create({
  baseURL: '',
  headers: { 'Content-Type': 'application/json' }
})

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('vulnerax_token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

api.interceptors.response.use(res => res, err => {
  if (err.response?.status === 401 || err.response?.status === 403) {
    // 401 = missing/invalid token, 403 = expired/invalid or permission — both require re-login for now
    const msg = err.response?.data?.message || ''
    if (msg.includes('Unauthorized') || msg.includes('Forbidden') || err.response?.status === 401) {
      localStorage.removeItem('vulnerax_token')
      if (location.pathname !== '/login') location.href = '/login'
    }
  }
  return Promise.reject(err)
})
