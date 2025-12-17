import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../services/api'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(sessionStorage.getItem('token') || null)
  const user = ref(null)

  const isAuthenticated = computed(() => !!token.value)

  const login = async (email, password) => {
    const formData = new FormData()
    formData.append('username', email)
    formData.append('password', password)
    
    const response = await api.post('/login', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })
    
    token.value = response.data.access_token
    sessionStorage.setItem('token', token.value)
    
    await fetchUser()
    
    return response.data
  }

  const register = async (userData) => {
    const response = await api.post('/register', userData)
    return response.data
  }

  const logout = () => {
    token.value = null
    user.value = null
    sessionStorage.removeItem('token')
  }

  const fetchUser = async () => {
    try {
      const response = await api.get('/me')
      user.value = response.data
      return response.data
    } catch (error) {
      if (error.response?.status === 401) {
        logout()
      }
      throw error
    }
  }

  return {
    token,
    user,
    isAuthenticated,
    login,
    register,
    logout,
    fetchUser
  }
})


