<template>
  <div class="min-h-screen py-8">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div class="flex justify-between items-center mb-8">
        <h1 class="text-4xl font-semibold text-gray-900 tracking-tight">My Requests</h1>
        <router-link 
          v-if="user?.role !== 'admin'"
          to="/event-request" 
          class="glass-btn glass-btn-primary"
        >
          + New Request
        </router-link>
      </div>
      <div v-if="loading" class="text-center py-16">
        <div class="inline-block animate-spin rounded-full h-12 w-12 border-3 border-blue-500/30 border-t-blue-500"></div>
        <p class="mt-4 text-gray-700 font-medium">Loading...</p>
      </div>
      <div v-else-if="requests.length === 0" class="text-center py-16">
        <div class="glass-card p-12 max-w-md mx-auto">
          <h3 class="text-2xl font-semibold text-gray-900 mb-3">No requests</h3>
          <p class="text-gray-700 mb-6">You haven't submitted any event requests yet</p>
          <router-link 
            v-if="user?.role !== 'admin'"
            to="/event-request" 
            class="glass-btn glass-btn-primary inline-block mb-3"
          >
            Create New Request
          </router-link>
          <br>
          <router-link to="/calendar" class="glass-btn inline-block">Go to Calendar</router-link>
        </div>
      </div>
      <div v-else class="space-y-6">
        <div
          v-for="request in requests"
          :key="request.id"
          class="glass-card p-6"
        >
          <div class="flex justify-between items-start mb-4">
            <div class="flex-1">
              <h3 class="text-xl font-semibold text-gray-900 mb-2">{{ request.title }}</h3>
              <p class="text-gray-700 mb-4">{{ request.description }}</p>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm text-gray-600">
                <div>
                  <span class="font-semibold">📅 Date:</span> {{ formatDate(request.date) }}
                </div>
                <div>
                  <span class="font-semibold">🕐 Time:</span> {{ formatTime(request.start_time) }}
                </div>
                <div>
                  <span class="font-semibold">📍 Location:</span> {{ request.location }}
                </div>
                <div>
                  <span class="font-semibold">👥 Participants:</span> {{ request.max_participants }} people
                </div>
              </div>
            </div>
            <span
              :class="[
                'px-4 py-2 rounded-full text-sm font-semibold whitespace-nowrap ml-4',
                request.status === 'approved' ? 'bg-green-100 text-green-800' :
                request.status === 'rejected' ? 'bg-red-100 text-red-800' :
                'bg-yellow-100 text-yellow-800'
              ]"
            >
              {{ request.status === 'approved' ? '✓ Approved' :
                 request.status === 'rejected' ? '✗ Rejected' :
                 '⏳ Pending' }}
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed, onMounted } from 'vue'
import { useAuthStore } from '../stores/auth'
import api from '../services/api'

export default {
  name: 'MyRequests',
  setup() {
    const authStore = useAuthStore()
    const user = computed(() => authStore.user)
    const requests = ref([])
    const loading = ref(true)
    
    const fetchRequests = async () => {
      try {
        const response = await api.get('/my-event-requests')
        requests.value = response.data
      } catch (error) {
        console.error('Failed to fetch requests:', error)
      } finally {
        loading.value = false
      }
    }
    
    const formatDate = (dateString) => {
      return new Date(dateString).toLocaleDateString('en-US')
    }
    
    const formatTime = (timeString) => {
      return timeString.substring(0, 5)
    }
    
    onMounted(() => {
      fetchRequests()
    })
    
    return {
      user,
      requests,
      loading,
      formatDate,
      formatTime
    }
  }
}
</script>

