import request from '@/utils/request'

export function dashboardStats () {
  return request({
    url: '/dashboard/stats',
    method: 'get',
  })
}