import request from '@/utils/request'

export function status () {
  return request({
    url: '/tfa/status',
  })
}

export function bind () {
  return request({
    url: '/tfa/bind',
    method: 'post',
  })
}

export function bindConfirm (data) {
  return request({
    url: '/tfa/bindConfirm',
    method: 'post',
    data,
  })
}

export function unbind (data) {
  return request({
    url: '/tfa/unbind',
    method: 'post',
    data,
  })
}
