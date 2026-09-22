<template>
  <div class="not-found">
    <div class="not-found-card">
      <div class="code">404</div>
      <div class="desc">{{ T('NotFound') }}</div>
      <el-button type="primary" @click="goHome">{{ T('BackHome') }}</el-button>
    </div>
  </div>
</template>

<script>
  import { useRouter } from 'vue-router'
  import { T } from '@/utils/i18n'
  export default {
    name: '404',
    setup () {
      const router = useRouter()
      const goHome = () => router.push('/')
      return { goHome, T }
    },
  }
</script>

<style scoped lang="scss">
.not-found {
  min-height: 80vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.not-found-card {
  text-align: center;
  background: rgba(39, 39, 39, 0.62);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 14px;
  padding: 40px 48px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 14px;
}
.code {
  font-size: 64px;
  font-weight: 700;
  letter-spacing: -0.04em;
  color: #ffffff;
  line-height: 1;
}
.desc {
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
</style>