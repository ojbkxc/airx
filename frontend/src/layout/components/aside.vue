<template>
  <el-scrollbar class="scroll-sidebar" height="100vh">
    <menus></menus>
  </el-scrollbar>
</template>
<script>
  import Menus from '@/layout/components/menu/index.vue'
  import { defineComponent, ref, onMounted } from 'vue'

  export default defineComponent({
    name: 'GAside',
    components: { Menus },
  })
</script>

<style scoped lang="scss">
.scroll-sidebar {
  background-color: rgba(18, 18, 22, 0.7);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-right: 1px solid rgba(255, 255, 255, 0.06);
}
</style>
