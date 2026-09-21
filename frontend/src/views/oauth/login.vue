<template>
  <div class="oauth">
    <el-card class="card">
      <h2>{{ T('OauthLogining') }}</h2>
      <el-form class="info" label-width="100px">
        <el-form-item :label="T('Device')">
          <div class="impt">{{ oauthInfo.device_name }}</div>
        </el-form-item>
        <el-form-item label="ID">
          <div class="impt">{{ oauthInfo.id }}</div>
        </el-form-item>
        <el-form-item label-width="0">
          <el-button style="width: 100%" v-if="!resStatus" type="success" size="large" @click="toConfirm">{{ T('ConfirmOauth') }}</el-button>
        </el-form-item>
        <el-form-item label-width="0">
          <el-button style="width: 100%" size="large" @click="out">{{ T('Close') }}</el-button>
        </el-form-item>
      </el-form>
      {{ T('OauthCloseNote') }}
    </el-card>
  </div>
</template>

<script setup>
  import { ref, onMounted } from 'vue'
  import { info, confirm } from '@/api/oauth'
  import { useRoute, useRouter } from 'vue-router'
  import { ElMessage } from 'element-plus'
  import { T } from '@/utils/i18n'

  const oauthInfo = ref({})
  const route = useRoute()
  const router = useRouter()
  const code = route.params?.code
  if (!code) {
    // router.push('/')
  }
  const getInfo = async () => {
    const res = await info({ code }).catch(_ => false)
    if (res) {
      oauthInfo.value = res.data
    } else {
      // router.push('/')
    }
  }
  getInfo()
  const resStatus = ref(0)
  const toConfirm = async () => {
    const res = await confirm({ code }).catch(_ => false)
    if (res) {
      resStatus.value = 1
      ElMessage.success(T('OperationSuccessAndCloseAfter3Seconds'))
      setTimeout(_ => {
        out()
      }, 3000)
    }
  }
  const out = () => {
    window.close()
  }

</script>

<style scoped lang="scss">
.oauth {
  width: 100vw;
  height: 100vh;
  background:
    radial-gradient(1200px 800px at 15% -10%, rgba(255, 255, 255, 0.07), transparent 60%),
    radial-gradient(900px 600px at 90% 5%, rgba(255, 255, 255, 0.05), transparent 60%),
    #171717;
  background-attachment: fixed;
  padding-top: 25vh;
  box-sizing: border-box;

  .card {
    max-width: 500px;
    background: rgba(39, 39, 39, 0.72);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 14px;
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.45);
    color: #fff;
    margin: 0 auto;
    text-align: center;

    .info {
      display: block;
      line-height: 30px;
      margin-bottom: 50px;

      ::v-deep(.el-form-item__label) {
        color: #fff;
      }
    }

    .impt {
      font-weight: bold;
      font-size: 20px;
    }
  }
}
</style>
