<template>
  <el-dialog v-model="visibleLocal" :title="T('TwoFactorAuth')" width="420px" @close="onClose">
    <div v-if="!bound">
      <template v-if="!binding">
        <el-alert type="info" :closable="false">
          {{ bound ? T('TfaBound') : T('TfaNotBound') }}
        </el-alert>
        <div style="text-align:center;margin-top:18px">
          <el-button type="primary" @click="startBind">{{ T('TfaBind') }}</el-button>
        </div>
      </template>
      <template v-else>
        <p class="tfa-tip">{{ T('TfaScanTip') }}</p>
        <div class="tfa-qr">
          <div v-html="qrSvg"></div>
          <div class="tfa-secret">Secret: <code>{{ bindInfo.secret }}</code></div>
        </div>
        <el-form label-position="top">
          <el-form-item :label="T('TfaCode')">
            <el-input v-model="code" :placeholder="T('TfaInputCode')" maxlength="6" @keyup.enter="confirmBind"/>
          </el-form-item>
        </el-form>
        <div style="text-align:center">
          <el-button type="primary" :loading="loading" @click="confirmBind">{{ T('TfaConfirmBind') }}</el-button>
        </div>
      </template>
    </div>
    <div v-else>
      <el-alert type="success" :closable="false">{{ T('TfaBound') }}</el-alert>
      <div style="text-align:center;margin-top:18px">
        <el-button type="danger" @click="doUnbind">{{ T('TfaUnbind') }}</el-button>
      </div>
    </div>
  </el-dialog>
</template>

<script setup>
  import { ref, computed, watch } from 'vue'
  import { ElMessage } from 'element-plus'
  import { T } from '@/utils/i18n'
  import { status, bind, bindConfirm, unbind } from '@/api/tfa'
  import qrcode from 'qrcode-generator'

  const props = defineProps({ visible: Boolean })
  const emit = defineEmits(['update:visible', 'refresh'])

  const visibleLocal = computed({
    get: () => props.visible,
    set: v => emit('update:visible', v),
  })
  const bound = ref(false)
  const binding = ref(false)
  const loading = ref(false)
  const code = ref('')
  const bindInfo = ref(null)

  const qrSvg = computed(() => {
    if (!bindInfo.value) return ''
    try {
      const qr = qrcode(0, 'M')
      qr.addData(bindInfo.value.url)
      qr.make()
      return qr.createSvgTag({ cellSize: 4, margin: 2 })
    } catch (e) {
      return ''
    }
  })

  const onClose = () => {
    binding.value = false
    code.value = ''
  }

  const loadStatus = async () => {
    const res = await status().catch(_ => false)
    if (res && !res.code) {
      bound.value = !!res.data.bound
    }
  }

  const startBind = async () => {
    const res = await bind().catch(_ => false)
    if (res && !res.code) {
      bindInfo.value = res.data
      binding.value = true
    } else if (res) {
      ElMessage.error(res.message)
    }
  }

  const confirmBind = async () => {
    if (!code.value) return
    loading.value = true
    const res = await bindConfirm({ code: code.value }).catch(_ => false)
    loading.value = false
    if (res && !res.code) {
      ElMessage.success(T('OperationSuccess'))
      bound.value = true
      binding.value = false
      emit('refresh')
    } else if (res) {
      ElMessage.error(T('TfaCodeError'))
      // 重新生成（旧 secret 已消费）
      startBind()
    }
  }

  const doUnbind = async () => {
    const res = await unbind({}).catch(_ => false)
    if (res && !res.code) {
      ElMessage.success(T('OperationSuccess'))
      bound.value = false
      emit('refresh')
    }
  }

  watch(() => props.visible, v => { if (v) loadStatus() })
</script>

<style scoped>
.tfa-tip {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin: 0 0 12px;
}
.tfa-qr {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}
.tfa-secret {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  word-break: break-all;
  text-align: center;
}
</style>
