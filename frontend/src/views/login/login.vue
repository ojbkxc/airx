<template>
  <div class="login-page">
    <!-- 右上工具组：语言切换 + 主题切换（对齐 AIGX） -->
    <div class="login-tools">
      <button class="tool-btn" @click="toggleLanguage" :title="T('ChangeLanguage')">
        {{ appStore.setting.lang === 'zh-CN' ? 'EN' : '中' }}
      </button>
      <button class="tool-btn" @click="toggleTheme" :title="T('ToggleTheme')">
        <el-icon :size="18">
          <Moon v-if="!isDark"/>
          <Sunny v-else/>
        </el-icon>
      </button>
    </div>

    <div class="login-card">
      <div class="login-head">
        <img src="@/assets/logo.png" alt="logo" class="login-logo"/>
        <h1>AIRX Admin</h1>
        <p class="login-sub">{{ T('Login') }} · {{ appStore.setting.title }}</p>
      </div>

      <el-form v-if="!disablePwd" label-position="top" class="login-form">
        <el-form-item :label="T('Username')">
          <el-input v-model="form.username" type="text" class="login-input" :placeholder="T('Username')"></el-input>
        </el-form-item>

        <el-form-item :label="T('Password')">
          <el-input v-model="form.password" type="password" @keyup.enter.native="login" show-password
                    class="login-input" :placeholder="T('Password')"></el-input>
        </el-form-item>

        <el-form-item :label="T('Captcha')" v-if="captchaCode">
          <el-input v-model="form.captcha" @keyup.enter.native="login" class="login-input captcha-input"
                    :placeholder="T('Captcha')">
            <template #append>
              <img :src="captchaCode.b64" @click="loadCaptcha" class="captcha" alt="captcha"/>
            </template>
          </el-input>
        </el-form-item>

        <el-form-item :label="T('TfaCode')" v-if="tfaRequired">
          <el-input v-model="form.tfa_code" type="password" @keyup.enter.native="login" class="login-input"
                    :placeholder="T('TfaInputCode')" maxlength="6"></el-input>
        </el-form-item>

        <el-button @click="login" type="primary" class="login-button" :loading="loading">{{ T('Login') }}</el-button>
        <el-button v-if="allowRegister" @click="register" class="login-button">{{ T('Register') }}</el-button>
      </el-form>

      <div class="divider" v-if="options.length > 0 && !disablePwd">
        <span>{{ T('or login in with') }}</span>
      </div>

      <div class="oidc-options">
        <div v-for="(option, index) in options" :key="index" class="oidc-option">
          <el-button @click="handleOIDCLogin(option.name)" class="oidc-btn">
            <img :src="getProviderImage(option.name)" alt="provider" class="oidc-icon"/>
            <span>{{ T(option.name) }}</span>
          </el-button>
        </div>
      </div>

      <div class="login-foot" v-if="!disablePwd">
        <a href="javascript:;" class="forgot-link">{{ T('ForgotPassword') }}</a>
      </div>
    </div>
  </div>
</template>

<script setup>
  import { reactive, onMounted, ref, computed } from 'vue'
  import { useUserStore } from '@/store/user'
  import { useAppStore } from '@/store/app'
  import { ElMessage } from 'element-plus'
  import { useDark } from '@vueuse/core'
  import { Moon, Sunny } from '@element-plus/icons'
  import { T } from '@/utils/i18n'
  import { useRoute, useRouter } from 'vue-router'
  import { loginOptions, captcha } from '@/api/login'
  import { getCode, removeCode } from '@/utils/auth'

  const oauthInfo = ref({})
  const userStore = useUserStore()
  const appStore = useAppStore()
  const route = useRoute()
  const router = useRouter()
  const options = reactive([]) // 存储 OIDC 登录选项
  const loading = ref(false)
  const isDark = useDark()

  let platform = window.navigator.platform
  if (navigator.platform.indexOf('Mac') === 0) {
    platform = 'mac'
  } else if (navigator.platform.indexOf('Win') === 0) {
    platform = 'windows'
  } else if (navigator.platform.indexOf('Linux armv') === 0) {
    platform = 'android'
  } else if (navigator.platform.indexOf('Linux') === 0) {
    platform = 'linux'
  }
  const userAgent = navigator.userAgent
  let browser = 'Unknown Browser'
  if (/chrome|crios/i.test(userAgent)) browser = 'Chrome'
  else if (/firefox|fxios/i.test(userAgent)) browser = 'Firefox'
  else if (/safari/i.test(userAgent) && !/chrome/i.test(userAgent)) browser = 'Safari'
  else if (/edg/i.test(userAgent)) browser = 'Edge'

  const form = reactive({
    username: '',
    password: '',
    platform: platform,
    captcha: '',
    captcha_id: '',
    tfa_code: ''
  })

  const captchaCode = ref('')
  const tfaRequired = ref(false)
  const redirect = route.query?.redirect

  const toggleLanguage = () => {
    const next = appStore.setting.lang === 'zh-CN' ? 'en' : 'zh-CN'
    appStore.changeLang(next)
  }
  const toggleTheme = () => {
    isDark.value = !isDark.value
  }

  const login = async () => {
    if (!form.username || !form.password) {
      ElMessage.warning(T('ParamRequired'))
      return
    }
    loading.value = true
    const res = await userStore.login(form).catch(e => e)
    loading.value = false
    if (!res.code) {
      ElMessage.success(T('LoginSuccess'))
      router.push({ path: redirect || '/', replace: true })
      return
    }
    if (res.code === 102) {
      // TFA：密码已对，提示输入两步验证动态码
      tfaRequired.value = true
      ElMessage.info(T('TfaRequired'))
      return
    }
    if (res.code === 110) {
      // need captcha
      loadCaptcha()
    }
  }

  const loadCaptcha = async () => {
    const captchaRes = await captcha().catch(_ => false)
    captchaCode.value = captchaRes.data.captcha
    form.captcha_id = captchaRes.data.captcha.id
  }

  const handleOIDCLogin = (provider) => {
    userStore.oidc(provider, platform, browser)
  }

  import googleImage from '@/assets/google.png'
  import githubImage from '@/assets/github.png'
  import oidcImage from '@/assets/oidc.png'
  import webauthImage from '@/assets/webauth.png'
  import defaultImage from '@/assets/oidc.png'

  const providerImageMap = {
    google: googleImage,
    github: githubImage,
    oidc: oidcImage,
    default: defaultImage,
  }

  const getProviderImage = (provider) => {
    return providerImageMap[provider.toLowerCase()] || providerImageMap.default
  }

  const allowRegister = ref(false)
  const disablePwd = ref(false)
  const loadLoginOptions = async () => {
    try {
      const res = await loginOptions().catch(_ => false)
      if (!res || !res.data) return console.error('No valid response received')
      res.data.ops.map(option => (options.push({ name: option })))
      if (res.data.auto_oidc) {
        handleOIDCLogin(res.data.ops[0])
      }
      disablePwd.value = res.data.disable_pwd
      allowRegister.value = res.data.register
      if (res.data.need_captcha) {
        loadCaptcha()
      }
    } catch (error) {
      console.error('Error loading login options:', error.message)
    }
  }

  onMounted(async () => {
    const code = getCode()
    if (code) {
      const res = await userStore.query(code)
      if (res) {
        removeCode()
        ElMessage.success(T('LoginSuccess'))
        router.push({ path: redirect || '/', replace: true })
      }
    } else {
      loadLoginOptions()
    }
  })

  const register = () => {
    router.push('/register')
  }
</script>

<style scoped lang="scss">
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px;
  box-sizing: border-box;
  position: relative;
  overflow: hidden;
}

.login-tools {
  position: fixed;
  top: 20px;
  right: 20px;
  display: flex;
  gap: 8px;
  z-index: 1000;
}

.tool-btn {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  background: rgba(39, 39, 44, 0.6);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255, 255, 255, 0.1);
  color: var(--el-text-color-primary);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  font-weight: 600;
  transition: border-color 0.2s ease, background 0.2s ease;
}
.tool-btn:hover {
  border-color: rgba(255, 255, 255, 0.25);
  background: rgba(255, 255, 255, 0.1);
}

.login-card {
  width: 100%;
  max-width: 380px;
  background: rgba(23, 23, 28, 0.72);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 14px;
  padding: 32px;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.45);
  animation: fadeIn 0.2s ease;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(6px); }
  to { opacity: 1; transform: translateY(0); }
}

.login-head {
  text-align: center;
  margin-bottom: 22px;
}

.login-logo {
  width: 48px;
  height: 48px;
  display: block;
  margin: 0 auto 14px;
}

.login-head h1 {
  font-size: 20px;
  font-weight: 700;
  letter-spacing: -0.4px;
  color: #fff;
  margin: 0 0 4px;
}

.login-sub {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin: 0;
}

.login-form {
  margin-bottom: 6px;
}

.login-input {
  width: 100%;
  :deep(.el-input__wrapper) {
    background: rgba(255, 255, 255, 0.05);
    box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.12) inset !important;
    border-radius: 8px;
    transition: box-shadow 0.2s ease, background 0.2s ease;
  }
  :deep(.el-input__wrapper.is-focus) {
    box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.5) inset !important;
    background: rgba(255, 255, 255, 0.07);
  }
  :deep(.el-input__inner) {
    color: var(--el-text-color-primary);
  }
  .captcha {
    cursor: pointer;
    width: 150px;
    height: 100%;
    object-fit: cover;
  }
}

.captcha-input {
  :deep(.el-input-group__append) {
    border-radius: 0 8px 8px 0;
    padding: 0;
    overflow: hidden;
    background: transparent;
    box-shadow: none;
  }
}

.login-button {
  width: 100%;
  height: 40px;
  margin-bottom: 12px;
  margin-left: 0;
  border-radius: 8px;
  font-weight: 600;
}

.divider {
  display: flex;
  align-items: center;
  margin: 18px 0;
  font-size: 12px;
  color: var(--el-text-color-secondary);

  &::before,
  &::after {
    content: '';
    flex: 1;
    height: 1px;
    background: rgba(255, 255, 255, 0.1);
  }

  &::before {
    margin-right: 12px;
  }

  &::after {
    margin-left: 12px;
  }
}

.oidc-options {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.oidc-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  width: 100%;
  height: 42px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 8px;
  color: var(--el-text-color-primary);
  font-size: 13px;
  transition: background 0.2s ease, border-color 0.2s ease;
}
.oidc-btn:hover {
  background: rgba(255, 255, 255, 0.1);
  border-color: rgba(255, 255, 255, 0.25);
}

.oidc-icon {
  width: 20px;
  height: 20px;
}

.login-foot {
  text-align: center;
  margin-top: 14px;
}

.forgot-link {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  text-decoration: none;
  transition: color 0.2s ease;
}
.forgot-link:hover {
  color: #fff;
}

.login-card :deep(.el-form-item__label) {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
</style>