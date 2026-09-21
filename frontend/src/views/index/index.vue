<template>
  <div class="dashboard">
    <!-- 顶部标题栏 -->
    <div class="dash-header">
      <div>
        <h1>{{ T('Dashboard') }}</h1>
        <p class="dash-sub">{{ T('DashboardDesc') }}</p>
      </div>
      <el-button :icon="Refresh" @click="load" :loading="loading" circle/>
    </div>

    <!-- 骨架屏加载态 -->
    <div v-if="loading" class="stats-grid">
      <div v-for="n in 4" :key="n" class="stat-card skeleton"></div>
    </div>

    <!-- 数据卡 -->
    <div v-else class="stats-grid">
      <div class="stat-card">
        <div class="stat-card-top">
          <div class="stat-title">{{ T('OnlineDevices') }}</div>
          <div class="stat-icon-badge" style="background: rgba(52,211,153,0.15); color: #34d399">⚡</div>
        </div>
        <div class="stat-value">{{ stats.online_peers }}</div>
        <div class="stat-desc">
          <span class="dot" style="background: #34d399"></span>
          {{ T('Online24h') }}
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-card-top">
          <div class="stat-title">{{ T('TotalDevices') }}</div>
          <div class="stat-icon-badge" style="background: rgba(124,164,245,0.15); color: #7ca4f5">🖥</div>
        </div>
        <div class="stat-value">{{ stats.total_peers }}</div>
        <div class="stat-desc">
          <span style="color: #9a9aa5">{{ T('OfflineDevices') }} {{ stats.offline_peers }}</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-card-top">
          <div class="stat-title">{{ T('TodayConns') }}</div>
          <div class="stat-icon-badge" style="background: rgba(251,191,36,0.15); color: #fbbf24">📡</div>
        </div>
        <div class="stat-value">{{ stats.today_conns }}</div>
        <div class="stat-desc">
          {{ T('ActiveConns') }} <span style="color:#fbbf24;font-weight:600">{{ stats.active_conns }}</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-card-top">
          <div class="stat-title">{{ T('Users') }}</div>
          <div class="stat-icon-badge" style="background: rgba(167,139,250,0.15); color: #a78bfa">👥</div>
        </div>
        <div class="stat-value">{{ stats.total_users }}</div>
        <div class="stat-desc">{{ T('RegisteredUsers') }}</div>
      </div>
    </div>

    <!-- 趋势 + 系统分布 -->
    <div class="dash-cols">
      <div class="section-card">
        <div class="section-card-header">
          <h2>{{ T('ConnTrend7d') }}</h2>
        </div>
        <div class="section-card-body">
          <TrendChart v-if="stats.trend && stats.trend.length" :data="stats.trend"/>
          <div v-else class="empty-state">{{ T('NoData') }}</div>
        </div>
      </div>
      <div class="section-card">
        <div class="section-card-header">
          <h2>{{ T('OsDist') }}</h2>
        </div>
        <div class="section-card-body">
          <OsChart v-if="stats.os_dist && stats.os_dist.length" :data="stats.os_dist"/>
          <div v-else class="empty-state">{{ T('NoData') }}</div>
        </div>
      </div>
    </div>

    <!-- 最近设备 + 最近连接 -->
    <div class="dash-cols">
      <div class="section-card">
        <div class="section-card-header">
          <h2>{{ T('RecentDevices') }}</h2>
        </div>
        <div class="section-card-body pad-0">
          <el-table :data="stats.recent_peers" size="small" class="glass-table">
            <el-table-column prop="hostname" :label="T('Hostname')" min-width="120" show-overflow-tooltip>
              <template #default="{row}">
                <span style="font-weight:600">{{ row.hostname || row.id }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="os" :label="T('Os')" min-width="160" show-overflow-tooltip/>
            <el-table-column prop="version" :label="T('Version')" width="80"/>
            <el-table-column :label="T('LastOnlineTime')" width="120">
              <template #default="{row}">
                <span style="color:#9a9aa5">{{ fmtAgo(row.last_online_time) }}</span>
              </template>
            </el-table-column>
          </el-table>
          <div v-if="!stats.recent_peers || !stats.recent_peers.length" class="empty-state">{{ T('NoData') }}</div>
        </div>
      </div>
      <div class="section-card">
        <div class="section-card-header">
          <h2>{{ T('RecentConns') }}</h2>
        </div>
        <div class="section-card-body pad-0">
          <el-table :data="stats.recent_conns" size="small" class="glass-table">
            <el-table-column prop="peer_id" :label="T('Device')" min-width="110">
              <template #default="{row}">
                <span style="font-family:monospace">{{ row.peer_id }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="ip" label="IP" min-width="120"/>
            <el-table-column :label="T('Status')" width="90" align="center">
              <template #default="{row}">
                <el-tag v-if="row.action==='new' && row.close_time===0" type="success" size="small">{{ T('Connecting') }}</el-tag>
                <el-tag v-else-if="row.action==='new'" type="info" size="small">{{ T('Closed') }}</el-tag>
                <el-tag v-else size="info">{{ row.action }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="created_at" :label="T('Time')" width="100">
              <template #default="{row}">
                <span style="color:#9a9aa5">{{ (row.created_at||'').slice(11,19) }}</span>
              </template>
            </el-table-column>
          </el-table>
          <div v-if="!stats.recent_conns || !stats.recent_conns.length" class="empty-state">{{ T('NoData') }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
  import { ref, onMounted } from 'vue'
  import { Refresh } from '@element-plus/icons'
  import { dashboardStats } from '@/api/dashboard'
  import { T } from '@/utils/i18n'
  import TrendChart from './dashboard/trend.vue'
  import OsChart from './dashboard/os.vue'

  const loading = ref(false)
  const stats = ref({
    total_peers: 0, online_peers: 0, offline_peers: 0,
    today_conns: 0, active_conns: 0, total_users: 0,
    trend: [], os_dist: [], recent_peers: [], recent_conns: [],
  })

  const load = async () => {
    loading.value = true
    const res = await dashboardStats().catch(() => null)
    loading.value = false
    if (res && res.data) {
      stats.value = {
        total_peers: 0, online_peers: 0, offline_peers: 0,
        today_conns: 0, active_conns: 0, total_users: 0,
        trend: [], os_dist: [], recent_peers: [], recent_conns: [],
        ...res.data,
      }
    }
  }

  const fmtAgo = (ts) => {
    if (!ts) return '—'
    const now = Date.now() / 1000
    const diff = now - ts
    if (diff < 60) return Math.floor(diff) + 's'
    if (diff < 3600) return Math.floor(diff / 60) + 'm'
    if (diff < 86400) return Math.floor(diff / 3600) + 'h'
    return Math.floor(diff / 86400) + 'd'
  }

  onMounted(load)
</script>

<style scoped lang="scss">
.dashboard { min-height: 100%; }
.dash-header {
  display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;
  h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.5px; }
  .dash-sub { font-size: 13px; color: var(--el-text-color-secondary); margin-top: 4px; }
}
.stats-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 14px; margin-bottom: 16px;
}
.stat-card {
  background: rgba(28,28,34,0.62); backdrop-filter: blur(12px);
  border: 1px solid rgba(255,255,255,0.08); border-radius: 12px;
  padding: 16px 20px; display: flex; flex-direction: column; gap: 10px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.35); transition: border-color .2s ease, box-shadow .2s ease;
}
.stat-card:hover { border-color: rgba(255,255,255,0.16); box-shadow: 0 12px 32px rgba(0,0,0,0.5); }
.stat-card-top { display: flex; justify-content: space-between; align-items: center; }
.stat-title { font-size: 12px; color: var(--el-text-color-secondary); font-weight: 500; letter-spacing: 0.04em; text-transform: uppercase; }
.stat-value { font-size: 28px; font-weight: 700; letter-spacing: -0.02em; line-height: 1; color: #fff; }
.stat-desc { font-size: 12px; color: var(--el-text-color-secondary); line-height: 1.6; }
.stat-icon-badge { width: 32px; height: 32px; border-radius: 8px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; }

.dash-cols {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(min(420px,100%), 1fr));
  gap: 16px; margin-top: 16px;
}
.section-card {
  background: rgba(28,28,34,0.62); backdrop-filter: blur(12px);
  border: 1px solid rgba(255,255,255,0.08); border-radius: 12px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.35); overflow: hidden;
}
.section-card-header { padding: 14px 18px; border-bottom: 1px solid rgba(255,255,255,0.06); }
.section-card-header h2 { font-size: 15px; font-weight: 600; }
.section-card-body { padding: 16px 18px; }
.section-card-body.pad-0 { padding: 0; }
.empty-state { text-align: center; padding: 28px 16px; color: var(--el-text-color-secondary); font-size: 13px; }

.skeleton {
  height: 120px; position: relative; overflow: hidden; background: rgba(255,255,255,0.03);
}
.skeleton::after {
  content: ''; position: absolute; inset: 0; transform: translateX(-100%);
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.08), transparent);
  animation: shimmer 1.6s ease-in-out infinite;
}
@keyframes shimmer { 100% { transform: translateX(100%); } }

:deep(.glass-table) {
  --el-table-bg-color: transparent;
  --el-table-tr-bg-color: transparent;
  --el-table-header-bg-color: rgba(255,255,255,0.04);
  --el-table-row-hover-bg-color: rgba(255,255,255,0.06);
  --el-table-border-color: rgba(255,255,255,0.07);
  --el-table-text-color: #e5e5e5;
  --el-table-header-text-color: #9a9aa5;
  background: transparent;
}
:deep(.glass-table.el-table::before) { display: none; }
</style>