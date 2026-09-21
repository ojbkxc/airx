<template>
  <svg v-if="points.length" :viewBox="`0 0 600 200`" style="width:100%;height:auto;display:block"
       @mousemove="onMove" @mouseleave="hover=null">
    <!-- 网格线 -->
    <g v-for="r in [0,0.25,0.5,0.75,1]" :key="r">
      <line :x1="pad.l" :y1="pad.t + chartH*(1-r)" :x2="600-pad.r" :y2="pad.t + chartH*(1-r)"
            stroke="rgba(255,255,255,0.08)" stroke-width="1"/>
      <text :x="pad.l-8" :y="pad.t + chartH*(1-r)+4" text-anchor="end" fill="#9a9aa5" font-size="10">
        {{ fmt(maxV*r) }}
      </text>
    </g>

    <!-- 面积渐变 -->
    <defs>
      <linearGradient id="airxTrendGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="rgba(255,255,255,0.25)"/>
        <stop offset="100%" stop-color="rgba(255,255,255,0)"/>
      </linearGradient>
    </defs>
    <polygon :points="areaPoints" fill="url(#airxTrendGrad)"/>
    <polyline :points="points.join(' ')" fill="none" stroke="#ffffff" stroke-width="2"
              stroke-linecap="round" stroke-linejoin="round"/>

    <!-- 数据点 -->
    <g v-for="(d,i) in data" :key="i">
      <circle :cx="x(i)" :cy="y(d)" :r="hover===i?5:3" fill="#ffffff" stroke="rgba(28,28,34,1)" stroke-width="2"
              style="transition:r .15s ease"/>
      <text :x="x(i)" :y="200-pad.b+16" text-anchor="middle" fill="#9a9aa5" font-size="9">
        {{ (d.date||'').slice(5) }}
      </text>
    </g>

    <!-- 悬停提示 -->
    <g v-if="hover!=null" pointer-events="none">
      <line :x1="x(hover)" :y1="pad.t" :x2="x(hover)" :y2="pad.t+chartH"
            stroke="#fff" stroke-width="1" stroke-dasharray="4 3" opacity="0.5"/>
      <rect :x="tipX" :y="tipY" width="110" height="36" rx="7" fill="rgba(28,28,34,0.92)" stroke="rgba(255,255,255,0.15)"/>
      <text :x="tipX+10" :y="tipY+17" fill="#eee" font-size="11" font-weight="600">{{ data[hover].date }}</text>
      <text :x="tipX+10" :y="tipY+30" fill="#9a9aa5" font-size="10">{{ data[hover].conns }} {{ T('Conns') }}</text>
    </g>
  </svg>
  <div v-else class="empty-state">{{ T('NoData') }}</div>
</template>

<script setup>
  import { ref, computed } from 'vue'
  import { T } from '@/utils/i18n'
  const props = defineProps({ data: { type: Array, default: () => [] } })
  const hover = ref(null)
  const pad = { t: 20, r: 20, b: 30, l: 45 }
  const chartW = 600 - pad.l - pad.r
  const chartH = 200 - pad.t - pad.b

  const maxV = computed(() => Math.max(...props.data.map(d => Number(d.conns)||0), 1))
  const x = (i) => pad.l + (i + 0.5) * (chartW / Math.max(props.data.length, 1))
  const y = (d) => pad.t + chartH - ((Number(d.conns)||0) / maxV.value) * chartH
  const points = computed(() => props.data.map((d, i) => `${x(i)},${y(d)}`))
  const areaPoints = computed(() => `${pad.l},${pad.t+chartH} ${points.value.join(' ')} ${600-pad.r},${pad.t+chartH}`)
  const fmt = (v) => v >= 1000 ? (v/1000).toFixed(1)+'K' : Math.round(v)

  const tipX = computed(() => {
    if (hover.value == null) return 0
    const hx = x(hover.value)
    return hx > 600-pad.r-118 ? hx-122 : hx+12
  })
  const tipY = computed(() => {
    if (hover.value == null) return 0
    return Math.max(pad.t, y(props.data[hover.value])-40)
  })

  const onMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const ratio = 600 / rect.width
    const mx = (e.clientX - rect.left) * ratio
    if (mx < pad.l || mx > 600-pad.r) { hover.value = null; return }
    const idx = Math.floor(((mx-pad.l)/chartW) * props.data.length)
    hover.value = Math.max(0, Math.min(props.data.length-1, idx))
  }
</script>