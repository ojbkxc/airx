<template>
  <div v-if="slices.length" class="os-wrap">
    <svg viewBox="0 0 240 240" style="width:220px;height:220px;flex-shrink:0">
      <path v-for="(s,i) in slices" :key="i" :d="s.path" :fill="s.color"
            :stroke="cardStroke" stroke-width="2"
            :opacity="hover==null||hover===i?1:0.35" style="transition:opacity .2s ease;cursor:pointer"
            @mouseenter="hover=i" @mouseleave="hover=null"/>
      <text :x="120" :y="118" text-anchor="middle" :fill="textMain" font-size="16" font-weight="700">
        {{ hover!=null ? slices[hover].pct.toFixed(1)+'%' : total }}
      </text>
      <text :x="120" :y="136" text-anchor="middle" :fill="mutedColor" font-size="10">
        {{ hover!=null ? slices[hover].label : T('Devices') }}
      </text>
    </svg>
    <div class="os-legend">
      <div v-for="(s,i) in slices" :key="i" class="os-row" @mouseenter="hover=i" @mouseleave="hover=null">
        <span class="os-dot" :style="{background:s.color}"></span>
        <span class="os-name">{{ s.label }}</span>
        <span class="os-pct">{{ s.pct.toFixed(1) }}%</span>
      </div>
    </div>
  </div>
  <div v-else class="empty-state">{{ T('NoData') }}</div>
</template>

<script setup>
  import { ref, computed } from 'vue'
  import { T } from '@/utils/i18n'
  const props = defineProps({ data: { type: Array, default: () => [] } })
  const hover = ref(null)
  const colors = ['#7ca4f5', '#34d399', '#fbbf24', '#f87171', '#a78bfa', '#22d3ee']
  const names = { windows: 'Windows', linux: 'Linux', macos: 'macOS', other: T('Other') }
  const textMain = '#ffffff'
  const mutedColor = '#9a9aa5'
  const cardStroke = 'rgba(28,28,34,1)'

  const slices = computed(() => {
    const raw = props.data.filter(d => Number(d.count) > 0)
    const total = raw.reduce((s, d) => s + Number(d.count), 0)
    if (!total) return []
    const cx = 120, cy = 120, r = 90
    let cum = -Math.PI/2
    return raw.map((d, i) => {
      const ang = (Number(d.count)/total) * 2 * Math.PI
      const x1 = cx + r*Math.cos(cum), y1 = cy + r*Math.sin(cum)
      const x2 = cx + r*Math.cos(cum+ang), y2 = cy + r*Math.sin(cum+ang)
      const largeArc = ang > Math.PI ? 1 : 0
      const mid = cum + ang/2
      const path = `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2} Z`
      cum += ang
      return { path, color: colors[i % colors.length], label: names[d.os] || d.os, pct: (Number(d.count)/total)*100, val: Number(d.count) }
    })
  })

  const total = computed(() => props.data.reduce((s, d) => s + Number(d.count)||0, 0))
</script>

<style scoped lang="scss">
.os-wrap { display: flex; gap: 20px; flex-wrap: wrap; align-items: center; }
.os-legend { display: flex; flex-direction: column; gap: 8px; flex: 1; min-width: 150px; }
.os-row { display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: default; padding: 3px 6px; border-radius: 6px; }
.os-row:hover { background: rgba(255,255,255,0.05); }
.os-dot { width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0; }
.os-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.os-pct { color: var(--el-text-color-secondary); font-weight: 600; }
</style>