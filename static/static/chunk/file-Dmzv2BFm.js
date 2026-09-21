function c(e){let o="",n=Object.keys(e[0]);return o+=n.join(",")+`
`,e.forEach(t=>{o+=n.map(r=>`"${t[r].toString().replaceAll('"','""')}"`).join(",")+`
`}),new Blob([o],{type:"text/csv"})}function d(e,o){const n=window.URL.createObjectURL(e),t=document.createElement("a");t.href=n,t.download=o,document.body.appendChild(t),t.click(),setTimeout(()=>{window.URL.revokeObjectURL(n),document.body.removeChild(t)})}function l(e){return e<1024?e+"B":e<1024*1024?(e/1024).toFixed(2)+"KB":e<1024*1024*1024?(e/1024/1024).toFixed(2)+"MB":(e/1024/1024/1024).toFixed(2)+"GB"}export{d,c as j,l as s};
