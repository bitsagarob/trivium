// Trivium: 2-of-3 bitcoin multisig. Bitcoin Core does all bitcoin work; this file moves QR codes.
import { URDecoder, UREncoder, UR, Buffer, jsQR, qrcode } from './vendor.js'

const $ = s => document.querySelector(s)
const [sheet, qr, cam, amt, go, signed, note] = ['#sheet', '#qr', '#cam', '#amt', '#go', '#signed', '#note'].map($)
const KEY = /\[[0-9a-f]{8}(\/\d+h)+\][xt]pub\w+/g
let keys = decodeURIComponent(location.hash).match(KEY) ?? [], coins = [], next = [0, 0]

const desc = () => `wsh(sortedmulti(2,${keys.map(k => k + '/<0;1>/*')}))`
const sleep = ms => new Promise(r => setTimeout(r, ms))
const btc = sats => (sats / 1e8).toFixed(8)
const tap = el => new Promise(r => el.addEventListener('click', r, { once: true }))

const rpc = (method, ...params) => fetch(location.search.includes('signet') ? 'signet' : 'rpc', { method: 'POST', body: JSON.stringify({ id: 0, method, params }) })
  .then(r => r.json()).then(r => r.error ? Promise.reject(r.error) : r.result)
// Core silently scans only the first path of a <0;1> descriptor, so ask for each branch on its own.
const branch = async b => (await rpc('getdescriptorinfo', desc().replaceAll('<0;1>', b))).descriptor
const address = async b => (await rpc('deriveaddresses', await branch(b), [next[b], next[b]]))[0]

function view(...els) {
  for (const el of [qr, cam, amt, go, signed]) el.hidden = !els.includes(el)
  if (!sheet.open) sheet.showModal()
}
function draw(text) {
  const q = qrcode(0, 'L')
  q.addData(text); q.make(); qr.src = q.createDataURL(1, 4)
}
const show = text => (draw(text), view(qr), tap(qr))

// Feed each QR text the camera sees to `each` until it returns true. A tap on the video cancels.
async function scan(each) {
  view(cam)
  const stream = cam.srcObject = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment', width: { ideal: 640 } } })
  const c = document.createElement('canvas'), g = c.getContext('2d', { willReadFrequently: true })
  let cancel = false
  cam.onclick = () => cancel = true
  try {
    await cam.play()
    for (let done = false; !done;) {
      if (cancel) throw 'cancel'
      await new Promise(requestAnimationFrame)
      c.width = cam.videoWidth; c.height = cam.videoHeight; g.drawImage(cam, 0, 0)
      const hit = c.width && jsQR(g.getImageData(0, 0, c.width, c.height).data, c.width, c.height)
      if (hit?.data) done = await each(hit.data)
    }
  } finally { stream.getTracks().forEach(t => t.stop()) }
}
const part = (d, t) => { try { d.receivePart(t) } catch {} return d.isComplete() }
async function scanUR() {
  const d = new URDecoder()
  await scan(t => part(d, t))
  if (!d.isSuccess()) throw 'bad'
  return d.resultUR().decodeCBOR()
}

// A crypto-account or crypto-hdkey (CBOR map) becomes "[fingerprint/path]xpub".
async function urKey(v) {
  const h = v[2]?.find(o => o[6][1][6] === 2) ?? v[2]?.[0] ?? v, path = h[6][1]
  const be = n => [n >>> 24, n >>> 16 & 255, n >>> 8 & 255, n & 255]
  const raw = new Uint8Array([...(h[5]?.[2] ? [4, 53, 135, 207] : [4, 136, 178, 30]), path.length / 2, ...be(h[8] ?? 0),
    ...be(path.at(-2) + (path.at(-1) ? 2 ** 31 : 0)), ...h[4], ...h[3]])
  const sum = await crypto.subtle.digest('SHA-256', await crypto.subtle.digest('SHA-256', raw))
  let n = BigInt('0x' + Buffer.concat([raw, new Uint8Array(sum, 0, 4)]).toString('hex')), b58 = ''
  for (; n; n /= 58n) b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[n % 58n] + b58
  const fp = ((v[1] ?? h[6][2]) >>> 0).toString(16).padStart(8, '0')
  return `[${fp}${path.map((x, i) => i % 2 ? (x ? 'h' : '') : '/' + x).join('')}]${b58}`
}

async function addKey() {
  const d = new URDecoder()
  let found
  await scan(t => (found = t.match(KEY)) || part(d, t))
  found ??= [await urKey(d.resultUR().decodeCBOR())]
  for (const k of found) await rpc('getdescriptorinfo', `wpkh(${k}/0/*)`)   // Core refuses a bad key or a wrong network
  keys = [...new Set([...keys, ...found])].slice(0, 3)                       // a backup QR fills all three dots
  history.replaceState(0, '', location.search + '#' + desc())
  if (keys.length === 3) { await show(desc()); refresh().catch(fail) }
}

async function refresh() {
  $('#wait').hidden = false; $('#sats').hidden = true
  const descs = [await branch(0), await branch(1)]                                                // Core scans 1000 addresses each
  let s
  while (!s) s = await rpc('scantxoutset', 'start', descs).catch(e => { if (!/in progress/.test(e.message)) throw e; return sleep(5000) })
  coins = s.unspents
  const seen = JSON.parse(localStorage[keys] ?? '[-1,-1]')
  for (const c of coins) { const [, b, i] = c.desc.match(/\/(\d)\/(\d+)\]/); seen[b] = Math.max(seen[b], +i) }
  localStorage[keys] = JSON.stringify(seen); next = seen.map(i => i + 1)
  $('#sats').value = Math.round(s.total_amount * 1e8).toLocaleString()
  $('#wait').hidden = true; $('#sats').hidden = false
}

async function lightSigners(psbt) {
  const i = (await rpc('decodepsbt', psbt)).inputs[0]
  const fps = (i.bip32_derivs ?? []).filter(d => i.partial_signatures?.[d.pubkey]).map(d => d.master_fingerprint)
  signed.querySelectorAll('.dot').forEach((dot, n) => dot.classList.toggle('on', fps.some(f => keys[n].startsWith('[' + f))))
}

async function send() {
  let to
  await scan(t => (to = t.match(/^(?:bitcoin:)?([a-z0-9]+)(?:\?(.*))?$/i)))
  amt.value = Math.round(new URLSearchParams(to[2]).get('amount') * 1e8) || ''                    // BIP21 amount, if any
  view(amt, go); amt.focus(); await tap(go)
  const sats = +amt.value, rate = ((await rpc('estimatesmartfee', 2)).feerate ?? 1e-5) * 1e5   // sat/vB
  let pick = [], sum = 0, fee = 0
  for (const c of [...coins].sort((a, b) => b.amount - a.amount)) {                              // largest coins first
    if (sum >= sats + fee) break
    pick.push(c); sum += Math.round(c.amount * 1e8)
    fee = Math.ceil((10.5 + 104.5 * pick.length + 2 * 43) * rate)                               // vsize of a 2-of-3 spend
  }
  if (!sats || sum < sats + fee) throw '∅'
  const outs = [{ [to[1]]: btc(sats) }], change = sum - sats - fee
  if (change > 1000) outs.push({ [await address(1)]: btc(change) })
  let psbt = await rpc('createpsbt', pick.map(c => ({ txid: c.txid, vout: c.vout })), outs)
  psbt = (await rpc('descriptorprocesspsbt', psbt, [await branch(0), await branch(1)])).psbt
  for (let done = false; !done;) {
    await lightSigners(psbt)
    const ur = new UREncoder(new UR(UR.fromBuffer(Buffer.from(psbt, 'base64')).cbor, 'crypto-psbt'), 60)
    const step = () => draw(ur.nextPart().toUpperCase())
    step(); view(qr, signed)
    const tick = setInterval(step, 200)
    await tap(qr).finally(() => clearInterval(tick))
    psbt = await rpc('combinepsbt', [psbt, (await scanUR()).toString('base64')])
    const tx = await rpc('finalizepsbt', psbt)
    if (tx.complete) { await rpc('sendrawtransaction', tx.hex); done = true }
  }
  await lightSigners(psbt); view(signed); await sleep(1500)
  refresh().catch(fail)
}

function fail(e) {
  console.error(e)
  document.body.animate([{ translate: '4vmin' }, { translate: '-4vmin' }, { translate: '0' }], { duration: 150, iterations: 3 })
  note.textContent = e === '∅' ? '∅' : e instanceof TypeError ? '⚡' : '✕'
  setTimeout(() => note.textContent = '', 2000)
}
async function run(flow) {
  try { await flow() } catch (e) { if (e !== 'cancel') fail(e) } finally { sheet.close(); render() }
}
function render() {
  document.querySelectorAll('#setup .dot').forEach((b, i) => b.classList.toggle('on', i < keys.length))
  $('#setup').hidden = keys.length === 3; $('#home').hidden = keys.length < 3
}

document.querySelectorAll('#setup .dot').forEach(b => b.onclick = () => run(addKey))
$('#recv').onclick = () => run(async () => { await show(await address(0)); refresh().catch(fail) })
$('#send').onclick = () => run(send)
let press
$('#home').onpointerdown = e => { if (e.target.tagName !== 'BUTTON') press = setTimeout(() => run(() => show(desc())), 700) }
$('#home').onpointerup = $('#home').onpointerleave = () => clearTimeout(press)
render()
if (keys.length === 3) refresh().catch(fail)
