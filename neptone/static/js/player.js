
(() => {
  const $ = (s, el=document) => el.querySelector(s);

  const ap = $('#ap'), waveEl = $('#ap-wave');
  const titleEl = $('#ap-title'), artistEl = $('#ap-artist'), coverEl = $('#ap-cover');
  const playBtn = $('#ap-play'), pauseBtn = $('#ap-pause'), prevBtn = $('#ap-prev'), nextBtn = $('#ap-next');
  const timeEl = $('#ap-time'), vol = $('#ap-vol');
  const rate = $('#ap-rate'), r05 = $('#ap-rate-05'), r10 = $('#ap-rate-10'), r20 = $('#ap-rate-20');
  const reverb = $('#ap-reverb');
  const audioEl = $('#ap-el');

  let ws, ctx, srcNode, convolver, wetGain, dryGain;
  let queue = []; let idx = -1; let restored = false;

  const fmt = t => { t = Math.max(0, Math.floor(t||0)); const m=(t/60|0), s=String(t%60).padStart(2,'0'); return `${m}:${s}`; };
  const updateButtons = () => { const p = !audioEl.paused; playBtn.hidden = p; pauseBtn.hidden = !p; };
  const updateTime = () => { timeEl.textContent = `${fmt(audioEl.currentTime)} / ${fmt(audioEl.duration||0)}`; };

  function createReverbIR(ctx, seconds=2.5, decay=2.0){
    const rate = ctx.sampleRate, length = rate * seconds;
    const impulse = ctx.createBuffer(2, length, rate);
    for (let ch=0; ch<2; ch++){
      const data = impulse.getChannelData(ch);
      for (let i=0; i<length; i++){
        data[i] = (Math.random()*2-1) * Math.pow(1 - i/length, decay);
      }
    }
    return impulse;
  }

  function ensureGraph(){
    if (ctx) return;
    ctx = new (window.AudioContext || window.webkitAudioContext)();
    srcNode = ctx.createMediaElementSource(audioEl);

    convolver = ctx.createConvolver();
    convolver.buffer = createReverbIR(ctx);

    wetGain = ctx.createGain();  wetGain.gain.value = parseFloat(reverb.value || '0');
    dryGain = ctx.createGain();  dryGain.gain.value = 1;

    srcNode.connect(dryGain);     dryGain.connect(ctx.destination);
    srcNode.connect(convolver);   convolver.connect(wetGain); wetGain.connect(ctx.destination);
  }

  function ensureWS(){
    if (ws) return ws;
    ws = WaveSurfer.create({
      container: waveEl,
      media: audioEl,
      height: 44,
      waveColor: '#888',
      progressColor: '#1db954',
      cursorColor: '#ccc',
      barWidth: 2, barGap: 1,
      responsive: true, normalize: true, partialRender: true,
    });
    ws.on('decode', () => { ap.hidden = false; });
    ws.on('timeupdate', updateTime);
    ws.on('finish', () => next());
    return ws;
  }

  function buildQueue(startEl){
    const nodes = Array.from(document.querySelectorAll('.js-track'));
    queue = nodes.map(n => ({
      src:   n.dataset.src,
      title: n.dataset.title || '',
      artist:n.dataset.artist || '',
      cover: n.dataset.cover || ''
    }));
    return nodes.indexOf(startEl);
  }

  function loadTrack(i){
    if (i<0 || i>=queue.length) return;
    idx = i; const t = queue[idx];
    titleEl.textContent = t.title || '—';
    artistEl.textContent = t.artist || '';
    coverEl.src = t.cover || '';
    ensureWS();
    audioEl.src = t.src;
    saveState();
  }

  function play(){ ensureGraph(); ctx.state === 'suspended' && ctx.resume(); audioEl.play().catch(()=>{}); updateButtons(); }
  function pause(){ audioEl.pause(); updateButtons(); }
  function prev(){ if (!queue.length) return; loadTrack((idx-1+queue.length)%queue.length); play(); }
  function next(){ if (!queue.length) return; loadTrack((idx+1)%queue.length); play(); }

  playBtn.addEventListener('click', play);
  pauseBtn.addEventListener('click', pause);
  prevBtn.addEventListener('click', prev);
  nextBtn.addEventListener('click', next);
  vol.addEventListener('input', () => { audioEl.volume = parseFloat(vol.value||'1'); saveState(); });

  function setRate(v){ v = Math.min(2, Math.max(0.5, parseFloat(v)||1)); audioEl.playbackRate = v; rate.value = v; saveState(); }
  rate.addEventListener('input', () => setRate(rate.value));
  r05?.addEventListener('click', (e)=>{e.preventDefault(); setRate(0.5);});
  r10?.addEventListener('click', (e)=>{e.preventDefault(); setRate(1);});
  r20?.addEventListener('click', (e)=>{e.preventDefault(); setRate(2);});

  reverb.addEventListener('input', () => { ensureGraph(); wetGain.gain.value = parseFloat(reverb.value||'0'); saveState(); });

  document.addEventListener('click', (e)=>{
    const el = e.target.closest('.js-track');
    if (!el) return;
    e.preventDefault();
    const startIdx = buildQueue(el);
    if (startIdx >= 0){ loadTrack(startIdx); play(); }
  });

  audioEl.addEventListener('play', updateButtons);
  audioEl.addEventListener('pause', updateButtons);
  audioEl.addEventListener('timeupdate', updateTime);
  audioEl.addEventListener('loadedmetadata', updateTime);

  function saveState(){
    try {
      localStorage.setItem('ap_state', JSON.stringify({
        queue, idx, vol: audioEl.volume, rate: audioEl.playbackRate,
        reverb: parseFloat(reverb.value||'0'), src: audioEl.src, t: audioEl.currentTime||0
      }));
    }catch(_){}
  }
  function restoreState(){
    try{
      const s = JSON.parse(localStorage.getItem('ap_state')||'null');
      if (!s) return;
      queue = Array.isArray(s.queue) ? s.queue : [];
      idx = typeof s.idx==='number' ? s.idx : -1;
      if (s.vol!=null){ vol.value = s.vol; audioEl.volume = s.vol; }
      if (s.rate!=null){ setRate(s.rate); }
      if (s.reverb!=null){ reverb.value = s.reverb; }
      if (queue.length && idx>=0){
        ensureWS(); ensureGraph();
        loadTrack(idx);
        audioEl.currentTime = s.t||0;
        wetGain.gain.value = parseFloat(reverb.value||'0');
      }
    }catch(_){}
  }
  document.addEventListener('turbo:load', () => { if (!restored){ restoreState(); restored = true; } });
})();
