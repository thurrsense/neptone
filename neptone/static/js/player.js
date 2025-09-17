(() => {
    const $ = (s, el = document) => el.querySelector(s);
    const ap = $('#ap'), waveEl = $('#ap-wave');
    const titleEl = $('#ap-title'), artistEl = $('#ap-artist'), coverEl = $('#ap-cover');
    const playBtn = $('#ap-play'), pauseBtn = $('#ap-pause'), prevBtn = $('#ap-prev'), nextBtn = $('#ap-next');
    const timeEl = $('#ap-time'), vol = $('#ap-vol');

    let ws; // WaveSurfer
    let queue = [];    // [{src,title,artist,cover}]
    let idx = -1;
    let restoreOnce = false;

    const fmt = t => {
        t = Math.max(0, Math.floor(t || 0));
        const m = (t / 60 | 0), s = String(t % 60).padStart(2, '0');
        return `${m}:${s}`;
    };

    function ensureWS() {
        if (ws) return ws;
        ws = WaveSurfer.create({
            container: waveEl,
            height: 44,
            waveColor: '#888',
            progressColor: '#1db954',
            cursorColor: '#ccc',
            barWidth: 2,
            barGap: 1,
            responsive: true,
            normalize: true,
            partialRender: true,
        });
        ws.on('ready', () => {
            ap.hidden = false;
            updateButtons();
            updateTime();
        });
        ws.on('play', updateButtons);
        ws.on('pause', updateButtons);
        ws.on('audioprocess', updateTime);
        ws.on('seek', updateTime);
        ws.on('finish', () => next());
        return ws;
    }

    function loadTrack(i) {
        if (i < 0 || i >= queue.length) return;
        idx = i;
        const t = queue[idx];
        titleEl.textContent = t.title || '—';
        artistEl.textContent = t.artist || '';
        coverEl.src = t.cover || '';
        const w = ensureWS();
        w.load(t.src);
        saveState();
    }

    function play() { ensureWS().play(); }
    function pause() { ws && ws.pause(); }
    function prev() { if (queue.length) loadTrack((idx - 1 + queue.length) % queue.length); play(); }
    function next() { if (queue.length) loadTrack((idx + 1) % queue.length); play(); }

    function updateButtons() {
        const playing = ws && ws.isPlaying();
        playBtn.hidden = !!playing;
        pauseBtn.hidden = !playing;
    }
    function updateTime() {
        const dur = ws?.getDuration() || 0;
        const cur = ws?.getCurrentTime() || 0;
        timeEl.textContent = `${fmt(cur)} / ${fmt(dur)}`;
    }

    function buildQueue(fromEl) {
        // Собираем все элементы .js-track в текущем документе в порядке отображения
        const nodes = Array.from(document.querySelectorAll('.js-track'));
        queue = nodes.map(n => ({
            src: n.dataset.src,
            title: n.dataset.title || n.dataset.artist ? `${n.dataset.artist} — ${n.dataset.title}` : n.dataset.title,
            artist: n.dataset.artist || '',
            cover: n.dataset.cover || ''
        }));
        return nodes.indexOf(fromEl);
    }

    function saveState() {
        try {
            localStorage.setItem('ap_queue', JSON.stringify({ queue, idx }));
            localStorage.setItem('ap_volume', String(vol.value));
        } catch (_) { }
    }
    function restoreState() {
        try {
            const q = JSON.parse(localStorage.getItem('ap_queue') || 'null');
            const v = parseFloat(localStorage.getItem('ap_volume') || '1');
            if (q && Array.isArray(q.queue) && q.queue.length) {
                queue = q.queue; idx = Math.min(Math.max(q.idx, 0), q.queue.length - 1);
                vol.value = isFinite(v) ? v : 1;
                ensureWS().setVolume(vol.value);
                loadTrack(idx);
            }
        } catch (_) { }
    }

    // Handlers
    playBtn.addEventListener('click', play);
    pauseBtn.addEventListener('click', pause);
    prevBtn.addEventListener('click', prev);
    nextBtn.addEventListener('click', next);
    vol.addEventListener('input', () => { ensureWS().setVolume(parseFloat(vol.value || '1')); saveState(); });

    // Делегат по клику на карточку трека/кнопку
    document.addEventListener('click', (e) => {
        const el = e.target.closest('.js-track');
        if (!el) return;
        e.preventDefault();
        const startIdx = buildQueue(el);
        if (startIdx >= 0) {
            loadTrack(startIdx);
            play();
        }
    });

    // Media Session
    if ('mediaSession' in navigator) {
        navigator.mediaSession.setActionHandler('play', play);
        navigator.mediaSession.setActionHandler('pause', pause);
        navigator.mediaSession.setActionHandler('previoustrack', prev);
        navigator.mediaSession.setActionHandler('nexttrack', next);
    }

    // Turbo — одно восстановление после первой загрузки
    document.addEventListener('turbo:load', () => {
        if (!restoreOnce) { restoreState(); restoreOnce = true; }
    });
})();
