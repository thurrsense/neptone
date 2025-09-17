(() => {
    const $ = (sel, el = document) => el.querySelector(sel);
    const bar = $('.player-bar');
    const audio = $('#ap-audio');
    const playBtn = $('#ap-play');
    const pauseBtn = $('#ap-pause');
    const seek = $('#ap-seek');
    const cur = $('#ap-cur'), dur = $('#ap-dur');
    const titleEl = $('#ap-title');

    let state = { src: null, title: '', t: 0 };

    function fmt(t) { t = Math.floor(t || 0); const m = Math.floor(t / 60), s = (t % 60).toString().padStart(2, '0'); return `${m}:${s}` }

    function load({ src, title, startAt = 0 }) {
        if (!src) return;
        if (state.src !== src) { audio.src = src; }
        state = { src, title, t: startAt || 0 };
        titleEl.textContent = title || '—';
        bar.hidden = false;
        audio.currentTime = state.t;
        audio.play().catch(() => { }); // автоплей может блокироваться до первого клика
        save();
        updateButtons();
    }

    function save() { try { localStorage.setItem('ap_state', JSON.stringify({ src: state.src, title: state.title, t: audio.currentTime || 0 })) } catch (e) { } }
    function restore() {
        try {
            const s = JSON.parse(localStorage.getItem('ap_state') || 'null');
            if (s && s.src) { load({ src: s.src, title: s.title, startAt: s.t }); }
        } catch (e) { }
    }

    function updateButtons() {
        if (audio.paused) { playBtn.hidden = false; pauseBtn.hidden = true; }
        else { playBtn.hidden = true; pauseBtn.hidden = false; }
    }

    audio.addEventListener('loadedmetadata', () => { dur.textContent = fmt(audio.duration); });
    audio.addEventListener('timeupdate', () => {
        cur.textContent = fmt(audio.currentTime);
        if (audio.duration) seek.value = (audio.currentTime / audio.duration) * 100;
    });
    audio.addEventListener('pause', updateButtons);
    audio.addEventListener('play', updateButtons);
    audio.addEventListener('ended', () => { updateButtons(); });

    seek.addEventListener('input', () => {
        if (audio.duration) { audio.currentTime = (seek.value / 100) * audio.duration; save(); }
    });
    playBtn.addEventListener('click', () => audio.play());
    pauseBtn.addEventListener('click', () => audio.pause());

    // Глобальный делегат: клик по любому .js-play-track
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.js-play-track');
        if (!btn) return;
        e.preventDefault();
        const src = btn.dataset.src; // абсолютный или относительный URL файла
        const title = btn.dataset.title || btn.textContent.trim();
        load({ src, title });
    });

    // Media Session API (красиво на телефонах/десктопе)
    if ('mediaSession' in navigator) {
        navigator.mediaSession.setActionHandler('play', () => audio.play());
        navigator.mediaSession.setActionHandler('pause', () => audio.pause());
        navigator.mediaSession.metadata = new MediaMetadata({ title: 'Neptone' });
    }

    // Сохраняем состояние при навигации Turbo
    document.addEventListener('turbo:before-cache', save);
    document.addEventListener('turbo:load', () => updateButtons());

    restore();
})();
