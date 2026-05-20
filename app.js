/* ============================================================
   PERFIL360 — app.js v4  (más dinamismo)
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {
  initProgress();
  initNav();
  initMobileMenu();
  initReveal();
  initCounters();
  initServices();
  initFAQ();
  initParallax();
  initMagnetic();
  initActiveNav();
  initSmoothScroll();
  initStaggered();
  pulseCtaBtn();
});

/* ── Barra de progreso de scroll ────────────────────────────── */
function initProgress() {
  const bar = document.getElementById('progress');
  if (!bar) return;
  window.addEventListener('scroll', () => {
    const total = document.documentElement.scrollHeight - window.innerHeight;
    bar.style.width = (scrollY / total * 100) + '%';
  }, { passive: true });
}


/* ── Navbar ─────────────────────────────────────────────────── */
function initNav() {
  const nav = document.getElementById('nav');
  if (!nav) return;
  window.addEventListener('scroll', () => {
    nav.classList.toggle('scrolled', scrollY > 50);
  }, { passive: true });
}

/* ── Mobile menu ────────────────────────────────────────────── */
function initMobileMenu() {
  const burger = document.getElementById('burger');
  const menu   = document.getElementById('mobMenu');
  const close  = document.getElementById('mobClose');
  if (!burger || !menu) return;
  burger.addEventListener('click', () => menu.removeAttribute('hidden'));
  close?.addEventListener('click', () => menu.setAttribute('hidden', ''));
  menu.querySelectorAll('a').forEach(a => a.addEventListener('click', () => menu.setAttribute('hidden', '')));
}

/* ── Reveal on scroll ───────────────────────────────────────── */
function initReveal() {
  // Hero .up: animan al cargar
  setTimeout(() => document.querySelectorAll('.up').forEach(el => el.classList.add('vis')), 80);

  // Resto: IntersectionObserver
  const all = document.querySelectorAll('.reveal, .reveal-left, .reveal-right, .reveal-scale');
  if (!all.length) return;

  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) { e.target.classList.add('visible'); io.unobserve(e.target); }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -28px 0px' });

  all.forEach(el => io.observe(el));
}

/* ── Staggered children ─────────────────────────────────────── */
function initStaggered() {
  // Process rows
  document.querySelectorAll('.prow').forEach((el, i) => {
    el.style.transitionDelay = (i * 0.07) + 's';
  });

  // Compliance cards
  document.querySelectorAll('.comp-card').forEach((el, i) => {
    el.style.transitionDelay = (i * 0.1) + 's';
  });

  // Testi mini
  document.querySelectorAll('.testi-mini').forEach((el, i) => {
    el.style.transitionDelay = (i * 0.12) + 's';
  });

  // FAQ items — animarlos con stagger al abrir sección
  const faqRight = document.querySelector('.faq-right');
  if (faqRight) {
    const io = new IntersectionObserver(entries => {
      if (entries[0].isIntersecting) {
        document.querySelectorAll('.fi').forEach((fi, i) => {
          fi.style.opacity = '0';
          fi.style.transform = 'translateY(16px)';
          fi.style.transition = `opacity .5s ${i * .08}s ease, transform .5s ${i * .08}s ease`;
          setTimeout(() => { fi.style.opacity = '1'; fi.style.transform = 'none'; }, 60);
        });
        io.disconnect();
      }
    }, { threshold: 0.2 });
    io.observe(faqRight);
  }
}

/* ── Animated counters ──────────────────────────────────────── */
function initCounters() {
  const els = document.querySelectorAll('.counter');
  if (!els.length) return;

  const easeOut = t => 1 - Math.pow(1 - t, 3);

  const run = el => {
    const target = +el.dataset.target;
    if (isNaN(target)) return;
    const dur = 1800, start = performance.now();
    const tick = now => {
      const p = Math.min((now - start) / dur, 1);
      el.textContent = Math.round(easeOut(p) * target);
      p < 1 ? requestAnimationFrame(tick) : (el.textContent = target);
    };
    requestAnimationFrame(tick);
  };

  const io = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) { run(e.target); io.unobserve(e.target); } });
  }, { threshold: 0.5 });
  els.forEach(el => io.observe(el));
}

/* ── Services panel switcher ────────────────────────────────── */
function initServices() {
  const items  = document.querySelectorAll('.sv-item');
  const panels = document.querySelectorAll('.sv-panel');
  if (!items.length) return;

  const activate = idx => {
    items.forEach(i => i.classList.remove('active'));
    panels.forEach(p => p.classList.remove('active'));
    items[idx]?.classList.add('active');
    panels[idx]?.classList.add('active');
  };

  items.forEach((item, i) => {
    item.addEventListener('mouseenter', () => activate(i));
    item.addEventListener('click', () => activate(i));
  });
}

/* ── FAQ accordion ──────────────────────────────────────────── */
function initFAQ() {
  document.querySelectorAll('.fi').forEach(item => {
    const trigger = item.querySelector('.ft');
    const answer  = item.querySelector('.fa');
    if (!trigger || !answer) return;

    trigger.addEventListener('click', () => {
      const isOpen = trigger.classList.contains('open');
      // Cerrar todos con transición
      document.querySelectorAll('.ft.open').forEach(t => {
        t.classList.remove('open');
        t.closest('.fi')?.querySelector('.fa')?.classList.remove('open');
      });
      if (!isOpen) { trigger.classList.add('open'); answer.classList.add('open'); }
    });
  });
}

/* ── Parallax hero text ─────────────────────────────────────── */
function initParallax() {
  const h1    = document.querySelector('.hero-h1');
  const stats = document.querySelector('.hero-stats');
  const orb1  = document.querySelector('.orb-1');
  const orb2  = document.querySelector('.orb-2');

  if (!h1) return;

  window.addEventListener('scroll', () => {
    const y = scrollY;
    if (y < window.innerHeight) {
      h1.style.transform    = `translateY(${y * 0.18}px)`;
      if (stats) stats.style.transform = `translateY(${y * 0.06}px)`;
      if (orb1) orb1.style.transform = `translateY(${y * -0.1}px)`;
      if (orb2) orb2.style.transform = `translateY(${y * 0.08}px)`;
    }
  }, { passive: true });
}

/* ── Magnetic buttons ───────────────────────────────────────── */
function initMagnetic() {
  if (window.matchMedia('(pointer: coarse)').matches) return;

  document.querySelectorAll('.btn-fill, .nav-pill, .cta-btn-a').forEach(btn => {
    btn.addEventListener('mousemove', e => {
      const r = btn.getBoundingClientRect();
      const x = e.clientX - r.left - r.width / 2;
      const y = e.clientY - r.top  - r.height / 2;
      btn.style.transform = `translate(${x * .25}px, ${y * .35}px)`;
    });
    btn.addEventListener('mouseleave', () => {
      btn.style.transform = '';
    });
  });
}

/* ── Active nav tracking ────────────────────────────────────── */
function initActiveNav() {
  const sections = document.querySelectorAll('section[id], div[id="contacto"]');
  const links    = document.querySelectorAll('.nav-links a');
  if (!links.length) return;

  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        links.forEach(l => l.classList.remove('nav-active'));
        const active = document.querySelector(`.nav-links a[href="#${e.target.id}"]`);
        active?.classList.add('nav-active');
      }
    });
  }, { threshold: 0.4 });

  sections.forEach(s => io.observe(s));
}

/* ── Pulse en el botón CTA ──────────────────────────────────── */
function pulseCtaBtn() {
  const btn = document.querySelector('.cta-btn-a');
  if (btn) {
    const io = new IntersectionObserver(entries => {
      if (entries[0].isIntersecting) btn.classList.add('pulse');
      else btn.classList.remove('pulse');
    }, { threshold: 0.5 });
    io.observe(btn);
  }
}

/* ── Smooth scroll ──────────────────────────────────────────── */
function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener('click', e => {
      const target = document.querySelector(link.getAttribute('href'));
      if (!target) return;
      e.preventDefault();
      window.scrollTo({ top: target.getBoundingClientRect().top + scrollY - 68, behavior: 'smooth' });
    });
  });
}
