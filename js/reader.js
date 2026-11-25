(() => {
  'use strict';

  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const field = document.createElement('textarea');
    field.value = text;
    field.setAttribute('aria-label', '待复制的代码');
    field.style.cssText = 'position:fixed;left:-9999px;top:0';
    document.body.append(field);
    const focused = document.activeElement;
    field.select();
    const copied = document.execCommand('copy');
    field.remove();
    if (focused instanceof HTMLElement) focused.focus({ preventScroll: true });
    if (!copied) throw new Error('Copy unavailable');
  }

  function enhanceCode(block) {
    if (block.parentElement.classList.contains('code-frame')) return;
    const frame = document.createElement('div');
    frame.className = 'code-frame';
    const toolbar = document.createElement('div');
    toolbar.className = 'code-tools';
    const language = document.createElement('span');
    language.className = 'code-language';
    language.textContent = block.classList.contains('highlight') ?
      Array.from(block.classList).find(name => name !== 'highlight') || 'code' : 'code';
    const wrap = document.createElement('button');
    wrap.type = 'button';
    wrap.textContent = '换行';
    wrap.setAttribute('aria-pressed', 'false');
    wrap.addEventListener('click', () => {
      wrap.setAttribute('aria-pressed', String(frame.classList.toggle('code-wrap')));
    });
    const copy = document.createElement('button');
    copy.type = 'button';
    copy.textContent = '复制代码';
    copy.title = block.dataset.code ? '原样复制，保留原文缩进与控制字符' : '复制显示的代码';
    const feedback = document.createElement('span');
    feedback.className = 'copy-feedback';
    feedback.setAttribute('role', 'status');
    copy.addEventListener('click', async () => {
      const lines = block.querySelectorAll('td.code .line');
      const text = block.dataset.code ?
        new TextDecoder().decode(Uint8Array.from(atob(block.dataset.code), char => char.charCodeAt(0))) :
        lines.length ? Array.from(lines, line => line.textContent).join('\n') : block.textContent;
      try {
        await copyText(text);
        feedback.textContent = '已复制';
      } catch {
        feedback.textContent = '请选中代码复制';
      }
      setTimeout(() => { feedback.textContent = ''; }, 3000);
    });
    toolbar.append(language, feedback, wrap, copy);
    block.before(frame);
    frame.append(toolbar, block);
    block.tabIndex = 0;
    block.setAttribute('aria-label', '代码区域，可滚动查看');
  }

  function revealTarget() {
    let id;
    try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
    const target = document.getElementById(id);
    if (!target) return;
    const record = id.startsWith('case-') ?
      document.getElementById('record-' + id.slice(5)) : target.closest('details');
    if (record) {
      record.open = true;
      requestAnimationFrame(() => target.scrollIntoView({ block: 'start' }));
    }
  }

  function initialize() {
    const controls = document.querySelectorAll('[data-expand-evidence]');
    controls.forEach(control => {
      if (control.dataset.ready) return;
      control.dataset.ready = 'true';
      control.setAttribute('aria-expanded', 'false');
      control.addEventListener('click', () => {
        const records = document.querySelectorAll('.kb-evidence');
        const expanded = Array.from(records).some(record => !record.open);
        records.forEach(record => { record.open = expanded; });
        control.setAttribute('aria-expanded', String(expanded));
        control.textContent = expanded ? '收起全部技术记录' : '展开全部技术记录';
      });
    });
    const blocks = Array.from(document.querySelectorAll('.post-body figure.highlight, .post-body pre'))
      .filter(block => block.matches('figure') || !block.closest('figure.highlight'));
    if (typeof IntersectionObserver === 'function') {
      const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
          if (!entry.isIntersecting) return;
          observer.unobserve(entry.target);
          enhanceCode(entry.target);
        });
      }, { rootMargin: '400px' });
      blocks.forEach(block => observer.observe(block));
    } else {
      blocks.forEach(enhanceCode);
    }
    revealTarget();
    setTimeout(() => {
      const marked = document.querySelector('.kb-evidence mark');
      if (marked && !location.hash) {
        marked.closest('details').open = true;
        marked.scrollIntoView({ block: 'center' });
      }
    }, 0);
  }

  document.addEventListener('DOMContentLoaded', initialize);
  document.addEventListener('pjax:success', initialize);
  window.addEventListener('hashchange', revealTarget);
})();
