/* global CONFIG, pjax, LocalSearch */

document.addEventListener('DOMContentLoaded', () => {
  if (!CONFIG.path) {
    // Search DB path
    console.warn('`hexo-generator-searchdb` plugin is not installed!');
    return;
  }
  const localSearch = new LocalSearch({
    path             : CONFIG.path,
    top_n_per_article: CONFIG.localsearch.top_n_per_article,
    unescape         : CONFIG.localsearch.unescape
  });

  const input = document.querySelector('.search-input');

  const inputEventFunction = () => {
    if (!localSearch.isfetched) return;
    const searchText = input.value.trim().toLowerCase();
    const keywords = searchText.split(/[-\s]+/);
    const container = document.querySelector('.search-result-container');
    let resultItems = [];
    if (searchText.length > 0) {
      // Perform local searching
      resultItems = localSearch.getResultItems(keywords);
    }
    if (keywords.length === 1 && keywords[0] === '') {
      container.classList.add('no-result');
      container.innerHTML = '<div class="search-result-icon"><i class="fa fa-search fa-5x"></i></div>';
    } else if (resultItems.length === 0) {
      container.classList.add('no-result');
      container.innerHTML = '<div class="search-result-icon"><i class="far fa-frown fa-5x"></i></div>';
    } else {
      resultItems.sort((left, right) => {
        if (left.includedCount !== right.includedCount) {
          return right.includedCount - left.includedCount;
        } else if (left.hitCount !== right.hitCount) {
          return right.hitCount - left.hitCount;
        }
        return right.id - left.id;
      });
      const stats = CONFIG.i18n.hits.replace('${hits}', resultItems.length);

      container.classList.remove('no-result');
      container.innerHTML = `<div class="search-stats">${stats}</div>
        <hr>
        <ul class="search-result-list">${resultItems.map(result => result.item).join('')}</ul>`;
      if (typeof pjax === 'object') pjax.refresh(container);
    }
  };

  localSearch.highlightSearchWords(document.querySelector('.post-body'));
  if (CONFIG.localsearch.preload) {
    localSearch.fetchData();
  }

  if (CONFIG.localsearch.trigger === 'auto') {
    input.addEventListener('input', inputEventFunction);
  } else {
    document.querySelector('.search-icon').addEventListener('click', inputEventFunction);
    input.addEventListener('keypress', event => {
      if (event.key === 'Enter') {
        inputEventFunction();
      }
    });
  }
  window.addEventListener('search:loaded', inputEventFunction);

  const closeButton = document.querySelector('.popup-btn-close');
  closeButton.setAttribute('aria-label', 'Close search');
  for (const control of document.querySelectorAll('.popup-trigger, .popup-btn-close')) {
    if (control.matches('button, a[href]')) continue;
    control.tabIndex = 0;
    control.addEventListener('keydown', event => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      control.click();
    });
  }

  let opener;
  let focusTimer;
  document.querySelectorAll('.popup-trigger').forEach(element => {
    element.addEventListener('click', () => {
      opener = element;
      document.body.classList.add('search-active');
      clearTimeout(focusTimer);
      focusTimer = setTimeout(() => input.focus(), 400);
      if (!localSearch.isfetched) localSearch.fetchData();
    });
  });

  // Monitor main search box
  const onPopupClose = () => {
    if (!document.body.classList.contains('search-active')) return;
    clearTimeout(focusTimer);
    document.body.classList.remove('search-active');
    if (opener && opener.isConnected) opener.focus({ preventScroll: true });
    opener = null;
  };

  document.querySelector('.search-pop-overlay').addEventListener('click', event => {
    if (event.target === document.querySelector('.search-pop-overlay')) {
      onPopupClose();
    }
  });
  closeButton.addEventListener('click', onPopupClose);
  document.addEventListener('pjax:success', () => {
    localSearch.highlightSearchWords(document.querySelector('.post-body'));
    onPopupClose();
  });
  window.addEventListener('keyup', event => {
    if (event.key === 'Escape') {
      onPopupClose();
    }
  });
});
