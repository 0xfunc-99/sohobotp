// SohobOTP portal - small progressive enhancements. Every page works without JavaScript.
// Loaded in <head> without "defer" so the saved colour theme applies before the first paint;
// everything that touches the page waits for DOMContentLoaded.
'use strict';

(() => {
  const THEME_KEY = 'sohobotp-theme';
  const MODES = ['system', 'light', 'dark'];
  const LABELS = { system: 'Colour theme: same as the system', light: 'Colour theme: light', dark: 'Colour theme: dark' };

  const savedTheme = () => {
    try {
      const value = window.localStorage.getItem(THEME_KEY);
      return MODES.includes(value) ? value : 'system';
    } catch (error) {
      return 'system';
    }
  };
  const applyTheme = (mode) => {
    if (mode === 'system') {
      delete document.documentElement.dataset.theme;
    } else {
      document.documentElement.dataset.theme = mode;
    }
  };
  applyTheme(savedTheme());

  document.addEventListener('DOMContentLoaded', () => {
    // Colour theme switch (system → light → dark)
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
      const show = (mode) => {
        button.dataset.mode = mode;
        button.setAttribute('aria-label', LABELS[mode]);
        button.title = LABELS[mode];
      };
      show(savedTheme());
      button.hidden = false;
      button.addEventListener('click', () => {
        const next = MODES[(MODES.indexOf(button.dataset.mode) + 1) % MODES.length];
        try {
          if (next === 'system') {
            window.localStorage.removeItem(THEME_KEY);
          } else {
            window.localStorage.setItem(THEME_KEY, next);
          }
        } catch (error) {
          // storage blocked: the choice lasts for this page only
        }
        applyTheme(next);
        show(next);
      });
    });

    // Close the mobile navigation with Escape
    const navToggle = document.getElementById('nav-toggle');
    if (navToggle) {
      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && navToggle.checked) {
          navToggle.checked = false;
        }
      });
    }

    // Ask before submitting forms marked with data-confirm (also on a submit button)
    document.querySelectorAll('form[data-confirm]').forEach((form) => {
      form.addEventListener('submit', (event) => {
        if (!window.confirm(form.dataset.confirm)) {
          event.preventDefault();
        }
      });
    });
    document.querySelectorAll('button[data-confirm]').forEach((button) => {
      button.addEventListener('click', (event) => {
        if (!window.confirm(button.dataset.confirm)) {
          event.preventDefault();
        }
      });
    });

    // "Copy" button next to secrets shown once and next to install commands
    const copyText = async (text) => {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.className = 'sr-only';
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand('copy');
      area.remove();
      return ok;
    };
    const addCopy = (source, after, label) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'copy-button';
      button.textContent = 'Copy';
      button.setAttribute('aria-label', label);
      button.addEventListener('click', async () => {
        let ok = false;
        try {
          ok = await copyText(source.textContent.trim());
        } catch (error) {
          ok = false;
        }
        button.textContent = ok ? 'Copied' : 'Select and copy by hand';
        if (ok) {
          button.dataset.copied = '';
        }
        window.setTimeout(() => {
          button.textContent = 'Copy';
          delete button.dataset.copied;
        }, 2000);
      });
      const bar = document.createElement('div');
      bar.className = 'secret-actions';
      bar.appendChild(button);
      after.insertAdjacentElement('afterend', bar);
    };
    document.querySelectorAll('.secret > code').forEach((code) => addCopy(code, code.parentElement, 'Copy to the clipboard'));
    document.querySelectorAll('pre > code').forEach((code) => addCopy(code, code.parentElement, 'Copy the command'));

    // "Select all" checkbox: <input type="checkbox" data-check-all="table-id">
    document.querySelectorAll('input[data-check-all]').forEach((master) => {
      const table = document.getElementById(master.dataset.checkAll);
      master.addEventListener('change', () => {
        table.querySelectorAll('tbody input[type="checkbox"]').forEach((box) => {
          if (!box.closest('tr').hidden) {
            box.checked = master.checked;
          }
        });
      });
    });

    // Live progress of a background job: <section data-job-poll="index.php?r=job-status&id=...">
    document.querySelectorAll('[data-job-poll]').forEach((panel) => {
      const set = (selector, text) => {
        const el = panel.querySelector(selector);
        if (el && text !== undefined) {
          el.textContent = text || '—';
        }
      };
      const poll = async () => {
        try {
          const response = await fetch(panel.dataset.jobPoll, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
          if (!response.ok) {
            return;
          }
          const job = await response.json();
          set('[data-job-status]', job.status);
          set('[data-job-progress]', job.progress);
          set('[data-job-engine]', job.engine);
          if (job.status !== 'queued' && job.status !== 'running') {
            window.location.reload();
            return;
          }
        } catch (error) {
          // network hiccup: try again on the next tick
        }
        window.setTimeout(poll, 2000);
      };
      window.setTimeout(poll, 2000);
    });

    // Instant filtering of table rows: <input data-filter-table="table-id">
    document.querySelectorAll('input[data-filter-table]').forEach((input) => {
      const table = document.getElementById(input.dataset.filterTable);
      if (!table) {
        return;
      }
      const tbody = table.querySelector('tbody');
      const columns = table.querySelectorAll('thead th').length || 1;
      const none = document.createElement('tr');
      none.hidden = true;
      none.innerHTML = '<td class="empty"></td>';
      none.firstChild.colSpan = columns;
      none.firstChild.textContent = 'Nothing matches this search.';
      tbody.appendChild(none);
      input.addEventListener('input', () => {
        const needle = input.value.trim().toLowerCase();
        let shown = 0;
        tbody.querySelectorAll('tr').forEach((row) => {
          if (row === none) {
            return;
          }
          const hide = needle !== '' && !row.textContent.toLowerCase().includes(needle);
          row.hidden = hide;
          shown += hide ? 0 : 1;
        });
        none.hidden = needle === '' || shown > 0;
      });
    });
  });
})();
