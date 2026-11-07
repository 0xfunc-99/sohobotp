// multiOTP portal - small progressive enhancements. Every page works without JavaScript.
'use strict';

document.addEventListener('DOMContentLoaded', () => {
  // Ask before submitting forms marked with data-confirm
  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm)) {
        event.preventDefault();
      }
    });
  });

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
    input.addEventListener('input', () => {
      const needle = input.value.trim().toLowerCase();
      table.querySelectorAll('tbody tr').forEach((row) => {
        row.hidden = needle !== '' && !row.textContent.toLowerCase().includes(needle);
      });
    });
  });
});
