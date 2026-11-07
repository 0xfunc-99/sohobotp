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
