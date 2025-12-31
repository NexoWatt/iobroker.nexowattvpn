/* global $, M, sendTo, socket, adapter, instance, _ */

'use strict';

let currentProtocol = null;

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function toast(msg) {
  try {
    M.toast({ html: escapeHtml(msg) });
  } catch (e) {
    // ignore
  }
}

function parsePortsCsv(csv) {
  const set = new Set();
  String(csv || '').split(',').forEach(p => {
    const n = parseInt(String(p).trim(), 10);
    if (!isNaN(n) && n > 0 && n <= 65535) set.add(n);
  });
  return Array.from(set).sort((a, b) => a - b);
}

function formatCreated(ts) {
  if (!ts) return '';
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch (e) {
    return String(ts);
  }
}

function renderStatusBadge(client) {
  if (client.disabled) {
    return '<span class="nexo-badge nexo-badge-warn translate">disabled</span>';
  }
  return '<span class="nexo-badge nexo-badge-ok translate">enabled</span>';
}

function renderClientRow(client) {
  const name = escapeHtml(client.name);
  const type = escapeHtml(client.type || 'unknown');
  const scope = escapeHtml(client.scope || 'unknown');

  const actions = [];
  actions.push(`<a href="#!" class="nexo-action-download" data-name="${name}">Download</a>`);

  if (currentProtocol === 'wireguard') {
    actions.push(`<a href="#!" class="nexo-action-qr" data-name="${name}">QR</a>`);
    if (client.disabled) {
      actions.push(`<a href="#!" class="nexo-action-enable" data-name="${name}">Enable</a>`);
    } else {
      actions.push(`<a href="#!" class="nexo-action-disable" data-name="${name}">Disable</a>`);
    }
  }

  actions.push(`<a href="#!" class="nexo-action-remove red-text" data-name="${name}">Remove</a>`);

  return `
    <tr>
      <td>
        <div class="nexo-mono">${name}</div>
        <div class="nexo-muted nexo-mono">${client.created ? escapeHtml(formatCreated(client.created)) : ''}</div>
      </td>
      <td>${type}</td>
      <td class="nexo-mono">${scope}</td>
      <td>${renderStatusBadge(client)}</td>
      <td class="nexo-actions">${actions.join('')}</td>
    </tr>
  `;
}

function loadServerInfo() {
  $('#serverInfo').text('Loading...');
  sendTo(null, 'getServerInfo', {}, (res) => {
    if (!res || !res.ok) {
      $('#serverInfo').text(`Error: ${(res && res.error) ? res.error : 'unknown'}`);
      return;
    }

    currentProtocol = res.protocol || null;

    const lines = [];
    lines.push(`protocol: ${res.protocol || '-'}`);
    if (res.serverAddresses) {
      lines.push(`vpn_ipv4: ${(res.serverAddresses.ipv4 || '-')}`);
      lines.push(`vpn_ipv6: ${(res.serverAddresses.ipv6 || '-')}`);
    }
    if (res.setupVars) {
      lines.push(`pivpnHOST: ${(res.setupVars.pivpnHOST || '-')}`);
      lines.push(`pivpnPORT: ${(res.setupVars.pivpnPORT || '-')}`);
      lines.push(`pivpnDNS1: ${(res.setupVars.pivpnDNS1 || '-')}`);
      lines.push(`pivpnDNS2: ${(res.setupVars.pivpnDNS2 || '-')}`);
      lines.push(`install_user: ${(res.setupVars.install_user || '-')}`);
      lines.push(`install_home: ${(res.setupVars.install_home || '-')}`);
      lines.push(`ALLOWED_IPS(default): ${(res.setupVars.ALLOWED_IPS || '-')}`);
    }

    $('#serverInfo').text(lines.join('\n'));

    // OpenVPN password input: hide helper when WG is detected
    if (currentProtocol === 'wireguard') {
      $('#newPassword').closest('.input-field').hide();
    } else {
      $('#newPassword').closest('.input-field').show();
    }
  });
}

function refreshClients() {
  $('#clientsError').text('');
  $('#clientsBody').html('<tr><td colspan="5" class="nexo-muted">Loading...</td></tr>');

  sendTo(null, 'listClients', {}, (res) => {
    if (!res || !res.ok) {
      $('#clientsError').text((res && res.error) ? res.error : 'Unknown error');
      $('#clientsBody').empty();
      return;
    }

    const clients = res.clients || [];
    if (!clients.length) {
      $('#clientsBody').html('<tr><td colspan="5" class="nexo-muted">No profiles found</td></tr>');
      return;
    }

    $('#clientsBody').html(clients.map(renderClientRow).join(''));
  });
}

function downloadTextFile(filename, content) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();

  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 250);
}

function bindClientActions() {
  // delegate clicks from tbody
  $('#clientsBody').on('click', 'a', function (e) {
    e.preventDefault();
    const $a = $(this);
    const name = $a.data('name');

    if ($a.hasClass('nexo-action-download')) {
      sendTo(null, 'getClientConfig', { name }, (res) => {
        if (!res || !res.ok) return toast((res && res.error) ? res.error : 'Download failed');
        const ext = (currentProtocol === 'wireguard') ? '.conf' : '.ovpn';
        downloadTextFile(`${name}${ext}`, res.content || '');
        toast('Downloaded');
      });
      return;
    }

    if ($a.hasClass('nexo-action-qr')) {
      sendTo(null, 'getClientQrSvg', { name }, (res) => {
        if (!res || !res.ok) return toast((res && res.error) ? res.error : 'QR failed');
        $('#qrContainer').html(res.svg || '');
        const modal = M.Modal.getInstance(document.getElementById('qrModal'));
        modal.open();
      });
      return;
    }

    if ($a.hasClass('nexo-action-disable')) {
      if (!confirm(`Disable ${name}?`)) return;
      sendTo(null, 'disableClient', { name }, (res) => {
        if (!res || !res.ok) return toast((res && res.error) ? res.error : 'Disable failed');
        toast('Disabled');
        refreshClients();
      });
      return;
    }

    if ($a.hasClass('nexo-action-enable')) {
      if (!confirm(`Enable ${name}?`)) return;
      sendTo(null, 'enableClient', { name }, (res) => {
        if (!res || !res.ok) return toast((res && res.error) ? res.error : 'Enable failed');
        toast('Enabled');
        refreshClients();
      });
      return;
    }

    if ($a.hasClass('nexo-action-remove')) {
      if (!confirm(`Remove/Revoke ${name}?`)) return;
      sendTo(null, 'removeClient', { name }, (res) => {
        if (!res || !res.ok) return toast((res && res.error) ? res.error : 'Remove failed');
        toast('Removed');
        refreshClients();
      });
      return;
    }
  });
}

function initFirewallFromSettings(settings) {
  $('#fwBlockForwarding').prop('checked', !!settings.blockForwarding);
  $('#fwRestrictPorts').prop('checked', !!settings.restrictPorts);

  const extraTcp = settings.extraTcpPorts || '';
  $('#fwTcpPorts').val(extraTcp);

  const extraUdp = settings.extraUdpPorts || '';
  $('#fwUdpPorts').val(extraUdp);

  M.updateTextFields();
}

function detectPortsIntoFirewallInput() {
  $('#fwResult').text('Detecting...');
  sendTo(null, 'detectPorts', {}, (res) => {
    if (!res || !res.ok) {
      $('#fwResult').text(`Error: ${(res && res.error) ? res.error : 'unknown'}`);
      return;
    }
    const ports = res.tcpPorts || [];
    $('#fwTcpPorts').val(ports.join(','));
    M.updateTextFields();
    $('#fwResult').text(`Detected TCP ports: ${ports.join(',')}`);
  });
}

function applyFirewall() {
  const tcpPorts = parsePortsCsv($('#fwTcpPorts').val());
  const udpPorts = parsePortsCsv($('#fwUdpPorts').val());
  const blockForwarding = $('#fwBlockForwarding').prop('checked');
  const restrictPorts = $('#fwRestrictPorts').prop('checked');

  $('#fwResult').text('Applying...');

  sendTo(null, 'applyFirewall', {
    blockForwarding,
    restrictPorts,
    tcpPorts,
    udpPorts,
  }, (res) => {
    if (!res || !res.ok) {
      $('#fwResult').text(`Error: ${(res && res.error) ? res.error : 'unknown'}`);
      return;
    }
    const lines = [];
    lines.push(`iface: ${res.iface}`);
    lines.push(`blockForwarding: ${res.blockForwarding}`);
    lines.push(`restrictPorts: ${res.restrictPorts}`);
    lines.push(`tcpPorts: ${(res.tcpPorts || []).join(',')}`);
    lines.push(`udpPorts: ${(res.udpPorts || []).join(',')}`);
    $('#fwResult').text(lines.join('\n'));
    toast('Firewall applied');
  });
}

function refreshStatus() {
  const idConn = `${adapter}.${instance}.info.connection`;
  const idErr = `${adapter}.${instance}.info.lastError`;
  const idProto = `${adapter}.${instance}.info.protocol`;

  const result = {};
  $('#statusInfo').text('Loading...');

  socket.emit('getState', idProto, (err, state) => {
    result.protocol = state && state.val;

    socket.emit('getState', idConn, (err2, st2) => {
      result.connection = st2 && st2.val;

      socket.emit('getState', idErr, (err3, st3) => {
        result.lastError = st3 && st3.val;

        $('#statusInfo').text(
          `protocol: ${result.protocol}\n` +
          `connection: ${result.connection}\n` +
          `lastError: ${result.lastError || ''}\n`
        );
      });
    });
  });
}

function createClient() {
  const name = String($('#newName').val() || '').trim();
  const type = String($('#newType').val() || 'customer');
  const scope = String($('#newScope').val() || 'hostOnly');
  const password = String($('#newPassword').val() || '');
  const lanCidr = String($('#newLanCidr').val() || '').trim();

  if (!name) {
    toast('Client name is required');
    return;
  }

  $('#createResult').text('Creating...');

  sendTo(null, 'addClient', { name, type, scope, password, lanCidr }, (res) => {
    if (!res || !res.ok) {
      $('#createResult').text('');
      toast((res && res.error) ? res.error : 'Create failed');
      return;
    }

    $('#createResult').text('');
    toast('Created');
    $('#newName').val('');
    $('#newPassword').val('');
    $('#newLanCidr').val('');
    M.updateTextFields();
    refreshClients();
  });
}

function load(settings, onChange) {
  if (!settings) return;

  $('.value').each(function () {
    const $this = $(this);
    const id = $this.attr('id');
    if (!id) return;

    if ($this.attr('type') === 'checkbox') {
      $this.prop('checked', settings[id]);
    } else {
      $this.val(settings[id]);
    }

    $this.on('change', () => onChange());
    $this.on('keyup', () => onChange());
  });

  M.updateTextFields();
  $('select').formSelect();
  $('.tabs').tabs();
  $('.modal').modal();

  // dynamic init
  initFirewallFromSettings(settings);
  loadServerInfo();
  refreshClients();
  refreshStatus();

  // handlers
  $('#btnRefresh').off('click').on('click', () => refreshClients());
  $('#btnCreate').off('click').on('click', () => createClient());
  $('#btnDetectPorts').off('click').on('click', () => detectPortsIntoFirewallInput());
  $('#btnApplyFirewall').off('click').on('click', () => applyFirewall());
  $('#btnStatus').off('click').on('click', () => refreshStatus());

  bindClientActions();

  onChange(false);
}

function save(callback) {
  const obj = {};
  $('.value').each(function () {
    const $this = $(this);
    const id = $this.attr('id');
    if (!id) return;

    if ($this.attr('type') === 'checkbox') {
      obj[id] = $this.prop('checked');
    } else {
      obj[id] = $this.val();
    }
  });
  callback(obj);
}
