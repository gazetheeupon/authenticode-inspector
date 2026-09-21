const $ = (id) => document.getElementById(id);

function setStatus(msg, isWarn) {
  const el = $('status');
  el.textContent = msg || '';
  el.classList.toggle('warn', !!isWarn);
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtTime(t) {
  if (!t) return '(unknown)';
  return t.iso ? `${t.iso} <span style="color:var(--muted)">(raw: ${escapeHtml(t.raw)})</span>` : `raw: ${escapeHtml(t.raw)}`;
}

function nameSummary(name) {
  if (!name) return '(none)';
  return escapeHtml(name.distinguishedName || '(empty name)');
}

function row(label, valueHtml) {
  return `<tr><td>${escapeHtml(label)}</td><td>${valueHtml}</td></tr>`;
}

function showError(msg) {
  $('errorCard').classList.remove('hidden');
  $('errorText').textContent = msg;
  $('resultsCard').classList.add('hidden');
}

function clearError() {
  $('errorCard').classList.add('hidden');
}

function renderUnsigned(parsed) {
  $('resultsCard').classList.remove('hidden');
  $('digestBanner').innerHTML = `<div class="banner neutral"><strong>Not signed</strong>This ${escapeHtml(parsed.architecture)} file has no Authenticode signature at all.</div>`;
  $('signerSection').style.display = 'none';
  $('opusSection').style.display = 'none';
  $('timestampSection').style.display = 'none';
  $('certsSection').style.display = 'none';
  renderWarnings(parsed.warnings);
}

function renderWarnings(warnings) {
  const section = $('warningsSection');
  if (!warnings || !warnings.length) {
    section.style.display = 'none';
    return;
  }
  section.style.display = '';
  $('warningsList').innerHTML = warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join('');
}

function renderTimestamp(ts) {
  const body = $('timestampBody');
  if (!ts) {
    body.innerHTML = `<div class="banner neutral"><strong>Not timestamped</strong>No RFC3161 or legacy timestamp was found on this signature. See the "Why does it say no timestamp?" note below.</div>`;
    return;
  }
  if (ts.error) {
    body.innerHTML = `<div class="banner bad"><strong>Timestamp present but could not be parsed</strong>${escapeHtml(ts.error)}</div>`;
    return;
  }
  if (ts.scheme === 'rfc3161') {
    let rows = '';
    rows += row('Timestamp time', fmtTime(ts.time));
    rows += row('Timestamp authority', ts.tsaName ? nameSummary(ts.tsaName) : '(not given as a directory name)');
    rows += row('Serial', `<code>${escapeHtml(ts.serialHex)}</code>`);
    rows += row('Policy OID', `<code>${escapeHtml(ts.policyOid)}</code>`);
    body.innerHTML = `<div class="banner good"><strong>RFC3161 timestamp present</strong>The signature was timestamped, so it can remain valid even after the signer's own certificate expires.</div><table class="kv">${rows}</table>`;
  } else if (ts.scheme === 'legacy-countersignature') {
    let rows = '';
    rows += row('Signing time', fmtTime(ts.time));
    rows += row('Countersigner', nameSummary(ts.issuer));
    rows += row('Serial', `<code>${escapeHtml(ts.serialHex)}</code>`);
    body.innerHTML = `<div class="banner good"><strong>Legacy PKCS#9 countersignature present</strong>An older-style timestamp countersignature was found.</div><table class="kv">${rows}</table>`;
  }
}

function renderCertificates(certs) {
  const body = $('certsBody');
  if (!certs.length) {
    body.innerHTML = '<p class="privacy">No certificates were embedded in the signature.</p>';
    return;
  }
  body.innerHTML = certs
    .map((c) => {
      if (c.error) return `<div class="cert-block"><p class="privacy" style="color:var(--bad);">${escapeHtml(c.error)}</p></div>`;
      const selfSigned = c.subject.distinguishedName === c.issuer.distinguishedName;
      let rows = '';
      rows += row('Subject', nameSummary(c.subject));
      rows += row('Issuer', nameSummary(c.issuer));
      rows += row('Serial', `<code>${escapeHtml(c.serialHex)}</code>`);
      rows += row('Valid from', fmtTime(c.notBefore));
      rows += row('Valid until', fmtTime(c.notAfter));
      const badge = c.isSigner ? '<span class="badge">SIGNER</span>' : '';
      const selfSignedNote = selfSigned ? '<p class="privacy" style="margin-top:.5rem;">Self-signed &mdash; issued and signed by the same identity, not backed by any certificate authority.</p>' : '';
      return `<div class="cert-block"><h3 style="margin-top:0;">Certificate${badge}</h3><table class="kv">${rows}</table>${selfSignedNote}</div>`;
    })
    .join('');
}

async function renderSigned(buffer, parsed) {
  $('resultsCard').classList.remove('hidden');
  const primary = parsed.certificateBlobs.find((b) => b.signedData);
  const sd = primary.signedData;
  const signer = sd.signer;

  $('signerSection').style.display = '';
  $('opusSection').style.display = '';
  $('timestampSection').style.display = '';
  $('certsSection').style.display = '';

  const signerCert = sd.certificates.find((c) => c.isSigner);
  let signerRows = '';
  signerRows += row('Subject', nameSummary(signerCert ? signerCert.subject : signer.issuer));
  signerRows += row('Issuer', nameSummary(signer.issuer));
  signerRows += row('Serial', `<code>${escapeHtml(signer.serialHex)}</code>`);
  signerRows += row('Digest algorithm', escapeHtml(signer.digestAlgorithm));
  $('signerTable').innerHTML = signerRows;

  let opusRows = '';
  opusRows += row('Program name', signer.programName ? escapeHtml(signer.programName) : '(not given)');
  opusRows += row('More info URL', signer.moreInfoUrl ? `<a href="${escapeHtml(signer.moreInfoUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(signer.moreInfoUrl)}</a>` : '(not given)');
  opusRows += row('Signing purpose', signer.statementType ? escapeHtml(signer.statementType) : '(not given)');
  opusRows += row('Signing time (claimed)', signer.signingTimeClaimed ? fmtTime(signer.signingTimeClaimed) : '(not given &mdash; see timestamp section for a trusted time)');
  $('opusTable').innerHTML = opusRows;

  renderTimestamp(signer.timestamp);
  renderCertificates(sd.certificates);
  renderWarnings(parsed.warnings);

  // Digest recomputation is async (Web Crypto). Show it as soon as it resolves.
  $('digestBanner').innerHTML = `<div class="banner neutral"><strong>Checking whether the file has been modified since signing&hellip;</strong></div>`;
  try {
    const digest = await AuthenticodeInspector.verifyDigest(buffer, parsed);
    if (digest.matches) {
      $('digestBanner').innerHTML = `<div class="banner good"><strong>Unmodified since signing</strong>The recomputed ${escapeHtml(sd.declaredDigestAlgorithm)} hash matches the hash declared in the signature.<br><code>${escapeHtml(digest.computedHex)}</code></div>`;
    } else {
      $('digestBanner').innerHTML = `<div class="banner bad"><strong>Modified since signing</strong>The file's current bytes do NOT match the hash declared in the signature. This file has changed since it was signed (or is corrupted).<br>Declared: <code>${escapeHtml(digest.declaredHex)}</code><br>Recomputed: <code>${escapeHtml(digest.computedHex)}</code></div>`;
    }
  } catch (e) {
    $('digestBanner').innerHTML = `<div class="banner bad"><strong>Could not recompute the hash</strong>${escapeHtml(e.message)}</div>`;
  }
}

async function handleFile(file) {
  clearError();
  $('fname').textContent = file.name;
  setStatus('Reading file…');
  $('resultsCard').classList.add('hidden');
  try {
    const buffer = await file.arrayBuffer();
    const parsed = AuthenticodeInspector.parsePEFile(buffer);
    setStatus(`Loaded ${file.name} (${parsed.architecture}, ${parsed.fileSize.toLocaleString()} bytes).`);
    if (!parsed.signed) {
      renderUnsigned(parsed);
    } else {
      await renderSigned(buffer, parsed);
    }
  } catch (err) {
    setStatus('', false);
    showError((err && err.message) || String(err));
  }
}

function bindDrop() {
  const dz = $('dropzone');
  const input = $('fileInput');
  const setDrag = (on) => dz.classList.toggle('drag', on);
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); setDrag(true); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); setDrag(false); }));
  dz.addEventListener('drop', (e) => {
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) handleFile(file);
  });
  dz.addEventListener('click', () => input.click());
  dz.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  input.addEventListener('change', () => {
    if (input.files && input.files[0]) handleFile(input.files[0]);
    input.value = '';
  });
}

bindDrop();
