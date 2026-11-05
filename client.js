window.__ModuleLoader__.load({
  id: 'dsh-rea',
  factory: (require) => {
    const React = require('react');
    const jsx = require('react/jsx-runtime');
    const h = React.createElement;
    const PLUGIN_ID = 'dsh-rea';
    const NS = 'dsh-rea';
    const dicts = {
      zh: {
        title: '逆向分析', subtitle: '环境与引擎', refresh: '刷新', loading: '读取环境…',
        preparing: '准备中', error: '失败',
        reaRuntime: '运行时', runtimeReady: '已解包', runtimeMissing: '未就绪',
        java: 'Java / JDK', jdkReady: '完整 JDK 已就绪', jdkMissing: '需要 64 位完整 JDK',
        jdkTooOld: (v, need) => `JDK ${v} 版本过低，Ghidra 需要 ${need}+`,
        ghidra: 'Ghidra', ghidraReady: '函数级反编译可用', ghidraMissing: '需要 Ghidra 12.1.4',
        configured: '已发现', cached: '插件缓存',         install: '准备 Ghidra', installing: '下载并解包中…',         installHint: '首次准备需要下载约 543 MB，校验后解包到 DSH 主目录。',
        download: '下载', extract: '解包', path: '路径',         external: '其他外部工具', jadx: 'JADX', apktool: 'Apktool', wabt: 'WABT', rizin: 'Kuna/Rizin',
        configuredYes: '已配置', configuredNo: '未配置', nativeHint: 'Ghidra 只在真正调用 native 函数分析时使用。',
        noNetwork: '下载需要网络；失败时不会修改已有安装。', pathConfig: '外部工具路径', save: '保存路径', saved: '已保存', pathPlaceholder: '绝对路径（可留空）', prepareTool: '准备', cannotPrepare: '无自动安装包，请填写路径。', manualRizin: 'Kuna/Rizin 需要你自行安装，在下方填写可执行文件的绝对路径。', updateTitle: '版本更新', updateCurrent: '当前版本', updateLatest: '最新版本', checkUpdate: '检查更新', checkingUpdate: '检查中…', upToDate: '已是最新版本', updateAvailable: '有新版本可下载', installUpdate: '下载并安装', installingUpdate: '下载安装中…', updateRestart: '安装完成，重启会话后生效。', updateSource: '来源', updateMirror: '镜像', updateMirrorsTried: '镜像尝试', updatePinned: '已钉死摘要', updateBackups: '备份保留', updateTrust: '生效信任级别', trustNone: '无独立校验（摘要与归档同源）', trustPin: '本地钉死摘要', trustSignature: '清单签名验签', trustBoth: '签名 + 钉死摘要', policyTitle: '安全策略', policyScope: '授权目标范围', policyUnrestricted: '未限制', policyDevices: '设备写操作', policySensitive: '敏感产物', policyRetention: '产物保留', policyEgress: '外联工具策略', policyOn: '开启', policyOff: '关闭', policyDays: '天', policySave: '保存策略', policyReset: '恢复默认', policySaved: '策略已保存', policyScopeHint: '每行一个绝对路径；留空表示不限制目标范围。', policyRetentionUnit: '天', policyEgressWarn: 'warn · 记录但不拦截', policyEgressAllow: 'allow · 不记录', policyEgressDeny: 'deny · 拒绝外联工具', policyFromPanel: '来自面板', policyFromRow: '来自配置行', policyDirty: '有未保存的修改', policySensitiveHint: '开启后完整结果不再写入磁盘，只能看到截断开头。', policyResetHint: '恢复默认会清除面板保存的所有策略。', policyError: '策略未保存', policyScopePick: '添加文件夹…', policyScopeEmpty: '未限制：任何路径都可以分析。', policyUp: '上一级', policyChoose: '选用此文件夹', policyCancel: '取消', policyRemove: '移除', policyBrowseFail: '读取目录失败', policyNeedsRestart: '目录选择需要重启会话后生效', policyPathPlaceholder: '绝对路径', policyAdd: '添加', egressWarn: '记录', egressAllow: '允许', egressDeny: '拒绝', policyTruncated: '目录过大，只显示前 400 项。', policyLegend: '绿点＝限制生效；黄点＝已放宽，工具可以做得更多。', policyDevicesOn: '工具可以写入、重命名或删除设备上的文件。', policyRisk: '已放宽', policyDirsOnly: '只显示文件夹',
      },
      en: {
        title: 'Reverse Engineering', subtitle: 'Environment and engines', refresh: 'Refresh', loading: 'Reading environment…',
        preparing: 'Preparing', error: 'Failed',
        reaRuntime: 'Runtime', runtimeReady: 'Unpacked', runtimeMissing: 'Not ready',
        java: 'Java / JDK', jdkReady: 'Full JDK ready', jdkMissing: '64-bit full JDK required',
        jdkTooOld: (v, need) => `JDK ${v} is below the ${need}+ that Ghidra needs`,
        ghidra: 'Ghidra', ghidraReady: 'Function decompilation available', ghidraMissing: 'Ghidra 12.1.4 required',
        configured: 'Detected', cached: 'Plugin cache',         install: 'Prepare Ghidra', installing: 'Downloading and extracting…',         installHint: 'First preparation downloads about 543 MB and extracts it into the DSH home.',
        download: 'Download', extract: 'Extract', path: 'Path',         external: 'Other external tools', jadx: 'JADX', apktool: 'Apktool', wabt: 'WABT', rizin: 'Kuna/Rizin',
        configuredYes: 'Configured', configuredNo: 'Not configured', nativeHint: 'Ghidra is used only when a native function analysis is actually called.',
        noNetwork: 'Downloading requires network access; an existing installation is not changed on failure.', pathConfig: 'External tool paths', save: 'Save paths', saved: 'Saved', pathPlaceholder: 'Absolute path (optional)', prepareTool: 'Prepare', cannotPrepare: 'No automatic package; enter a path.', manualRizin: 'Kuna/Rizin must be installed by you; enter the absolute path below.', updateTitle: 'Updates', updateCurrent: 'Installed', updateLatest: 'Latest', checkUpdate: 'Check for updates', checkingUpdate: 'Checking…', upToDate: 'Up to date', updateAvailable: 'Update available', installUpdate: 'Download and install', installingUpdate: 'Downloading…', updateRestart: 'Installed. Restart the session to load it.', updateSource: 'Source', updateMirror: 'Mirror', updateMirrorsTried: 'Mirror attempts', updatePinned: 'Pinned digest', updateBackups: 'Backups kept', updateTrust: 'Effective trust', trustNone: 'no independent check (digest shares the asset origin)', trustPin: 'locally pinned digest', trustSignature: 'signed manifest', trustBoth: 'signature + pinned digest', policyTitle: 'Security policy', policyScope: 'Authorized target roots', policyUnrestricted: 'unrestricted', policyDevices: 'Device mutations', policySensitive: 'Sensitive artifacts', policyRetention: 'Artifact retention', policyEgress: 'Network egress', policyOn: 'on', policyOff: 'off', policyDays: 'd', policySave: 'Save policy', policyReset: 'Reset', policySaved: 'Policy saved', policyScopeHint: 'One absolute path per line; empty means unrestricted.', policyRetentionUnit: 'days', policyEgressWarn: 'warn · record, allow', policyEgressAllow: 'allow · silent', policyEgressDeny: 'deny · refuse', policyFromPanel: 'from the panel', policyFromRow: 'from the config row', policyDirty: 'unsaved changes', policySensitiveHint: 'When on, full results are never written to disk; only a truncated head is shown.', policyResetHint: 'Reset clears every policy saved from the panel.', policyError: 'Policy not saved', policyScopePick: 'Add folder…', policyScopeEmpty: 'Unrestricted: any path can be analysed.', policyUp: 'Up', policyChoose: 'Use this folder', policyCancel: 'Cancel', policyRemove: 'Remove', policyBrowseFail: 'Could not read the directory', policyNeedsRestart: 'The folder picker needs a session restart', policyPathPlaceholder: 'Absolute path', policyAdd: 'Add', egressWarn: 'Record', egressAllow: 'Allow', egressDeny: 'Deny', policyTruncated: 'Directory is large; showing the first 400 entries.', policyLegend: 'Green = restriction active; amber = relaxed, tools can do more.', policyDevicesOn: 'Tools may write, rename or delete files on the device.', policyRisk: 'relaxed', policyDirsOnly: 'folders only',
      },
    };
    function api(path) { const u = new URL(path, document.baseURI); u.hash = ''; return u.pathname + u.search; }
    async function getStatus() { const r = await fetch(api('/rea/environment'), { cache: 'no-store' }); const j = await r.json(); if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }
    async function installGhidra() { const r = await fetch(api('/rea/ghidra/install'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }); const j = await r.json(); if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }
    async function saveConfig(paths) { const r = await fetch(api('/rea/engine/config'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(paths) }); const j = await r.json(); if (!r.ok || j.ok === false) throw new Error(j.error || `HTTP ${r.status}`); return j; }
    async function listDirs(path, restartHint) {
      const query = encodeURIComponent(path || '');
      const attempt = async (method) => {
        const url = method === 'GET' ? api(`/rea/fs/list?path=${query}`) : api('/rea/fs/list');
        const init = method === 'GET'
          ? { cache: 'no-store' }
          : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ path: path || '' }) };
        const r = await fetch(url, init);
        const text = await r.text();
        let body = null;
        // An empty body is what a host answers when it has no route for this
        // path; `r.json()` would report "Unexpected end of JSON input" instead.
        try { body = text.length > 0 ? JSON.parse(text) : null; } catch { body = null; }
        return { status: r.status, ok: r.ok, body };
      };
      // POST first because every other route on this panel is a JSON POST; a
      // 405 means this host only routes GET on the path, so try that once.
      let result = await attempt('POST');
      if (result.status === 405) result = await attempt('GET');
      if (result.body === null) throw new Error(result.status === 404 ? (restartHint || 'HTTP 404') : `HTTP ${result.status}`);
      if (!result.ok || result.body.ok === false) throw new Error(result.body.error || `HTTP ${result.status}`);
      return result.body;
    }
    async function savePolicy(patch) { const r = await fetch(api('/rea/policy'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(patch) }); const j = await r.json(); if (!r.ok || j.ok === false) throw new Error(j.error || `HTTP ${r.status}`); return j; }
    async function installTool(tool) { const r = await fetch(api('/rea/engine/install'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tool }) }); const j = await r.json(); if (!r.ok || j.ok === false) throw new Error(j.error || `HTTP ${r.status}`); return j; }
    async function checkUpdate() { const r = await fetch(api('/rea/update/check'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }); const j = await r.json(); if (!r.ok || j.ok === false) throw new Error(j.error || `HTTP ${r.status}`); return j; }
    async function startUpdate() { const r = await fetch(api('/rea/update/install'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }); const j = await r.json(); if (!r.ok || j.ok === false) throw new Error(j.error || `HTTP ${r.status}`); return j; }
    function lensIcon(size, active) {
      const color = active ? 'var(--dsw-alias-brand-primary)' : 'currentColor';
      const dim = size || 20;
      return h('svg', { width: dim, height: dim, viewBox: '0 0 24 24', fill: 'none', stroke: color, strokeWidth: 1.7, strokeLinecap: 'round', strokeLinejoin: 'round', 'aria-hidden': true },
        h('rect', { x: 3.5, y: 5, width: 11.5, height: 10, rx: 1.8 }),
        h('path', { d: 'M6 8.5h5M6 11h3.2' }),
        h('circle', { cx: 16.5, cy: 15.5, r: 3.4 }),
        h('path', { d: 'm19 18 2.2 2.2' }),
      );
    }
    function StatusDot({ state }) { return h('span', { className: `rea-dot rea-${state}` }); }
    function StatusRow({ label, state, detail, extra, action }) { return h('div', { className: 'rea-status-row' }, h('div', { className: 'rea-status-label' }, h(StatusDot, { state }), h('span', null, label)), h('span', { className: 'rea-status-detail' }, detail), extra || null, action || null); }
    function Section({ title, children }) { return h('section', { className: 'rea-section' }, h('h3', null, title), children); }
    function ExternalCard({ keyName, label, configured, canPrepare, state, busy, onPrepare, t }) {
      const pct = state?.total > 0 ? Math.min(100, Math.round(state.bytes / state.total * 100)) : 0;
      const running = state?.phase === 'downloading' || state?.phase === 'configuring';
      const failed = state?.phase === 'error';
      const action = configured || running ? null
        : canPrepare === false
          ? h('small', { style: { color: 'var(--dsw-alias-label-secondary)', fontSize: '11px', flex: 'none' } }, t('cannotPrepare'))
          : h('button', { className: 'rea-config', type: 'button', onClick: () => onPrepare(keyName), disabled: busy }, t('prepareTool'));
      return h('div', { className: 'rea-external', key: keyName },
        h('div', { className: 'rea-external-main' }, h(StatusDot, { state: configured ? 'ok' : running ? 'busy' : failed ? 'error' : 'warn' }), h('span', null, label), h('small', null, configured ? t('configuredYes') : running ? `${t('preparing')} ${pct}%` : failed ? t('error') : t('configuredNo'))),
        action,
        running ? h('div', { className: 'rea-tool-progress' }, h('div', { style: { width: `${pct}%` } })) : null,
      );
    }
    function PathForm({ t, paths, setPaths, doSave, busy, saved }) {
      const fields = [['GHIDRA_INSTALL_DIR', t('ghidra')], ['JAVA_HOME', t('java')], ['REA_JADX_MCP_JAR', t('jadx')], ['REA_APKTOOL_COMMAND', t('apktool')], ['REA_WABT_BIN_DIRECTORY', t('wabt')], ['REA_KUNA_COMMAND', t('rizin')]];
      return h(Section, { title: t('pathConfig') }, h('div', { className: 'rea-path-form' },
        fields.map(([key, label]) => h('label', { className: 'rea-path-field', key }, h('span', null, label), h('input', { value: paths[key] || '', placeholder: t('pathPlaceholder'), onChange: (e) => setPaths((old) => ({ ...old, [key]: e.target.value })) }))),
        h('button', { className: 'rea-primary', type: 'button', onClick: doSave, disabled: busy }, saved ? t('saved') : t('save')),
      ));
    }
    function ExternalGrid({ t, status, busy, onPrepare }) {
      const items = [['jadx', t('jadx')], ['apktool', t('apktool')], ['wabt', t('wabt')], ['rizin', t('rizin')]];
      return h(Section, { title: t('external') },
        h('div', { className: 'rea-external-grid' }, items.map(([key, label]) => h(ExternalCard, { key, keyName: key, label, configured: status.external?.[key], canPrepare: status.externalCanPrepare?.[key], state: status.externalState?.[key], busy, onPrepare, t }))),
        h('p', { className: 'rea-hint', style: { marginLeft: 0 } }, t('manualRizin')),
      );
    }
    function UpdateSection({ t, status, busy, onCheck, onInstall }) {
      const update = status?.update ?? {};
      const phase = update.phase ?? 'idle';
      const working = phase === 'checking' || phase === 'downloading' || phase === 'extracting' || phase === 'installing';
      const pct = update.total > 0 ? Math.min(100, Math.round(update.bytes / update.total * 100)) : 0;
      const state = update.restartRequired ? 'ok' : phase === 'error' ? 'error' : update.hasUpdate ? 'busy' : 'ok';
      const detail = update.restartRequired ? t('updateRestart')
        : phase === 'error' ? (update.error || t('error'))
          : update.hasUpdate ? `${t('updateAvailable')} · ${update.latest}`
            : update.checkedAt ? t('upToDate') : `${t('updateCurrent')} ${update.current || status?.version || '—'}`;
      return h(Section, { title: t('updateTitle') },
        h(StatusRow, {
          label: t('updateCurrent'),
          state,
          detail,
          extra: update.source ? h('span', { className: 'rea-badge' }, `${t('updateSource')}: ${update.source}`) : null,
          action: h('button', { className: 'rea-config', type: 'button', onClick: onCheck, disabled: busy || working }, working && phase === 'checking' ? t('checkingUpdate') : t('checkUpdate')),
        }),
        update.hasUpdate && !update.restartRequired
          ? h('button', { className: 'rea-primary', type: 'button', onClick: onInstall, disabled: working }, working ? t('installingUpdate') : `${t('installUpdate')} ${update.latest}`)
          : null,
        phase === 'downloading'
          ? h('div', { className: 'rea-progress-wrap' }, h('div', { className: 'rea-progress-label' }, `${update.mirror || t('updateMirror')} · ${pct}%`), h('div', { className: 'rea-progress' }, h('div', { style: { width: `${pct}%` } })))
          : null,
        phase === 'extracting' || phase === 'installing' ? h('div', { className: 'rea-progress-label', style: { marginLeft: 0 } }, update.message || t('installingUpdate')) : null,
        update.mirrorAttempts && update.mirrorAttempts.length > 0
          ? h('div', { className: 'rea-mirror-log' }, h('div', { className: 'rea-mirror-log-title' }, t('updateMirrorsTried')), update.mirrorAttempts.map((attempt, index) => h('div', { className: `rea-mirror-row ${attempt.ok ? 'rea-mirror-ok' : 'rea-mirror-fail'}`, key: `${attempt.id}-${index}` }, h('span', null, attempt.label), h('small', null, attempt.reason))))
          : null,
        update.pinnedSha256 ? h('div', { className: 'rea-path' }, `${t('updatePinned')}: ${String(update.pinnedSha256).slice(0, 16)}…`) : null,
        h('div', { className: 'rea-path' }, `${t('updateTrust')}: ${t(({ none: 'trustNone', pin: 'trustPin', signature: 'trustSignature', 'pin+signature': 'trustBoth' })[update.trustPolicy] || 'trustNone')}`),
        update.restartRequired && update.backupCount > 0 ? h('div', { className: 'rea-path' }, `${t('updateBackups')}: ${update.backupCount}`) : null,
        update.hasUpdate && update.releaseUrl && !update.restartRequired
          ? h('p', { className: 'rea-hint', style: { marginLeft: 0 } }, h('a', { href: update.releaseUrl, target: '_blank', rel: 'noreferrer', style: { color: 'var(--dsw-alias-brand-primary)' } }, `${t('updateLatest')} ${update.latest}`))
          : null,
      );
    }
    function Toggle({ checked, onLabel, offLabel, onChange, disabled }) {
      return h('button', {
        className: `rea-switch${checked ? ' rea-switch-on' : ''}`,
        type: 'button',
        role: 'switch',
        'aria-checked': checked ? 'true' : 'false',
        disabled,
        onClick: () => onChange(!checked),
      }, h('span', { className: 'rea-switch-track' }, h('span', { className: 'rea-switch-knob' })), h('span', null, checked ? onLabel : offLabel));
    }
    /**
     * A segmented control instead of a <select>.
     *
     * The native dropdown renders with the operating system's own chrome, which
     * in a dark panel is a white list with a different font - it looked like a
     * form borrowed from another application. Three radio buttons cost one line
     * more and match every other control in this section.
     */
    function Segmented({ value, options, onChange, disabled }) {
      return h('div', { className: 'rea-seg', role: 'radiogroup' },
        options.map((option) => h('button', {
          key: option.value,
          type: 'button',
          role: 'radio',
          'aria-checked': option.value === value ? 'true' : 'false',
          className: `rea-seg-item${option.value === value ? ' rea-seg-on' : ''}`,
          disabled,
          onClick: () => onChange(option.value),
        }, option.label)));
    }
    /**
     * Folder picker.
     *
     * A textarea was the wrong control: a scope root is a directory on this
     * machine, and asking a person to type an absolute path by hand is how a
     * typo becomes "the tool refuses every file". The server lists directory
     * names only; this component never sees file contents.
     */
    function ScopePicker({ t, targets, onChange, disabled }) {
      const [open, setOpen] = React.useState(false);
      const [listing, setListing] = React.useState(null);
      const [error, setError] = React.useState('');
      const [busy, setBusy] = React.useState(false);
      const [manual, setManual] = React.useState('');
      const browse = async (path) => {
        setBusy(true);
        try {
          setListing(await listDirs(path, t('policyNeedsRestart')));
          setError('');
        } catch (e) { setError(`${t('policyBrowseFail')}: ${String(e?.message || e)}`); } finally { setBusy(false); }
      };
      const start = () => { setOpen(true); if (!listing) browse(''); };
      const add = (path) => { if (path && !targets.includes(path)) onChange([...targets, path]); setOpen(false); };
      return h('div', { className: 'rea-scope' },
        targets.length === 0
          ? h('span', { className: 'rea-scope-empty' }, t('policyUnrestricted'))
          : targets.map((path) => h('div', { className: 'rea-scope-chip', key: path },
            h('span', { className: 'rea-scope-path' }, path),
            h('button', {
              className: 'rea-scope-x',
              type: 'button',
              title: t('policyRemove'),
              'aria-label': `${t('policyRemove')} ${path}`,
              disabled,
              onClick: () => onChange(targets.filter((entry) => entry !== path)),
            }, '\u00d7'))),
        h('button', { className: 'rea-config', type: 'button', disabled, onClick: start }, t('policyScopePick')),
        open ? h('div', { className: 'rea-browser' },
          h('div', { className: 'rea-browser-bar' },
            h('button', { className: 'rea-config', type: 'button', disabled: busy || !listing?.parent, onClick: () => browse(listing.parent) }, t('policyUp')),
            h('code', { className: 'rea-browser-path' }, listing?.path || '\u2014'),
            h('small', { className: 'rea-policy-note' }, t('policyDirsOnly')),
          ),
          error ? h('div', { className: 'rea-alert' }, error) : null,
          error ? h('div', { className: 'rea-browser-actions' },
            h('input', {
              className: 'rea-policy-number',
              style: { flex: '1', width: 'auto' },
              value: manual,
              placeholder: t('policyPathPlaceholder'),
              onInput: (event) => setManual(String(event.target.value)),
            }),
            h('button', { className: 'rea-config', type: 'button', disabled: !manual.trim(), onClick: () => add(manual.trim()) }, t('policyAdd'))) : null,
          h('div', { className: 'rea-browser-list' },
            (listing?.entries || []).map((entry) => h('button', { className: 'rea-browser-entry', type: 'button', key: entry.path, disabled: busy, onClick: () => browse(entry.path) }, entry.name))),
          listing?.truncated ? h('small', { className: 'rea-policy-note' }, t('policyTruncated')) : null,
          h('div', { className: 'rea-browser-actions' },
            h('button', { className: 'rea-primary', type: 'button', disabled: busy || !listing?.path, onClick: () => add(listing.path) }, t('policyChoose')),
            h('button', { className: 'rea-ghost', type: 'button', onClick: () => setOpen(false) }, t('policyCancel')),
          ),
        ) : null,
      );
    }
    function PolicySection({ t, status, busy, draft, setDraft, onSave, onReset, saved, dirty }) {
      const policy = status?.policy;
      if (!policy) return null;
      const value = draft ?? {
        allowedTargets: policy.values?.allowedTargets ?? [],
        allowDeviceMutations: policy.values?.allowDeviceMutations ?? false,
        sensitiveArtifacts: policy.values?.sensitiveArtifacts ?? false,
        artifactRetentionDays: policy.values?.artifactRetentionDays ?? 7,
        networkEgressPolicy: policy.values?.networkEgressPolicy ?? 'warn',
      };
      const targets = Array.isArray(value.allowedTargets) ? value.allowedTargets : [];
      const edit = (patch) => setDraft({ ...value, ...patch });
      // One rule for the whole panel: green means on / configured, grey means
      // off. Anything else - amber for "relaxed", red for "risky" - turned a
      // working switch into what looked like a broken one.
      const row = (label, on, control) => h('div', { className: 'rea-policy-row' },
        h('div', { className: 'rea-status-label' }, h(StatusDot, { state: on ? 'ok' : 'off' }), h('span', null, label)),
        h('div', { className: 'rea-policy-control' }, control),
      );
      return h(Section, { title: t('policyTitle') },
        h('div', { className: 'rea-policy' },
          row(t('policyScope'), targets.length > 0,
            h(ScopePicker, { t, targets, onChange: (next) => edit({ allowedTargets: next }), disabled: busy })),
          row(t('policyDevices'), value.allowDeviceMutations,
            h(Toggle, { checked: value.allowDeviceMutations, onLabel: t('policyOn'), offLabel: t('policyOff'), onChange: (next) => edit({ allowDeviceMutations: next }), disabled: busy })),
          row(t('policySensitive'), value.sensitiveArtifacts,
            h(Toggle, { checked: value.sensitiveArtifacts, onLabel: t('policyOn'), offLabel: t('policyOff'), onChange: (next) => edit({ sensitiveArtifacts: next }), disabled: busy })),
          row(t('policyRetention'), true,
            h('input', {
              className: 'rea-policy-number',
              type: 'number',
              min: 1,
              max: 365,
              step: 1,
              value: value.artifactRetentionDays,
              onChange: (event) => edit({ artifactRetentionDays: Number(event.target.value) }),
            })),
          row(t('policyEgress'), policy.networkEgressPolicy === 'deny',
            h(Segmented, {
              value: value.networkEgressPolicy,
              disabled: busy,
              onChange: (next) => edit({ networkEgressPolicy: next }),
              options: [
                { value: 'warn', label: t('egressWarn') },
                { value: 'allow', label: t('egressAllow') },
                { value: 'deny', label: t('egressDeny') },
              ],
            })),
        ),
        policy.error ? h('p', { className: 'rea-policy-note' }, `${t('policyError')}: ${policy.error}`) : null,
        h('div', { className: 'rea-policy-actions' },
          h('button', { className: 'rea-primary', type: 'button', onClick: onSave, disabled: busy || !dirty }, saved ? t('policySaved') : t('policySave')),
          h('button', { className: 'rea-ghost', type: 'button', onClick: onReset, disabled: busy }, t('policyReset')),
        ),
      );
    }
    function Panel({ t }) {
      const [status, setStatus] = React.useState(null);
      const [busy, setBusy] = React.useState(false);
      const [error, setError] = React.useState('');
      const [paths, setPaths] = React.useState({});
      const [saved, setSaved] = React.useState(false);
      // The security policy is editable in place. It has its own dirty flag
      // because a poll must never overwrite a switch the person just flipped.
      const [policyDraft, setPolicyDraft] = React.useState(null);
      const [policySaved, setPolicySaved] = React.useState(false);
      const policyTouched = React.useRef(false);
      // The panel polls for install progress. Without this flag the poll wrote
      // the server's saved paths back into the form every three seconds, which
      // erased whatever the person was typing.
      const pathsTouched = React.useRef(false);
      const load = React.useCallback(async (adopt) => {
        try {
          setError('');
          const next = await getStatus();
          setStatus(next);
          if (adopt === true || !pathsTouched.current) {
            setPaths(next.configured ?? {});
            pathsTouched.current = false;
          }
          if (adopt === true || !policyTouched.current) {
            setPolicyDraft(next.policy?.values ?? null);
            policyTouched.current = false;
          }
        } catch (e) { setError(String(e?.message || e)); }
      }, []);
      React.useEffect(() => {
        load(false);
        const timer = setInterval(() => { if (document.visibilityState !== 'hidden') load(false); }, 3000);
        return () => clearInterval(timer);
      }, [load]);
      React.useEffect(() => {
        if (!saved) return undefined;
        const timer = setTimeout(() => setSaved(false), 2000);
        return () => clearTimeout(timer);
      }, [saved]);
      React.useEffect(() => {
        if (!policySaved) return undefined;
        const timer = setTimeout(() => setPolicySaved(false), 2400);
        return () => clearTimeout(timer);
      }, [policySaved]);
      const editPaths = React.useCallback((updater) => { pathsTouched.current = true; setPaths(updater); }, []);
      const editPolicy = React.useCallback((next) => { policyTouched.current = true; setPolicyDraft(next); }, []);
      const gh = status?.ghidra;
      const java = status?.java;
      const doInstall = async () => { setBusy(true); setError(''); try { setStatus(await installGhidra()); } catch (e) { setError(String(e?.message || e)); } finally { setBusy(false); } };
      const doSave = async () => {
        setBusy(true); setError(''); setSaved(false);
        try {
          const next = await saveConfig(paths);
          setStatus(next);
          setPaths(next.configured ?? {});
          pathsTouched.current = false;
          setSaved(true);
        } catch (e) { setError(String(e?.message || e)); } finally { setBusy(false); }
      };
      const policyPayload = (draft) => ({
        allowedTargets: (draft?.allowedTargets ?? []).map((entry) => String(entry).trim()).filter((entry) => entry.length > 0),
        allowDeviceMutations: draft?.allowDeviceMutations === true,
        sensitiveArtifacts: draft?.sensitiveArtifacts === true,
        artifactRetentionDays: Number(draft?.artifactRetentionDays ?? 7),
        networkEgressPolicy: draft?.networkEgressPolicy ?? 'warn',
      });
      const settled = status?.policy?.values ? policyPayload(status.policy.values) : null;
      const policyDirty = Boolean(policyDraft && settled) && JSON.stringify(policyPayload(policyDraft)) !== JSON.stringify(settled);
      const doSavePolicy = async () => {
        setBusy(true); setError(''); setPolicySaved(false);
        try {
          const next = await savePolicy(policyPayload(policyDraft));
          setStatus(next);
          setPolicyDraft(next.policy?.values ?? null);
          policyTouched.current = false;
          setPolicySaved(true);
        } catch (e) { setError(String(e?.message || e)); } finally { setBusy(false); }
      };
      const doResetPolicy = async () => {
        setBusy(true); setError(''); setPolicySaved(false);
        try {
          const next = await savePolicy({ reset: true });
          setStatus(next);
          setPolicyDraft(next.policy?.values ?? null);
          policyTouched.current = false;
          setPolicySaved(true);
        } catch (e) { setError(String(e?.message || e)); } finally { setBusy(false); }
      };
      const doTool = async (tool) => { setBusy(true); setError(''); try { setStatus(await installTool(tool)); } catch (e) { setError(String(e?.message || e)); } finally { setBusy(false); } };
      const doCheckUpdate = async () => { setBusy(true); setError(''); try { setStatus(await checkUpdate()); } catch (e) { setError(String(e?.message || e)); } finally { setBusy(false); } };
      const doInstallUpdate = async () => { setBusy(true); setError(''); try { setStatus(await startUpdate()); } catch (e) { setError(String(e?.message || e)); } finally { setBusy(false); } };
      const pct = gh?.total > 0 ? Math.min(100, Math.round(gh.bytes / gh.total * 100)) : 0;
      return h('div', { className: 'rea-panel' },
        h('div', { className: 'rea-header' }, h('div', { className: 'rea-heading' }, h('div', { className: 'rea-title' }, lensIcon(22, true), h('span', null, t('title'))), h('div', { className: 'rea-subtitle' }, t('subtitle'))), h('button', { className: 'rea-ghost', type: 'button', onClick: () => load(false), disabled: busy }, t('refresh'))),
        error ? h('div', { className: 'rea-alert' }, error) : null,
        status ? h(UpdateSection, { t, status, busy, onCheck: doCheckUpdate, onInstall: doInstallUpdate }) : null,
        !status ? h('div', { className: 'rea-loading' }, t('loading')) : h(React.Fragment, null,
          h(Section, { title: t('reaRuntime') }, h(StatusRow, { label: t('reaRuntime'), state: status.runtime?.unpacked ? 'ok' : 'warn', detail: status.runtime?.unpacked ? t('runtimeReady') : t('runtimeMissing') })),
          h(Section, { title: t('ghidra') },
            h(StatusRow, { label: t('java'), state: java?.fullJdk && java?.sufficientForGhidra !== false ? 'ok' : 'warn', detail: java?.fullJdk ? (java?.sufficientForGhidra === false ? t('jdkTooOld', java.version || '?', java.requiredMajor ?? 21) : `${t('jdkReady')} · ${java.version || ''}`) : t('jdkMissing') }),
            h(StatusRow, { label: t('ghidra'), state: gh?.ready ? 'ok' : gh?.phase === 'error' ? 'error' : gh?.phase === 'downloading' || gh?.phase === 'extracting' ? 'busy' : 'warn', detail: gh?.ready ? `${t('ghidraReady')} · ${gh.version || ''}` : gh?.phase === 'downloading' || gh?.phase === 'extracting' ? t('preparing') : t('ghidraMissing'), extra: gh?.ready ? h('span', { className: 'rea-badge' }, gh.source === 'rea-engines-cache' ? t('cached') : t('configured')) : null }),
            gh?.phase === 'downloading' ? h('div', { className: 'rea-progress-wrap' }, h('div', { className: 'rea-progress-label' }, `${t('download')} · ${pct}%`), h('div', { className: 'rea-progress' }, h('div', { style: { width: `${pct}%` } }))) : null,
            gh?.phase === 'extracting' ? h('div', { className: 'rea-progress-label' }, t('extract')) : null,
            gh?.path ? h('div', { className: 'rea-path' }, `${t('path')}: ${gh.path}`) : null,
            !gh?.ready ? h(React.Fragment, null, h('p', { className: 'rea-hint' }, t('installHint')), h('button', { className: 'rea-primary', type: 'button', onClick: doInstall, disabled: busy || gh?.phase === 'downloading' || gh?.phase === 'extracting' }, busy ? t('installing') : t('install'))) : null,
            h('p', { className: 'rea-hint' }, t('nativeHint')),
          ),
          h(ExternalGrid, { t, status, busy, onPrepare: doTool }),
          h(PathForm, { t, paths, setPaths: editPaths, doSave, busy, saved }),
          h(PolicySection, { t, status, busy, draft: policyDraft, setDraft: editPolicy, onSave: doSavePolicy, onReset: doResetPolicy, saved: policySaved, dirty: policyDirty }),
          h('div', { className: 'rea-footnote' }, t('noNetwork')),
        ),
      );
    }
    const css = `.rea-panel{height:100%;overflow:auto;box-sizing:border-box;padding:24px 28px;color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-base);font:13px/1.5 system-ui,sans-serif}.rea-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:22px}.rea-title{display:flex;align-items:center;gap:9px;font-size:18px;font-weight:650}.rea-subtitle{margin:4px 0 0 31px;color:var(--dsw-alias-label-secondary);font-size:12px}.rea-ghost,.rea-primary,.rea-config{border:1px solid var(--dsw-alias-border-l1);border-radius:7px;padding:6px 11px;background:var(--dsw-alias-button-elevated-fill,var(--dsw-alias-bg-layer-1));color:var(--dsw-alias-label-primary);cursor:pointer}.rea-primary{border-color:var(--dsw-alias-button-primary-fill,var(--dsw-alias-brand-primary));background:var(--dsw-alias-button-primary-fill,var(--dsw-alias-brand-primary));color:var(--dsw-alias-label-primary-foreground,#fff);font-weight:600;margin-top:7px}.rea-config{padding:4px 8px;font-size:11px;flex:none}.rea-ghost:disabled,.rea-primary:disabled{opacity:.55;cursor:wait}.rea-alert{background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 13%,transparent);color:var(--dsw-alias-state-error-primary);border-radius:7px;padding:9px 11px;margin-bottom:12px;word-break:break-word}.rea-loading{color:var(--dsw-alias-label-secondary);padding:28px 0}.rea-section{border-top:1px solid var(--dsw-alias-border-l1);padding:16px 0}.rea-section h3{font-size:12px;font-weight:600;color:var(--dsw-alias-label-secondary);margin:0 0 10px;text-transform:uppercase;letter-spacing:.04em}.rea-status-row{display:flex;align-items:center;gap:8px;min-height:32px}.rea-status-label{display:flex;align-items:center;gap:8px;min-width:145px}.rea-status-detail{color:var(--dsw-alias-label-secondary);font-size:12px;flex:1}.rea-dot{width:8px;height:8px;border-radius:50%;display:inline-block;background:var(--dsw-alias-state-warning-primary)}.rea-dot.rea-ok{background:var(--dsw-alias-state-success-primary)}.rea-dot.rea-error{background:var(--dsw-alias-state-error-primary)}.rea-dot.rea-busy{background:var(--dsw-alias-brand-primary);animation:rea-pulse 1.2s ease-in-out infinite}.rea-badge{font-size:11px;padding:2px 6px;border-radius:5px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-secondary)}.rea-progress-wrap{margin:8px 0 2px 153px}.rea-progress-label{font-size:11px;color:var(--dsw-alias-label-secondary);margin:5px 0}.rea-progress{height:5px;border-radius:5px;background:var(--dsw-alias-bg-layer-2);overflow:hidden}.rea-progress>div{height:100%;background:var(--dsw-alias-brand-primary);transition:width .3s}.rea-path{font:11px ui-monospace,Consolas,monospace;color:var(--dsw-alias-label-secondary);word-break:break-all;margin:6px 0 0 153px}.rea-hint,.rea-footnote{color:var(--dsw-alias-label-secondary);font-size:11px;margin:10px 0 0}.rea-hint{margin-left:153px}.rea-path-form{display:flex;flex-direction:column;gap:7px}.rea-path-field{display:flex;align-items:center;gap:8px}.rea-path-field span{width:145px;flex:none;color:var(--dsw-alias-label-secondary);font-size:11px}.rea-path-field input{min-width:0;flex:1;height:28px;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l1);border-radius:6px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);padding:0 8px;font:11px ui-monospace,Consolas,monospace}.rea-path-form>.rea-primary{align-self:flex-start}.rea-path-form{display:flex;flex-direction:column;gap:7px}.rea-path-field{display:flex;align-items:center;gap:8px}.rea-path-field span{width:145px;flex:none;color:var(--dsw-alias-label-secondary);font-size:11px}.rea-path-field input{min-width:0;flex:1;height:28px;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l1);border-radius:6px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);padding:0 8px;font:11px ui-monospace,Consolas,monospace}.rea-path-form>.rea-primary{align-self:flex-start}.rea-tool-progress{height:3px;flex:1;min-width:40px;background:var(--dsw-alias-bg-layer-2);border-radius:3px;overflow:hidden}.rea-tool-progress>div{height:100%;background:var(--dsw-alias-brand-primary);transition:width .3s}.rea-external-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}.rea-external{display:flex;align-items:center;gap:7px;padding:8px 9px;border:1px solid var(--dsw-alias-border-l1);border-radius:7px;color:var(--dsw-alias-label-primary)}.rea-external small{margin-left:auto;color:var(--dsw-alias-label-secondary);font-size:10px}@keyframes rea-pulse{50%{opacity:.35}}`;
    const policyCss = `.rea-policy{display:flex;flex-direction:column;gap:6px}.rea-policy-row{display:flex;align-items:center;gap:10px;min-height:30px}.rea-policy-row .rea-status-label{width:145px;flex:none;display:flex;align-items:center;gap:8px}.rea-policy-control{flex:1;display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-width:0}.rea-policy-number{width:76px;height:28px;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l1);border-radius:6px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);padding:0 8px}.rea-seg{display:inline-flex;height:28px;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l1);border-radius:7px;overflow:hidden}.rea-seg-item{border:none;border-right:1px solid var(--dsw-alias-border-l1);background:none;color:var(--dsw-alias-label-secondary);font:12px system-ui,sans-serif;padding:0 11px;cursor:pointer}.rea-seg-item:last-child{border-right:none}.rea-seg-item:disabled{opacity:.55;cursor:wait}.rea-seg-on{background:color-mix(in srgb,var(--dsw-alias-brand-primary) 18%,transparent);color:var(--dsw-alias-label-primary);font-weight:600}.rea-switch{display:inline-flex;align-items:center;gap:8px;border:none;background:none;padding:0;cursor:pointer;color:var(--dsw-alias-label-secondary);font:12px/18px system-ui,sans-serif}.rea-switch-track{position:relative;width:34px;height:18px;box-sizing:border-box;border-radius:9px;border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-2);transition:background .15s,border-color .15s;flex:none}.rea-switch-knob{position:absolute;top:1px;left:1px;width:14px;height:14px;border-radius:50%;background:var(--dsw-alias-label-secondary);transition:transform .15s,background .15s}.rea-switch-on{color:var(--dsw-alias-label-primary)}.rea-switch-on .rea-switch-track{background:color-mix(in srgb,var(--dsw-alias-brand-primary) 26%,transparent);border-color:var(--dsw-alias-brand-primary)}.rea-switch-on .rea-switch-knob{transform:translateX(16px);background:var(--dsw-alias-brand-primary)}.rea-switch:disabled{opacity:.55;cursor:wait}.rea-dot.rea-off{background:var(--dsw-alias-border-l1,#6b7280)}.rea-policy-note{color:var(--dsw-alias-label-secondary);font-size:11px;margin:0}.rea-scope{display:flex;flex-wrap:wrap;gap:6px;align-items:center;width:100%;min-height:28px}.rea-scope-empty{color:var(--dsw-alias-label-secondary);font-size:12px}.rea-scope-chip{display:inline-flex;align-items:center;gap:6px;max-width:100%;height:28px;box-sizing:border-box;padding:0 4px 0 8px;border:1px solid var(--dsw-alias-border-l1);border-radius:6px;background:var(--dsw-alias-bg-layer-1)}.rea-scope-path{font:11px ui-monospace,Consolas,monospace;color:var(--dsw-alias-label-primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:300px}.rea-scope-x{border:none;background:none;color:var(--dsw-alias-label-secondary);cursor:pointer;font-size:13px;line-height:1;padding:0 2px}.rea-scope-x:hover{color:var(--dsw-alias-state-error-primary)}.rea-browser{width:100%;margin-top:2px;border:1px solid var(--dsw-alias-border-l1);border-radius:8px;padding:8px;background:var(--dsw-alias-bg-layer-1)}.rea-browser-bar{display:flex;align-items:center;gap:8px;margin-bottom:6px}.rea-browser-path{flex:1;min-width:0;font:11px ui-monospace,Consolas,monospace;color:var(--dsw-alias-label-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.rea-browser-list{max-height:190px;overflow:auto;display:flex;flex-direction:column;border:1px solid var(--dsw-alias-border-l1);border-radius:6px}.rea-browser-entry{text-align:left;border:none;border-bottom:1px solid var(--dsw-alias-border-l1);background:none;color:var(--dsw-alias-label-primary);padding:5px 8px;font:12px system-ui,sans-serif;cursor:pointer}.rea-browser-entry:last-child{border-bottom:none}.rea-browser-entry:hover{background:var(--dsw-alias-bg-layer-2)}.rea-browser-actions{display:flex;gap:8px;margin-top:8px}.rea-browser-actions .rea-primary{margin-top:0}.rea-policy-actions{display:flex;align-items:center;gap:10px;margin-top:10px}.rea-policy-actions .rea-primary{margin-top:0}`;
    const extraCss = `.rea-mirror-log{margin-top:9px;border:1px solid var(--dsw-alias-border-l1);border-radius:7px;padding:8px 10px}.rea-mirror-log-title{font-size:11px;color:var(--dsw-alias-label-secondary);margin-bottom:5px}.rea-mirror-row{display:flex;justify-content:space-between;gap:10px;font-size:11px;padding:2px 0;word-break:break-word}.rea-mirror-row small{color:var(--dsw-alias-label-secondary);text-align:right;max-width:65%}.rea-mirror-ok span{color:var(--dsw-alias-state-success-primary)}.rea-mirror-fail span{color:var(--dsw-alias-state-error-primary)}`;
    return {
      inject: ['slots', 'locale'],
      // The panel has no DOM harness in this repository, so the two pure
      // components are exposed for tests that assert the controls exist and
      // report the value the person actually clicked.
      __test: { PolicySection, Toggle, ScopePicker, styles: css + extraCss + policyCss },
      apply(ctx) {
        ctx.effect(() => ctx.locale.register(NS, dicts), 'dsh-rea: dictionaries');
        ctx.effect(() => { const style = document.createElement('style'); style.dataset.plugin = PLUGIN_ID; style.textContent = css + extraCss + policyCss; document.head.appendChild(style); return () => style.remove(); }, 'dsh-rea: styles');
        const t = ctx.locale.bind(NS);
        const panelId = 'rea';
        ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({ name: 'sidebar.panellist', id: panelId, order: 85, label: () => t('title') }, ({ size, active }) => lensIcon(size, active)));
        ctx.slots.inject('main', () => ctx.slots.register({ name: 'main', key: panelId, inject: () => ({ t }) }, () => h(Panel, { t })));
      },
    };
  },
});







