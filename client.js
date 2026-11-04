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
        ghidra: 'Ghidra', ghidraReady: '函数级反编译可用', ghidraMissing: '需要 Ghidra 12.1.4',
        configured: '已发现', cached: '插件缓存',         install: '准备 Ghidra', installing: '下载并解包中…',         installHint: '首次准备需要下载约 543 MB，校验后解包到 DSH 主目录。',
        download: '下载', extract: '解包', path: '路径',         external: '其他外部工具', jadx: 'JADX', apktool: 'Apktool', wabt: 'WABT', rizin: 'Kuna/Rizin',
        configuredYes: '已配置', configuredNo: '未配置', nativeHint: 'Ghidra 只在真正调用 native 函数分析时使用。',
        noNetwork: '下载需要网络；失败时不会修改已有安装。', pathConfig: '外部工具路径', save: '保存路径', saved: '已保存', pathPlaceholder: '绝对路径（可留空）', prepareTool: '准备', cannotPrepare: '无自动安装包，请填写路径。', manualRizin: 'Kuna/Rizin 需要你自行安装，在下方填写可执行文件的绝对路径。', updateTitle: '版本更新', updateCurrent: '当前版本', updateLatest: '最新版本', checkUpdate: '检查更新', checkingUpdate: '检查中…', upToDate: '已是最新版本', updateAvailable: '有新版本可下载', installUpdate: '下载并安装', installingUpdate: '下载安装中…', updateRestart: '安装完成，重启会话后生效。', updateSource: '来源', updateMirror: '镜像', updateMirrorsTried: '镜像尝试', updatePinned: '已钉死摘要', updateBackups: '备份保留', updateTrust: '生效信任级别', trustNone: '无独立校验（摘要与归档同源）', trustPin: '本地钉死摘要', trustSignature: '清单签名验签', trustBoth: '签名 + 钉死摘要', policyTitle: '安全策略', policyScope: '授权目标范围', policyUnrestricted: '未限制', policyDevices: '设备写操作', policySensitive: '敏感产物', policyRetention: '产物保留', policyOn: '开启', policyOff: '关闭', policyDays: '天',
      },
      en: {
        title: 'Reverse Engineering', subtitle: 'Environment and engines', refresh: 'Refresh', loading: 'Reading environment…',
        preparing: 'Preparing', error: 'Failed',
        reaRuntime: 'Runtime', runtimeReady: 'Unpacked', runtimeMissing: 'Not ready',
        java: 'Java / JDK', jdkReady: 'Full JDK ready', jdkMissing: '64-bit full JDK required',
        ghidra: 'Ghidra', ghidraReady: 'Function decompilation available', ghidraMissing: 'Ghidra 12.1.4 required',
        configured: 'Detected', cached: 'Plugin cache',         install: 'Prepare Ghidra', installing: 'Downloading and extracting…',         installHint: 'First preparation downloads about 543 MB and extracts it into the DSH home.',
        download: 'Download', extract: 'Extract', path: 'Path',         external: 'Other external tools', jadx: 'JADX', apktool: 'Apktool', wabt: 'WABT', rizin: 'Kuna/Rizin',
        configuredYes: 'Configured', configuredNo: 'Not configured', nativeHint: 'Ghidra is used only when a native function analysis is actually called.',
        noNetwork: 'Downloading requires network access; an existing installation is not changed on failure.', pathConfig: 'External tool paths', save: 'Save paths', saved: 'Saved', pathPlaceholder: 'Absolute path (optional)', prepareTool: 'Prepare', cannotPrepare: 'No automatic package; enter a path.', manualRizin: 'Kuna/Rizin must be installed by you; enter the absolute path below.', updateTitle: 'Updates', updateCurrent: 'Installed', updateLatest: 'Latest', checkUpdate: 'Check for updates', checkingUpdate: 'Checking…', upToDate: 'Up to date', updateAvailable: 'Update available', installUpdate: 'Download and install', installingUpdate: 'Downloading…', updateRestart: 'Installed. Restart the session to load it.', updateSource: 'Source', updateMirror: 'Mirror', updateMirrorsTried: 'Mirror attempts', updatePinned: 'Pinned digest', updateBackups: 'Backups kept', updateTrust: 'Effective trust', trustNone: 'no independent check (digest shares the asset origin)', trustPin: 'locally pinned digest', trustSignature: 'signed manifest', trustBoth: 'signature + pinned digest', policyTitle: 'Security policy', policyScope: 'Authorized target roots', policyUnrestricted: 'unrestricted', policyDevices: 'Device mutations', policySensitive: 'Sensitive artifacts', policyRetention: 'Artifact retention', policyOn: 'on', policyOff: 'off', policyDays: 'd',
      },
    };
    function api(path) { const u = new URL(path, document.baseURI); u.hash = ''; return u.pathname + u.search; }
    async function getStatus() { const r = await fetch(api('/rea/environment'), { cache: 'no-store' }); const j = await r.json(); if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }
    async function installGhidra() { const r = await fetch(api('/rea/ghidra/install'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }); const j = await r.json(); if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; }
    async function saveConfig(paths) { const r = await fetch(api('/rea/engine/config'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(paths) }); const j = await r.json(); if (!r.ok || j.ok === false) throw new Error(j.error || `HTTP ${r.status}`); return j; }
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
    function PolicySection({ t, status }) {
      const policy = status?.policy;
      if (!policy) return null;
      const yes = (value) => value ? t('policyOn') : t('policyOff');
      return h(Section, { title: t('policyTitle') },
        h(StatusRow, { label: t('policyScope'), state: policy.allowedTargets > 0 ? 'ok' : 'warn', detail: policy.allowedTargets > 0 ? `${policy.allowedTargets} roots` : t('policyUnrestricted') }),
        h(StatusRow, { label: t('policyDevices'), state: policy.allowDeviceMutations ? 'warn' : 'ok', detail: yes(policy.allowDeviceMutations) }),
        h(StatusRow, { label: t('policySensitive'), state: policy.sensitiveArtifacts ? 'ok' : 'warn', detail: yes(policy.sensitiveArtifacts) }),
        h(StatusRow, { label: t('policyRetention'), state: 'ok', detail: `${policy.artifactRetentionDays} ${t('policyDays')}` }),
      );
    }
    function Panel({ t }) {
      const [status, setStatus] = React.useState(null);
      const [busy, setBusy] = React.useState(false);
      const [error, setError] = React.useState('');
      const [paths, setPaths] = React.useState({});
      const [saved, setSaved] = React.useState(false);
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
      const editPaths = React.useCallback((updater) => { pathsTouched.current = true; setPaths(updater); }, []);
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
            h(StatusRow, { label: t('java'), state: java?.fullJdk ? 'ok' : 'warn', detail: java?.fullJdk ? `${t('jdkReady')} · ${java.version || ''}` : t('jdkMissing') }),
            h(StatusRow, { label: t('ghidra'), state: gh?.ready ? 'ok' : gh?.phase === 'error' ? 'error' : gh?.phase === 'downloading' || gh?.phase === 'extracting' ? 'busy' : 'warn', detail: gh?.ready ? `${t('ghidraReady')} · ${gh.version || ''}` : gh?.phase === 'downloading' || gh?.phase === 'extracting' ? t('preparing') : t('ghidraMissing'), extra: gh?.ready ? h('span', { className: 'rea-badge' }, gh.source === 'rea-engines-cache' ? t('cached') : t('configured')) : null }),
            gh?.phase === 'downloading' ? h('div', { className: 'rea-progress-wrap' }, h('div', { className: 'rea-progress-label' }, `${t('download')} · ${pct}%`), h('div', { className: 'rea-progress' }, h('div', { style: { width: `${pct}%` } }))) : null,
            gh?.phase === 'extracting' ? h('div', { className: 'rea-progress-label' }, t('extract')) : null,
            gh?.path ? h('div', { className: 'rea-path' }, `${t('path')}: ${gh.path}`) : null,
            !gh?.ready ? h(React.Fragment, null, h('p', { className: 'rea-hint' }, t('installHint')), h('button', { className: 'rea-primary', type: 'button', onClick: doInstall, disabled: busy || gh?.phase === 'downloading' || gh?.phase === 'extracting' }, busy ? t('installing') : t('install'))) : null,
            h('p', { className: 'rea-hint' }, t('nativeHint')),
          ),
          h(ExternalGrid, { t, status, busy, onPrepare: doTool }),
          h(PathForm, { t, paths, setPaths: editPaths, doSave, busy, saved }),
          h(PolicySection, { t, status }),
          h('div', { className: 'rea-footnote' }, t('noNetwork')),
        ),
      );
    }
    const css = `.rea-panel{height:100%;overflow:auto;box-sizing:border-box;padding:24px 28px;color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-base);font:13px/1.5 system-ui,sans-serif}.rea-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:22px}.rea-title{display:flex;align-items:center;gap:9px;font-size:18px;font-weight:650}.rea-subtitle{margin:4px 0 0 31px;color:var(--dsw-alias-label-secondary);font-size:12px}.rea-ghost,.rea-primary,.rea-config{border:1px solid var(--dsw-alias-border-l1);border-radius:7px;padding:6px 11px;background:var(--dsw-alias-button-elevated-fill,var(--dsw-alias-bg-layer-1));color:var(--dsw-alias-label-primary);cursor:pointer}.rea-primary{border-color:var(--dsw-alias-button-primary-fill,var(--dsw-alias-brand-primary));background:var(--dsw-alias-button-primary-fill,var(--dsw-alias-brand-primary));color:var(--dsw-alias-label-primary-foreground,#fff);font-weight:600;margin-top:7px}.rea-config{padding:4px 8px;font-size:11px;flex:none}.rea-ghost:disabled,.rea-primary:disabled{opacity:.55;cursor:wait}.rea-alert{background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 13%,transparent);color:var(--dsw-alias-state-error-primary);border-radius:7px;padding:9px 11px;margin-bottom:12px;word-break:break-word}.rea-loading{color:var(--dsw-alias-label-secondary);padding:28px 0}.rea-section{border-top:1px solid var(--dsw-alias-border-l1);padding:16px 0}.rea-section h3{font-size:12px;font-weight:600;color:var(--dsw-alias-label-secondary);margin:0 0 10px;text-transform:uppercase;letter-spacing:.04em}.rea-status-row{display:flex;align-items:center;gap:8px;min-height:32px}.rea-status-label{display:flex;align-items:center;gap:8px;min-width:145px}.rea-status-detail{color:var(--dsw-alias-label-secondary);font-size:12px;flex:1}.rea-dot{width:8px;height:8px;border-radius:50%;display:inline-block;background:var(--dsw-alias-state-warning-primary)}.rea-dot.rea-ok{background:var(--dsw-alias-state-success-primary)}.rea-dot.rea-error{background:var(--dsw-alias-state-error-primary)}.rea-dot.rea-busy{background:var(--dsw-alias-brand-primary);animation:rea-pulse 1.2s ease-in-out infinite}.rea-badge{font-size:11px;padding:2px 6px;border-radius:5px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-secondary)}.rea-progress-wrap{margin:8px 0 2px 153px}.rea-progress-label{font-size:11px;color:var(--dsw-alias-label-secondary);margin:5px 0}.rea-progress{height:5px;border-radius:5px;background:var(--dsw-alias-bg-layer-2);overflow:hidden}.rea-progress>div{height:100%;background:var(--dsw-alias-brand-primary);transition:width .3s}.rea-path{font:11px ui-monospace,Consolas,monospace;color:var(--dsw-alias-label-secondary);word-break:break-all;margin:6px 0 0 153px}.rea-hint,.rea-footnote{color:var(--dsw-alias-label-secondary);font-size:11px;margin:10px 0 0}.rea-hint{margin-left:153px}.rea-path-form{display:flex;flex-direction:column;gap:7px}.rea-path-field{display:flex;align-items:center;gap:8px}.rea-path-field span{width:145px;flex:none;color:var(--dsw-alias-label-secondary);font-size:11px}.rea-path-field input{min-width:0;flex:1;height:28px;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l1);border-radius:6px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);padding:0 8px;font:11px ui-monospace,Consolas,monospace}.rea-path-form>.rea-primary{align-self:flex-start}.rea-path-form{display:flex;flex-direction:column;gap:7px}.rea-path-field{display:flex;align-items:center;gap:8px}.rea-path-field span{width:145px;flex:none;color:var(--dsw-alias-label-secondary);font-size:11px}.rea-path-field input{min-width:0;flex:1;height:28px;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l1);border-radius:6px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);padding:0 8px;font:11px ui-monospace,Consolas,monospace}.rea-path-form>.rea-primary{align-self:flex-start}.rea-tool-progress{height:3px;flex:1;min-width:40px;background:var(--dsw-alias-bg-layer-2);border-radius:3px;overflow:hidden}.rea-tool-progress>div{height:100%;background:var(--dsw-alias-brand-primary);transition:width .3s}.rea-external-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}.rea-external{display:flex;align-items:center;gap:7px;padding:8px 9px;border:1px solid var(--dsw-alias-border-l1);border-radius:7px;color:var(--dsw-alias-label-primary)}.rea-external small{margin-left:auto;color:var(--dsw-alias-label-secondary);font-size:10px}@keyframes rea-pulse{50%{opacity:.35}}`;
    const extraCss = `.rea-mirror-log{margin-top:9px;border:1px solid var(--dsw-alias-border-l1);border-radius:7px;padding:8px 10px}.rea-mirror-log-title{font-size:11px;color:var(--dsw-alias-label-secondary);margin-bottom:5px}.rea-mirror-row{display:flex;justify-content:space-between;gap:10px;font-size:11px;padding:2px 0;word-break:break-word}.rea-mirror-row small{color:var(--dsw-alias-label-secondary);text-align:right;max-width:65%}.rea-mirror-ok span{color:var(--dsw-alias-state-success-primary)}.rea-mirror-fail span{color:var(--dsw-alias-state-error-primary)}`;
    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        ctx.effect(() => ctx.locale.register(NS, dicts), 'dsh-rea: dictionaries');
        ctx.effect(() => { const style = document.createElement('style'); style.dataset.plugin = PLUGIN_ID; style.textContent = css + extraCss; document.head.appendChild(style); return () => style.remove(); }, 'dsh-rea: styles');
        const t = ctx.locale.bind(NS);
        const panelId = 'rea';
        ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({ name: 'sidebar.panellist', id: panelId, order: 85, label: () => t('title') }, ({ size, active }) => lensIcon(size, active)));
        ctx.slots.inject('main', () => ctx.slots.register({ name: 'main', key: panelId, inject: () => ({ t }) }, () => h(Panel, { t })));
      },
    };
  },
});







