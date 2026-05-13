/**
 * ╔═══════════════════════════════════════════════════════╗
 * ║           VORTEX SHIELD — Sistema de Defesa           ║
 * ║           Versão 1.0 · Produção · 2025                ║
 * ╚═══════════════════════════════════════════════════════╝
 *
 * 10 CAMADAS DE PROTEÇÃO:
 *  1. Frame Busting      — impede embedding em iframes
 *  2. Right-Click Block  — bloqueia menu de contexto
 *  3. Keyboard Shield    — bloqueia atalhos de cópia/inspeção
 *  4. DevTools Detector  — detecta e reage ao DevTools aberto
 *  5. Selection Guard    — desativa seleção de texto
 *  6. Print/Screenshot   — borrão no modo impressão/print
 *  7. Console Honeypot   — armadilha e limpeza do console
 *  8. Access Token Gate  — valida chave de compra única
 *  9. Watermark System   — marca d'água com dados do usuário
 * 10. Session Lock       — expira sessão após tempo definido
 *
 * CONFIGURAÇÃO:
 *  window.VORTEX_CONFIG antes de carregar este script.
 *
 * COMO USAR:
 *  <script>
 *    window.VORTEX_CONFIG = {
 *      productName: 'VORTEX Protocol',
 *      caktoCheckout: 'https://pay.cakto.com.br/SEU_LINK',
 *      sessionHours: 72,
 *      enableToken: true,
 *      enableWatermark: true,
 *      enableDevTools: true,
 *      watermarkOpacity: 0.045,
 *      onTokenValid: function(user){ ... },
 *      onTokenInvalid: function(){ ... },
 *    };
 *  </script>
 *  <script src="vortex-shield.js"></script>
 */

;(function(window, document){
  'use strict';

  // ─── CONFIGURAÇÃO PADRÃO ──────────────────────────────
  var CFG = Object.assign({
    productName:      'VORTEX Protocol',
    caktoCheckout:    '#',
    sessionHours:     72,
    enableToken:      true,
    enableWatermark:  true,
    enableDevTools:   true,
    enableKeyboard:   true,
    enableRightClick: true,
    enableSelection:  true,
    enablePrint:      true,
    enableFrameBust:  true,
    enableConsole:    true,
    watermarkOpacity: 0.045,
    tokenParam:       'vtk',
    storageKey:       'vtx_shield_session',
    tokenSalt:        'VTX2025SHIELD',
    onTokenValid:     null,
    onTokenInvalid:   null,
  }, window.VORTEX_CONFIG || {});

  // ─── ESTADO INTERNO ───────────────────────────────────
  var STATE = {
    devToolsOpen:   false,
    devToolsCount:  0,
    watermarkEl:    null,
    lockScreen:     null,
    currentUser:    null,
    sessionValid:   false,
    initialized:    false,
  };

  // ─── UTILS ────────────────────────────────────────────
  function ls_get(k){
    try{ return localStorage.getItem(k); }catch(e){ return null; }
  }
  function ls_set(k,v){
    try{ localStorage.setItem(k,v); }catch(e){}
  }
  function ls_del(k){
    try{ localStorage.removeItem(k); }catch(e){}
  }

  /* Hash simples FNV-1a 32bit para validar token */
  function fnv32(str){
    var h = 2166136261;
    for(var i=0;i<str.length;i++){
      h ^= str.charCodeAt(i);
      h = (h * 16777619) >>> 0;
    }
    return h.toString(16).toUpperCase();
  }

  /* Gera hash do token esperado com base no email + salt */
  function makeTokenHash(email){
    var raw = (email || '').toLowerCase().trim() + CFG.tokenSalt;
    return fnv32(raw);
  }

  /* Verifica se um token de acesso é válido */
  function validateToken(token){
    if(!token || token.length < 8) return null;
    // Formato esperado: BASE64(email):HASH
    try{
      var parts = atob(token).split('|');
      if(parts.length < 2) return null;
      var email = parts[0];
      var hash  = parts[1];
      if(fnv32(email + CFG.tokenSalt) === hash){
        return { email: email, token: token };
      }
    }catch(e){ return null; }
    return null;
  }

  /* Gera token para um email (use no painel admin) */
  function generateToken(email){
    var clean = email.toLowerCase().trim();
    var hash  = fnv32(clean + CFG.tokenSalt);
    return btoa(clean + '|' + hash);
  }
  window.VORTEX_ADMIN_generateToken = generateToken;

  // ─── LAYER 1: FRAME BUSTING ───────────────────────────
  function initFrameBust(){
    if(!CFG.enableFrameBust) return;
    if(window.top !== window.self){
      try{
        window.top.location.href = window.location.href;
      }catch(e){
        document.documentElement.style.display = 'none';
        document.write('<h1 style="font-family:sans-serif;padding:2rem;color:#c03a2a">Acesso não autorizado via iframe.</h1>');
      }
    }
    // X-Frame-Options via meta (ajuda em alguns browsers)
    var meta = document.createElement('meta');
    meta.httpEquiv = 'X-Frame-Options';
    meta.content   = 'DENY';
    document.head && document.head.appendChild(meta);
  }

  // ─── LAYER 2: RIGHT-CLICK BLOCK ───────────────────────
  function initRightClick(){
    if(!CFG.enableRightClick) return;
    document.addEventListener('contextmenu', function(e){
      e.preventDefault();
      e.stopPropagation();
      showToast('🔒 Conteúdo protegido — © VORTEX Protocol');
      return false;
    }, true);
  }

  // ─── LAYER 3: KEYBOARD SHIELD ─────────────────────────
  function initKeyboard(){
    if(!CFG.enableKeyboard) return;
    var BLOCKED = {
      // Atalhos de desenvolvedor / cópia de código
      'F12':        true,
      'ctrl+u':     true, // View Source
      'ctrl+s':     true, // Save
      'ctrl+a':     true, // Select All
      'ctrl+c':     true, // Copy
      'ctrl+p':     true, // Print
      'ctrl+shift+i': true, // DevTools Chrome
      'ctrl+shift+j': true, // Console Chrome
      'ctrl+shift+c': true, // Inspector Chrome
      'ctrl+shift+k': true, // Console Firefox
      'ctrl+shift+e': true, // Network Firefox
      'meta+u':     true, // View Source Mac
      'meta+s':     true, // Save Mac
      'meta+a':     true, // Select All Mac
      'meta+c':     true, // Copy Mac
      'meta+p':     true, // Print Mac
      'meta+shift+i': true,
      'meta+shift+j': true,
      'meta+shift+c': true,
    };

    document.addEventListener('keydown', function(e){
      var key   = (e.key || '').toLowerCase();
      var parts = [];
      if(e.ctrlKey  && key !== 'control')  parts.push('ctrl');
      if(e.metaKey  && key !== 'meta')     parts.push('meta');
      if(e.shiftKey && key !== 'shift')    parts.push('shift');
      if(e.altKey   && key !== 'alt')      parts.push('alt');
      parts.push(key);
      var combo = parts.join('+');

      if(BLOCKED[combo] || BLOCKED[key]){
        e.preventDefault();
        e.stopPropagation();
        showToast('🔒 Atalho bloqueado — conteúdo protegido');
        return false;
      }
    }, true);

    // PrintScreen específico (Windows)
    document.addEventListener('keyup', function(e){
      if(e.key === 'PrintScreen'){
        navigator.clipboard && navigator.clipboard.writeText('').catch(function(){});
        showToast('📸 Screenshot protegido — © ' + CFG.productName);
      }
    }, true);
  }

  // ─── LAYER 4: DEVTOOLS DETECTOR ───────────────────────
  function initDevTools(){
    if(!CFG.enableDevTools) return;

    // Método 1: Diferença de dimensão da janela
    function checkWindowSize(){
      var threshold = 160;
      var widthDiff  = window.outerWidth  - window.innerWidth;
      var heightDiff = window.outerHeight - window.innerHeight;
      return widthDiff > threshold || heightDiff > threshold;
    }

    // Método 2: toString override — DevTools formata objetos ao inspecionar
    var devObj = (function(){
      var isOpen = false;
      var o = { toString: function(){ isOpen = true; return ''; } };
      Object.defineProperty(o, 'isOpen', {get: function(){ return isOpen; }});
      return o;
    })();

    // Método 3: Timing do debugger
    function checkTiming(){
      var start = Date.now();
      // eslint-disable-next-line no-debugger
      debugger; // Pausa MUITO mais tempo quando DevTools está aberto
      return (Date.now() - start) > 200;
    }

    var devToolsCheckInterval = setInterval(function(){
      var bySize   = checkWindowSize();
      var byDebug  = false;
      try{ byDebug = checkTiming(); }catch(e){}

      if(bySize || byDebug){
        STATE.devToolsCount++;
        if(STATE.devToolsCount >= 2 && !STATE.devToolsOpen){
          STATE.devToolsOpen = true;
          onDevToolsDetected();
        }
      } else {
        STATE.devToolsCount = Math.max(0, STATE.devToolsCount - 1);
        if(STATE.devToolsOpen && STATE.devToolsCount === 0){
          STATE.devToolsOpen = false;
          onDevToolsClosed();
        }
      }
    }, 1000);

    window.addEventListener('devtoolschange', function(e){
      if(e.detail && e.detail.open) onDevToolsDetected();
    });
  }

  function onDevToolsDetected(){
    showLockScreen(
      '🔍 Ferramentas de desenvolvedor detectadas.',
      'O conteúdo do ' + CFG.productName + ' é protegido por direitos autorais.\n\nFeche as ferramentas de desenvolvedor para continuar.',
      false
    );
  }

  function onDevToolsClosed(){
    hideLockScreen();
  }

  // ─── LAYER 5: SELECTION GUARD ─────────────────────────
  function initSelection(){
    if(!CFG.enableSelection) return;

    // CSS via style injection
    var style = document.createElement('style');
    style.id  = 'vtx-shield-css';
    style.textContent = [
      '* {',
      '  -webkit-user-select: none !important;',
      '  -moz-user-select: none !important;',
      '  -ms-user-select: none !important;',
      '  user-select: none !important;',
      '  -webkit-touch-callout: none !important;',
      '}',
      'input, textarea {',
      '  -webkit-user-select: text !important;',
      '  user-select: text !important;',
      '}',
    ].join('\n');
    document.head && document.head.appendChild(style);

    document.addEventListener('selectstart', function(e){
      if(e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA'){
        e.preventDefault();
      }
    }, true);

    document.addEventListener('copy', function(e){
      e.clipboardData && e.clipboardData.setData('text/plain', '© ' + CFG.productName + ' — conteúdo protegido.');
      e.preventDefault();
    }, true);

    document.addEventListener('dragstart', function(e){
      e.preventDefault();
    }, true);
  }

  // ─── LAYER 6: PRINT / SCREENSHOT PROTECTION ───────────
  function initPrint(){
    if(!CFG.enablePrint) return;

    var printStyle = document.createElement('style');
    printStyle.textContent = [
      '@media print {',
      '  body * { visibility: hidden !important; }',
      '  body::after {',
      '    visibility: visible !important;',
      '    position: fixed !important;',
      '    display: flex !important;',
      '    align-items: center !important;',
      '    justify-content: center !important;',
      '    inset: 0 !important;',
      '    font-family: serif !important;',
      '    font-size: 24px !important;',
      '    text-align: center !important;',
      '    content: "© ' + CFG.productName + ' — Impressão não autorizada. Conteúdo protegido por direitos autorais." !important;',
      '    padding: 4rem !important;',
      '    color: #0a0a0a !important;',
      '    line-height: 1.6 !important;',
      '  }',
      '}',
    ].join('\n');
    document.head && document.head.appendChild(printStyle);

    window.addEventListener('beforeprint', function(){
      document.body.style.filter = 'blur(20px)';
      showToast('🖨️ Impressão bloqueada — © ' + CFG.productName);
    });

    window.addEventListener('afterprint', function(){
      document.body.style.filter = '';
    });
  }

  // ─── LAYER 7: CONSOLE HONEYPOT ────────────────────────
  function initConsole(){
    if(!CFG.enableConsole) return;

    // Limpa console periodicamente
    var clearInterval_ = setInterval(function(){
      try{ console.clear(); }catch(e){}
    }, 2000);

    // Exibe aviso persistente no console
    setTimeout(function(){
      try{
        console.log('%c⛔ STOP!', 'color:#c03a2a;font-size:40px;font-weight:bold;');
        console.log(
          '%cEste console é para uso de desenvolvedores.\n\nSe alguém te pediu para colar algo aqui, é um golpe.\n\n© ' + CFG.productName + ' — Acesso não autorizado.',
          'color:#333;font-size:14px;line-height:1.8'
        );
      }catch(e){}
    }, 500);

    // Trap: se alguém tentar acessar dados internos
    try{
      Object.defineProperty(console, '_commandLineAPI', {
        get: function(){
          throw new Error('VORTEX SHIELD: acesso ao console bloqueado.');
        }
      });
    }catch(e){}
  }

  // ─── LAYER 8: ACCESS TOKEN GATE ───────────────────────
  function initTokenGate(){
    if(!CFG.enableToken) return;

    // 1. Verifica URL param (?vtk=TOKEN)
    var urlParams = new URLSearchParams(window.location.search);
    var tokenFromUrl = urlParams.get(CFG.tokenParam);

    // 2. Verifica localStorage
    var storedSession = ls_get(CFG.storageKey);
    var session = null;
    try{ session = JSON.parse(storedSession); }catch(e){}

    // 3. Valida token da URL primeiro
    if(tokenFromUrl){
      var user = validateToken(tokenFromUrl);
      if(user){
        // Salva sessão
        var expiry = Date.now() + (CFG.sessionHours * 3600000);
        ls_set(CFG.storageKey, JSON.stringify({
          user: user,
          token: tokenFromUrl,
          expiry: expiry,
          created: Date.now()
        }));
        STATE.currentUser  = user;
        STATE.sessionValid = true;
        // Limpa token da URL (mais seguro)
        var cleanUrl = window.location.pathname + window.location.hash;
        window.history.replaceState({}, '', cleanUrl);
        onAccessGranted(user);
        return;
      }
    }

    // 4. Valida sessão salva
    if(session && session.user && session.expiry){
      if(Date.now() < session.expiry){
        STATE.currentUser  = session.user;
        STATE.sessionValid = true;
        // Renova sessão
        session.expiry = Date.now() + (CFG.sessionHours * 3600000);
        ls_set(CFG.storageKey, JSON.stringify(session));
        onAccessGranted(session.user);
        return;
      } else {
        // Sessão expirada
        ls_del(CFG.storageKey);
      }
    }

    // 5. Sem token válido — exibe paywall
    onAccessDenied();
  }

  function onAccessGranted(user){
    STATE.sessionValid = true;
    STATE.currentUser  = user;
    // Aplica watermark com dados do usuário
    if(CFG.enableWatermark){
      setTimeout(function(){ applyWatermark(user); }, 800);
    }
    if(typeof CFG.onTokenValid === 'function'){
      CFG.onTokenValid(user);
    }
    // Expõe info básica do usuário para o app
    window.VORTEX_USER = { email: user.email };
  }

  function onAccessDenied(){
    if(typeof CFG.onTokenInvalid === 'function'){
      CFG.onTokenInvalid();
      return;
    }
    // Comportamento padrão: exibe tela de acesso negado
    showPaywall();
  }

  // ─── LAYER 9: WATERMARK SYSTEM ────────────────────────
  function applyWatermark(user){
    if(!CFG.enableWatermark) return;
    // Remove watermark anterior
    var prev = document.getElementById('vtx-watermark');
    if(prev) prev.parentNode.removeChild(prev);

    var email = (user && user.email) ? user.email : '© VORTEX';
    var text  = '© ' + CFG.productName + ' · ' + email + ' · Licença Individual · Não reproduza';

    var wm = document.createElement('div');
    wm.id  = 'vtx-watermark';

    // Cria grid de texto em diagonal
    var rows = 8, cols = 5;
    var inner = '';
    for(var r = 0; r < rows; r++){
      for(var c = 0; c < cols; c++){
        inner += '<div style="display:inline-block;padding:60px 80px;white-space:nowrap;">' + text + '</div>';
      }
      inner += '<br>';
    }

    wm.innerHTML = inner;
    Object.assign(wm.style, {
      position:        'fixed',
      inset:           '0',
      zIndex:          '1000',
      pointerEvents:   'none',
      userSelect:      'none',
      WebkitUserSelect:'none',
      opacity:         String(CFG.watermarkOpacity),
      transform:       'rotate(-28deg)',
      transformOrigin: 'center center',
      fontSize:        '11px',
      fontFamily:      'monospace',
      fontWeight:      '600',
      color:           '#000000',
      letterSpacing:   '0.04em',
      lineHeight:      '1',
      overflow:        'hidden',
      whiteSpace:      'nowrap',
    });

    document.body && document.body.appendChild(wm);
    STATE.watermarkEl = wm;

    // Re-injeta watermark se for removido via DOM
    if(window.MutationObserver){
      var obs = new MutationObserver(function(){
        if(!document.getElementById('vtx-watermark') && STATE.sessionValid){
          applyWatermark(STATE.currentUser);
        }
      });
      obs.observe(document.body, { childList: true, subtree: false });
    }
  }

  // ─── LAYER 10: SESSION LOCK ───────────────────────────
  function initSessionLock(){
    // Verifica validade da sessão a cada 5 minutos
    setInterval(function(){
      if(!CFG.enableToken) return;
      var stored = ls_get(CFG.storageKey);
      if(!stored){
        if(STATE.sessionValid){
          STATE.sessionValid = false;
          showPaywall();
        }
        return;
      }
      try{
        var s = JSON.parse(stored);
        if(Date.now() >= s.expiry){
          ls_del(CFG.storageKey);
          STATE.sessionValid = false;
          showPaywall();
        }
      }catch(e){
        ls_del(CFG.storageKey);
      }
    }, 5 * 60 * 1000);

    // Detecta abertura em nova aba/clone (tab-sharing attack)
    window.addEventListener('storage', function(e){
      if(e.key === CFG.storageKey && e.newValue === null){
        // Sessão foi removida em outra aba
        if(STATE.sessionValid){
          STATE.sessionValid = false;
          showLockScreen('🔒 Sessão encerrada.', 'Sua sessão foi encerrada em outro dispositivo. Faça login novamente.', true);
        }
      }
    });
  }

  // ─── UI HELPERS ───────────────────────────────────────

  /* Toast de notificação */
  var toastTimeout;
  function showToast(msg){
    var existing = document.getElementById('vtx-toast');
    if(existing) existing.parentNode.removeChild(existing);

    var t = document.createElement('div');
    t.id  = 'vtx-toast';
    t.textContent = msg;
    Object.assign(t.style, {
      position:      'fixed',
      bottom:        'calc(80px + env(safe-area-inset-bottom, 0px))',
      left:          '50%',
      transform:     'translateX(-50%)',
      background:    '#0f0f0c',
      color:         '#e8efec',
      padding:       '10px 20px',
      borderRadius:  '100px',
      fontSize:      '12px',
      fontFamily:    'system-ui, sans-serif',
      fontWeight:    '600',
      letterSpacing: '0.02em',
      zIndex:        '99999',
      whiteSpace:    'nowrap',
      border:        '1px solid rgba(255,255,255,0.12)',
      boxShadow:     '0 8px 24px rgba(0,0,0,0.4)',
      opacity:       '0',
      transition:    'opacity 0.2s ease',
      pointerEvents: 'none',
    });
    document.body && document.body.appendChild(t);
    requestAnimationFrame(function(){
      t.style.opacity = '1';
      clearTimeout(toastTimeout);
      toastTimeout = setTimeout(function(){
        t.style.opacity = '0';
        setTimeout(function(){ t.parentNode && t.parentNode.removeChild(t); }, 300);
      }, 3000);
    });
  }

  /* Tela de bloqueio (DevTools, cópia, etc.) */
  function showLockScreen(title, msg, canDismiss){
    if(STATE.lockScreen) return;

    var overlay = document.createElement('div');
    overlay.id  = 'vtx-lock';
    Object.assign(overlay.style, {
      position:       'fixed',
      inset:          '0',
      zIndex:         '99998',
      background:     'rgba(8,11,10,0.97)',
      backdropFilter: 'blur(16px)',
      display:        'flex',
      flexDirection:  'column',
      alignItems:     'center',
      justifyContent: 'center',
      padding:        '2rem',
      fontFamily:     'system-ui, sans-serif',
      textAlign:      'center',
    });
    overlay.innerHTML = [
      '<div style="font-size:48px;margin-bottom:1.5rem">🛡️</div>',
      '<div style="font-size:22px;font-weight:700;color:#e8efec;margin-bottom:.75rem">' + title + '</div>',
      '<div style="font-size:13px;color:#8fada6;line-height:1.8;max-width:340px;white-space:pre-line;margin-bottom:2rem">' + msg + '</div>',
      canDismiss
        ? '<button id="vtx-dismiss" style="background:#0ec494;color:#fff;border:none;border-radius:100px;padding:.75rem 2rem;font-size:13px;font-weight:700;cursor:pointer;font-family:inherit">Continuar</button>'
        : '<div style="font-size:11px;color:#4a6660;letter-spacing:0.1em;text-transform:uppercase">© ' + CFG.productName + ' — Conteúdo protegido</div>',
    ].join('');

    document.body && document.body.appendChild(overlay);
    STATE.lockScreen = overlay;

    if(canDismiss){
      var btn = document.getElementById('vtx-dismiss');
      btn && btn.addEventListener('click', function(){
        hideLockScreen();
      });
    }
  }

  function hideLockScreen(){
    if(STATE.lockScreen){
      STATE.lockScreen.parentNode && STATE.lockScreen.parentNode.removeChild(STATE.lockScreen);
      STATE.lockScreen = null;
    }
  }

  /* Tela de paywall (sem token válido) */
  function showPaywall(){
    var existing = document.getElementById('vtx-paywall');
    if(existing) return;

    // Oculta conteúdo principal
    var body = document.body;
    if(body){
      Array.prototype.forEach.call(body.children, function(child){
        if(child.id !== 'vtx-paywall') child.style.filter = 'blur(12px)';
      });
    }

    var pw = document.createElement('div');
    pw.id  = 'vtx-paywall';
    Object.assign(pw.style, {
      position:       'fixed',
      inset:          '0',
      zIndex:         '99997',
      background:     'rgba(8,11,10,0.96)',
      backdropFilter: 'blur(20px)',
      display:        'flex',
      flexDirection:  'column',
      alignItems:     'center',
      justifyContent: 'center',
      padding:        '2rem',
      fontFamily:     '"Syne", system-ui, sans-serif',
      textAlign:      'center',
    });
    pw.innerHTML = [
      '<div style="font-family:\'Cormorant Garamond\',serif;font-size:30px;font-weight:300;letter-spacing:.1em;color:#e8efec;margin-bottom:.5rem">VORTEX</div>',
      '<div style="font-size:9px;font-weight:700;letter-spacing:.22em;text-transform:uppercase;color:#0ec494;margin-bottom:2rem;border:1px solid rgba(14,196,148,0.3);padding:3px 12px;border-radius:100px;background:rgba(14,196,148,0.06)">Protocol · Conteúdo Protegido</div>',
      '<div style="font-size:48px;margin-bottom:1.5rem">🔒</div>',
      '<div style="font-size:20px;font-weight:700;color:#e8efec;margin-bottom:.75rem;max-width:300px;line-height:1.3">Acesso exclusivo para compradores</div>',
      '<div style="font-size:13px;color:#8fada6;line-height:1.85;max-width:320px;margin-bottom:2rem">Este conteúdo é protegido por direitos autorais e requer uma licença válida.<br><br>Se você já comprou, use o link de acesso enviado por email.</div>',
      '<a href="' + CFG.caktoCheckout + '" style="display:inline-flex;align-items:center;gap:.5rem;background:#0ec494;color:#fff;border:none;border-radius:100px;padding:.9rem 2rem;font-size:14px;font-weight:800;cursor:pointer;text-decoration:none;font-family:inherit;letter-spacing:.03em;transition:all .2s">🚀 Adquirir acesso — R$30</a>',
      '<div style="margin-top:1rem;font-size:11px;color:#4a6660">Garantia de 7 dias · Acesso imediato após pagamento</div>',
      '<div style="margin-top:2.5rem;font-size:10px;color:#2a3d3a;letter-spacing:.1em;text-transform:uppercase;font-family:monospace">© 2025 ' + CFG.productName + ' · Todos os direitos reservados</div>',
    ].join('');

    document.body && document.body.appendChild(pw);
  }

  // ─── INICIALIZAÇÃO ────────────────────────────────────
  function init(){
    if(STATE.initialized) return;
    STATE.initialized = true;

    initFrameBust();
    initRightClick();
    initKeyboard();
    initSelection();
    initPrint();

    if(document.readyState === 'loading'){
      document.addEventListener('DOMContentLoaded', function(){
        initConsole();
        if(CFG.enableToken) initTokenGate();
        if(CFG.enableToken) initSessionLock();
        if(CFG.enableDevTools) setTimeout(initDevTools, 800);
      });
    } else {
      initConsole();
      if(CFG.enableToken) initTokenGate();
      if(CFG.enableToken) initSessionLock();
      if(CFG.enableDevTools) setTimeout(initDevTools, 800);
    }
  }

  // ─── API PÚBLICA ──────────────────────────────────────
  window.VORTEX_SHIELD = {
    version:       '1.0.0',
    generateToken: generateToken,
    validateToken: validateToken,
    getUser:       function(){ return STATE.currentUser; },
    isValid:       function(){ return STATE.sessionValid; },
    logout:        function(){
      ls_del(CFG.storageKey);
      STATE.sessionValid = false;
      STATE.currentUser  = null;
      showPaywall();
    },
    showToast:     showToast,
    lockScreen:    function(t,m){ showLockScreen(t,m,true); },
  };

  init();

})(window, document);
