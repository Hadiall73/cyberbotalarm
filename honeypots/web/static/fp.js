// Browser Fingerprinting + WebRTC IP Leak
(async () => {
  const data = {};

  // Basic info
  data.userAgent    = navigator.userAgent;
  data.language     = navigator.language;
  data.languages    = navigator.languages;
  data.platform     = navigator.platform;
  data.screen       = `${screen.width}x${screen.height}x${screen.colorDepth}`;
  data.timezone     = Intl.DateTimeFormat().resolvedOptions().timeZone;
  data.timezoneOffset = new Date().getTimezoneOffset();
  data.cookiesEnabled = navigator.cookieEnabled;
  data.doNotTrack   = navigator.doNotTrack;
  data.hardwareConcurrency = navigator.hardwareConcurrency;
  data.deviceMemory = navigator.deviceMemory || "?";
  data.touchPoints  = navigator.maxTouchPoints;
  data.plugins      = Array.from(navigator.plugins).map(p => p.name);

  // Canvas Fingerprint
  try {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    canvas.width = 300; canvas.height = 100;
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("CyberHoneypot🍯", 2, 15);
    ctx.fillStyle = "rgba(102,204,0,0.7)";
    ctx.fillText("CyberHoneypot🍯", 4, 45);
    data.canvasFingerprint = canvas.toDataURL().slice(-50);
  } catch(e) { data.canvasFingerprint = "blocked"; }

  // WebGL Fingerprint
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    const ext = gl.getExtension("WEBGL_debug_renderer_info");
    data.webglVendor   = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);
    data.webglRenderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
  } catch(e) { data.webglVendor = "?"; }

  // Font detection
  const testFonts = ["Arial","Courier New","Georgia","Times New Roman","Verdana","Comic Sans MS","Impact","Palatino","Tahoma","Trebuchet MS","Ubuntu","Roboto","Calibri"];
  const canvas2 = document.createElement("canvas");
  const ctx2 = canvas2.getContext("2d");
  data.fonts = testFonts.filter(font => {
    ctx2.font = `16px ${font}`;
    const w1 = ctx2.measureText("mmmmlli").width;
    ctx2.font = `16px monospace`;
    const w2 = ctx2.measureText("mmmmlli").width;
    return w1 !== w2;
  });

  // Audio fingerprint
  try {
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const oscillator = audioCtx.createOscillator();
    const analyser = audioCtx.createAnalyser();
    const gain = audioCtx.createGain();
    gain.gain.value = 0;
    oscillator.connect(analyser);
    analyser.connect(gain);
    gain.connect(audioCtx.destination);
    oscillator.start(0);
    const data32 = new Float32Array(analyser.frequencyBinCount);
    analyser.getFloatFrequencyData(data32);
    data.audioFingerprint = data32.slice(0,10).reduce((a,b) => a+b, 0).toFixed(4);
    oscillator.stop();
    await audioCtx.close();
  } catch(e) { data.audioFingerprint = "blocked"; }

  // WebRTC Real IP Leak
  const ips = [];
  try {
    const pc = new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"}]});
    pc.createDataChannel("");
    pc.onicecandidate = e => {
      if (!e.candidate) return;
      const m = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/g);
      if (m) m.forEach(ip => { if (!ips.includes(ip)) ips.push(ip); });
    };
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await new Promise(r => setTimeout(r, 2000));
    pc.close();
  } catch(e) {}
  data.webrtcIPs = ips;

  // Send everything to server
  fetch("/fp/collect", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(data),
  });
})();
