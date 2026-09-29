'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
if(path) { 

}
const { sendContactEmail } = require('./services/mailer');
const { verifyRecaptcha } = require('./services/recaptcha');
const { logConsent } = require('./services/logger');
const { sendToCRM } = require('./services/crm');

const app = express();
const PORT = process.env.PORT || 3000;

/* ==========================================================
   SEGURANÇA BÁSICA
   ========================================================== */
app.use(helmet({
  contentSecurityPolicy: false // ajuste conforme seu domínio
}));

app.set('trust proxy', 1);

// CORS restrito
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Permite requisições sem origin (Postman, curl) em dev
    if (!origin && process.env.NODE_ENV !== 'production') return callback(null, true);
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origem não permitida pelo CORS'));
  },
  methods: ['POST', 'GET', 'OPTIONS'],
  credentials: false
}));

app.use(express.json({ limit: '100kb' }));

/* ==========================================================
   RATE LIMIT — anti-spam
   ========================================================== */
const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 10,                   // 10 requisições por IP
  message: { success: false, message: 'Muitas requisições. Tente novamente em alguns minutos.' },
  standardHeaders: true,
  legacyHeaders: false
});

/* ==========================================================
   HEALTH CHECK
   ========================================================== */
app.get('/api/health', (req, res) => {
  res.json({ success: true, status: 'ok', timestamp: new Date().toISOString() });
});

/* ==========================================================
   ENDPOINT: /api/contato
   ========================================================== */
app.post('/api/contato', contactLimiter, async (req, res) => {
  const startTime = Date.now();
// Desenvolvimento local
const API_ENDPOINT = 'http://localhost:3000/api/contato';

// Produção (ajuste para o domínio real)
const API_ENDPOINT = 'https://api.alphasolucoes.com.br/api/contato';
  try {
    const {
      nome, email, whatsapp, empresa, investimento,
      mensagem, consentimento, timestamp, origem,
      utm, recaptchaToken
    } = req.body || {};

    /* ---------- Validação server-side ---------- */
    const errors = [];

    if (!nome || nome.trim().length < 3) errors.push('Nome inválido');
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push('E-mail inválido');
    if (!whatsapp || whatsapp.replace(/\D/g, '').length < 10) errors.push('WhatsApp inválido');
    if (!investimento) errors.push('Investimento não informado');
    if (consentimento !== true) errors.push('Consentimento LGPD obrigatório');

    if (errors.length) {
      return res.status(400).json({
        success: false,
        message: 'Dados inválidos.',
        errors
      });
    }

    /* ---------- reCAPTCHA ---------- */
    const recaptcha = await verifyRecaptcha(recaptchaToken, req.ip);
    if (!recaptcha.success) {
      return res.status(403).json({
        success: false,
        message: 'Falha na verificação anti-spam. Recarregue a página e tente novamente.',
        score: recaptcha.score
      });
    }

    /* ---------- IP anonimizado (LGPD) ---------- */
    const crypto = require('crypto');
    const ipHash = crypto
      .createHash('sha256')
      .update(String(req.ip) + (process.env.RECAPTCHA_SECRET_KEY || 'salt'))
      .digest('hex')
      .slice(0, 16);

    /* ---------- Payload ---------- */
    const payload = {
      nome: nome.trim(),
      email: email.trim().toLowerCase(),
      whatsapp: whatsapp.trim(),
      empresa: (empresa || '').trim(),
      investimento,
      mensagem: (mensagem || '').trim(),
      consentimento: true,
      origem: origem || req.headers.referer || '',
      utm: utm || {},
      ipHash,
      userAgent: req.headers['user-agent'] || '',
      timestamp: timestamp || new Date().toISOString(),
      recaptchaScore: recaptcha.score
    };

    /* ---------- Registra consentimento LGPD ---------- */
    await logConsent(payload);

    /* ---------- Envia e-mail ---------- */
    await sendContactEmail(payload);

    /* ---------- Envia para CRM (opcional) ---------- */
    if (process.env.CRM_WEBHOOK_URL) {
      try {
        await sendToCRM(payload);
      } catch (crmErr) {
        console.warn('⚠️ Falha no CRM (não bloqueia):', crmErr.message);
      }
    }

    /* ---------- Resposta ---------- */
    const elapsed = Date.now() - startTime;
    console.log(`✅ Lead recebido em ${elapsed}ms — ${payload.email}`);

    return res.json({
      success: true,
      message: 'Solicitação recebida com sucesso.',
      ipHash
    });

  } catch (err) {
    console.error('❌ Erro em /api/contato:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro interno. Tente novamente ou fale conosco pelo WhatsApp.'
    });
  }
});

/* ==========================================================
   SERVE O FRONT (opcional)
   ========================================================== */
app.use(express.static(path.join(__dirname, 'public')));

/* ==========================================================
   START
   ========================================================== */
app.listen(PORT, () => {
  console.log(`🚀 Alpha Soluções Backend rodando na porta ${PORT}`);
  console.log(`   Ambiente: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   Endpoint: http://localhost:${PORT}/api/contato`);
});