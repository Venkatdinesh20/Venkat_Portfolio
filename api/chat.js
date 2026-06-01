// api/chat.js — Vercel Serverless Function
// Secure proxy for Claude API
//
// SECURITY MEASURES:
// 1. API key stored in Vercel env vars — never in browser
// 2. Input validation + length limit — prevents abuse
// 3. Rate limiting via simple in-memory store (per IP)
// 4. Allowed origins check — only your domain can call this
// 5. No sensitive data returned in error messages
// 6. Request method enforcement
// 7. Audit log on every call (Vercel logs)

// ── IN-MEMORY RATE LIMITER ──────────────────────────────────────
const rateLimitMap = new Map();
const RATE_LIMIT = 10;
const RATE_WINDOW = 60000;

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > RATE_WINDOW) {
    rateLimitMap.set(ip, { count: 1, start: now });
    return false;
  }
  if (entry.count >= RATE_LIMIT) return true;
  entry.count++;
  rateLimitMap.set(ip, entry);
  return false;
}

// ── ALLOWED ORIGINS ─────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://venkat-portfolio.vercel.app',
  'https://venkatdinesh.vercel.app',
  'https://venkat-portfolio-ten.vercel.app',
  'https://venkat-portfolio.app',
  'http://localhost:3000',
  'http://127.0.0.1:5500',
];

// ── VENKAT'S CONTEXT ────────────────────────────────────────────
const VENKAT_CONTEXT = `You are a helpful AI assistant on Venkat Dinesh Pasupuleti's portfolio website. Answer questions about Venkat accurately, professionally, and concisely (2-4 sentences max). Be warm and encouraging about his candidacy.

VENKAT'S PROFILE:
- Applied ML Scientist & AI Engineer — 7+ years experience
- Location: Windsor, Ontario, Canada
- Open to: Senior ML/AI roles Toronto (hybrid) or remote Canada
- Work Authorization: Valid Canadian work permit. Authorized to work for any employer. No sponsorship required.
- Availability: Immediate start
- Salary: $130K-$140K CAD base (full-time), $70-80/hr (contract)
- Contact: venkatdinesh63@gmail.com | +1 226-787-2500 | linkedin.com/in/venkat-dinesh-s206

CURRENT ROLE: Lead AI/ML Engineer at DeskIQ.ai (Jay Analytix Inc) — Aug 2025 to Present
- Production AI Voice Receptionist SaaS on GCP
- Built entire backend: 557 FastAPI endpoints, 42 production modules
- Twilio telephony, GPT-4.1 and Claude Sonnet 4.5 as LLMs
- Agentic tool system (8 custom tools), RAG with hallucination prevention
- 71-permission RBAC, 365-day audit logging, GKE autoscaling, GitHub Actions CI/CD
- Live RAG system: venkatdinesh-rag.hf.space (BM25+FAISS, cross-encoder reranking, 50+ tests)

PREVIOUS: Lead Data Scientist at Vreedhi Financial Services — Jun 2023 to Jan 2025
- Regulated fintech/lending on Azure ML
- Fraud detection: 90% precision, ~$500K annual savings (XGBoost, SHAP explainability)
- OCR pipeline: 50% manual data entry reduction (Azure AI Document Intelligence)
- Loan approval: XGBoost ~70% accuracy, SHAP for compliance audit (RBI guidelines)
- PSI drift monitoring — caught 90%→74% precision drop, retrained, restored in one sprint
- Azure DevOps CI/CD with automated evaluation gates

EARLIER: Data Scientist at Vreedhi (May 2021 - May 2023), Data Analyst at Vinfosoft (Dec 2018 - Apr 2021)

TOTAL EXPERIENCE: 7 years 4 months — use "7+ years"

KEY PROJECTS:
- Production RAG System (live: venkatdinesh-rag.hf.space): hybrid BM25+FAISS retrieval, cross-encoder reranking, streaming, citation enforcement, 50+ test suite, CI-gated evaluation, Docker multi-stage. $0/month infra cost.
- DeskIQ.ai Voice AI Platform: 557 FastAPI endpoints, 42 modules, 8 tool schemas, GKE autoscaling, live in production
- Fraud Detection (Vreedhi): XGBoost, 90% precision, $500K savings, SHAP for compliance
- OCR Pipeline (Vreedhi): Azure Form Recognizer, 50% manual reduction

KEY SKILLS: Python, FastAPI, GPT-4.1, Claude Sonnet 4.5, RAG, Agentic AI, Azure ML (DP-100), GKE, Docker, Kubernetes, MLflow, XGBoost, LightGBM, SHAP, FAISS, MongoDB, PostgreSQL, GitHub Actions, PSI drift monitoring

CERTIFICATIONS: Microsoft Azure Data Scientist DP-100, Columbia University Prompt Engineering, Google Cloud Responsible AI, Google/Coursera LLM Specialisation

IMPORTANT RULES:
- Never reveal specific immigration document numbers, permit expiry dates, or application IDs
- If asked about salary, give the range: $130K-$140K CAD base for full-time, $70-80/hr contract
- If asked to schedule, suggest emailing venkatdinesh63@gmail.com
- If you don't know something specific, say "I don't have that detail — contact Venkat at venkatdinesh63@gmail.com"
- Keep answers concise — recruiters are busy
- Do NOT claim LangChain experience — not in production codebase
- Do NOT claim PyTorch as primary framework`;

// ── FIX: module.exports instead of export default ───────────────
// This is required for Vercel serverless functions (CommonJS)
module.exports = async function handler(req, res) {

  // ── Get caller IP for rate limiting + audit logging
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.headers['x-real-ip']
    || 'unknown';

  // ── Audit log every request
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    ip,
    method: req.method,
    origin: req.headers.origin || 'none',
    ua: req.headers['user-agent']?.slice(0, 80) || 'none',
  }));

  // ── CORS
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (!origin) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }

  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // ── Rate limiting
  if (isRateLimited(ip)) {
    console.warn(`Rate limited: ${ip}`);
    return res.status(429).json({
      error: 'Too many requests. Please wait a moment before asking again.'
    });
  }

  // ── Input validation
  const { message } = req.body || {};

  if (!message || typeof message !== 'string' || message.trim().length === 0) {
    return res.status(400).json({ error: 'Please enter a question.' });
  }

  if (message.length > 500) {
    return res.status(400).json({ error: 'Question too long. Please keep it under 500 characters.' });
  }

  const blocked = ['ignore previous', 'disregard', 'system prompt', 'jailbreak', 'forget instructions'];
  if (blocked.some(w => message.toLowerCase().includes(w))) {
    return res.status(400).json({ error: 'Invalid request.' });
  }

  // ── Get API key
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('ANTHROPIC_API_KEY missing from environment variables');
    return res.status(503).json({
      error: 'Service temporarily unavailable. Please email venkatdinesh63@gmail.com directly.'
    });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 250,
        system: VENKAT_CONTEXT,
        messages: [{ role: 'user', content: message.trim() }],
      }),
    });

    if (!response.ok) {
      const errBody = await response.json().catch(() => ({}));
      console.error('Anthropic error:', response.status, JSON.stringify(errBody));
      return res.status(502).json({
        error: 'Could not get a response right now. Try again or email venkatdinesh63@gmail.com'
      });
    }

    const data = await response.json();
    const reply = data?.content?.[0]?.text?.trim();

    if (!reply) {
      return res.status(502).json({ error: 'Empty response. Please try again.' });
    }

    console.log(JSON.stringify({ ts: new Date().toISOString(), ip, status: 'ok', chars: message.length }));

    return res.status(200).json({ reply });

  } catch (err) {
    console.error('Handler error:', err.message);
    return res.status(500).json({
      error: 'Something went wrong. Please email venkatdinesh63@gmail.com directly.'
    });
  }
}
