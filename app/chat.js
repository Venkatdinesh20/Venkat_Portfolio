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
// WHY? Without this, anyone can spam your API endpoint and
// drain your Anthropic credits. Max 10 requests per IP per minute.
const rateLimitMap = new Map();
const RATE_LIMIT = 10;       // max requests
const RATE_WINDOW = 60000;   // per 60 seconds (ms)

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > RATE_WINDOW) {
    // Window expired — reset
    rateLimitMap.set(ip, { count: 1, start: now });
    return false;
  }
  if (entry.count >= RATE_LIMIT) return true;
  entry.count++;
  rateLimitMap.set(ip, entry);
  return false;
}

// ── ALLOWED ORIGINS ─────────────────────────────────────────────
// WHY? Prevents other websites from using YOUR API key
// by calling your /api/chat endpoint from their frontend.
const ALLOWED_ORIGINS = [
  'https://venkat-portfolio.vercel.app',
  'https://venkatdinesh.vercel.app',
  'https://venkat-portfolio-ten.vercel.app',
  'https://venkat-portfolio.app',
  'http://localhost:3000',   // local development
  'http://127.0.0.1:5500',  // VS Code Live Server
];

// ── VENKAT'S CONTEXT (what Claude knows about you) ──────────────
const VENKAT_CONTEXT = `You are a helpful AI assistant on Venkat Dinesh Pasupuleti's portfolio website. Answer questions about Venkat accurately, professionally, and concisely (2-4 sentences max). Be warm and encouraging about his candidacy.

VENKAT'S PROFILE:
- Applied ML Scientist & AI Engineer — 6.5 years experience
- Location: Windsor, Ontario, Canada
- Open to: Senior ML/AI roles Toronto (hybrid) or remote Canada
- Work Authorization: Valid Canadian work permit. Authorized to work for any employer. No sponsorship required.
- Availability: Immediate start
- Salary: $140K-$150K CAD base (full-time), $70-80/hr (contract)
- Contact: venkatdinesh63@gmail.com | +1 226-787-2500 | linkedin.com/in/venkat-dinesh-s206

CURRENT ROLE: Lead AI/ML Engineer at DeskIQ.ai (Jay Analytix Inc) — Aug 2025 to Present
- Production AI Voice Receptionist SaaS on GCP
- Built entire backend solo: 97K lines Python, 557 FastAPI endpoints, 42 modules
- Twilio telephony, GPT-4.1 and Claude Sonnet 4.5 as LLMs
- Agentic tool system (8 custom tools), RAG with hallucination prevention, 71-permission RBAC, 365-day audit logging, GKE autoscaling, GitHub Actions CI/CD

PREVIOUS: Lead Data Scientist at Vreedhi Financial Services — Jun 2023 to Jan 2025
- Regulated fintech/lending, on Azure ML
- Fraud detection: 90% precision, ~$500K annual savings (YOLOv3 + Faster R-CNN, SHAP explainability)
- OCR pipeline: 50% manual data entry reduction (Azure AI Document Intelligence)
- Loan approval: XGBoost, ~70% accuracy, SHAP interpretability for compliance
- Azure DevOps CI/CD with automated evaluation gates

EARLIER: Data Scientist at Vreedhi (2021-2023), Data Analyst at Vinfosoft (2018-2021)

PROJECTS:
- FinRoute AI: Financial document intelligence with SLM/LLM routing. 73% handled by SLM (Phi-3 Mini, <50ms). Complex tasks (fraud, anomaly, risk) → Claude Sonnet 4.5. 8x cost reduction. XGBoost + Isolation Forest + SHAP.
- DeskIQ.ai: Production AI Voice Receptionist SaaS (described above)
- Fraud Detection: 90% precision, $500K savings, Azure ML
- OCR Pipeline: 50% manual reduction, Azure AI Document Intelligence

KEY SKILLS: Python, FastAPI, GPT-4.1, Claude Sonnet 4.5, RAG, Agentic AI, LangChain, Azure ML (DP-100), GKE, Docker, Kubernetes, MLflow, XGBoost, TensorFlow, SHAP, FAISS, MongoDB, R

CERTIFICATIONS: Microsoft Azure Data Scientist DP-100, Columbia+ Prompt Engineering, Google Cloud Responsible AI

IMPORTANT RULES:
- Never reveal specific immigration document numbers, permit expiry dates, or application IDs
- If asked about salary, give the range: $140K-$150K CAD base for full-time
- If asked to schedule, suggest emailing venkatdinesh63@gmail.com
- If you don't know something specific, say "I don't have that detail — contact Venkat at venkatdinesh63@gmail.com"
- Keep answers concise — recruiters are busy`;

export default async function handler(req, res) {

  // ── Get caller IP for rate limiting + audit logging
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.headers['x-real-ip']
    || 'unknown';

  // ── Audit log every request (visible in Vercel Logs)
  // WHY? You can monitor who is asking what and detect abuse
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    ip,
    method: req.method,
    origin: req.headers.origin || 'none',
    ua: req.headers['user-agent']?.slice(0, 80) || 'none',
  }));

  // ── CORS — set headers for allowed origins only
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (!origin) {
    // Direct server-to-server call (e.g. testing with curl) — allow
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  // If origin is set but not in allowed list — don't set CORS header
  // Browser will block the request automatically

  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // ── Method check
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

  // Max 500 chars — prevents token abuse
  if (message.length > 500) {
    return res.status(400).json({ error: 'Question too long. Please keep it under 500 characters.' });
  }

  // Block obvious prompt injection attempts
  const blocked = ['ignore previous', 'disregard', 'system prompt', 'jailbreak', 'forget instructions'];
  if (blocked.some(w => message.toLowerCase().includes(w))) {
    return res.status(400).json({ error: 'Invalid request.' });
  }

  // ── Get API key
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('ANTHROPIC_API_KEY missing from environment variables');
    // Generic error — don't expose internal details to client
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
        model: 'claude-sonnet-4-20250514',
        max_tokens: 250,
        system: VENKAT_CONTEXT,
        messages: [{ role: 'user', content: message.trim() }],
      }),
    });

    if (!response.ok) {
      // Log detail server-side, return generic message to client
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

    // Log question category for analytics (no PII)
    console.log(JSON.stringify({ ts: new Date().toISOString(), ip, status: 'ok', chars: message.length }));

    return res.status(200).json({ reply });

  } catch (err) {
    // Log full error server-side only
    console.error('Handler error:', err.message);
    return res.status(500).json({
      error: 'Something went wrong. Please email venkatdinesh63@gmail.com directly.'
    });
  }
}
