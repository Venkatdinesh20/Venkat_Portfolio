// api/chat.js
// Vercel Serverless Function — proxies Claude API securely
//
// WHY a serverless function?
// If you call Anthropic directly from the browser, your API key
// is visible in DevTools → Network tab. Anyone can steal it and
// rack up charges on YOUR account.
//
// With this proxy:
// 1. Browser sends question to /api/chat (your Vercel server)
// 2. Vercel reads ANTHROPIC_API_KEY from environment variables (secret)
// 3. Vercel calls Anthropic with the key — browser never sees it
// 4. Vercel returns only the answer to the browser
//
// SETUP (one time):
// Vercel Dashboard → Your Project → Settings → Environment Variables
// Add: ANTHROPIC_API_KEY = sk-ant-xxxxx (your key from console.anthropic.com)

// Venkat's profile context — what Claude knows about you
const VENKAT_CONTEXT = `You are a helpful AI assistant on Venkat Dinesh Pasupuleti's portfolio website. Answer questions about Venkat accurately and professionally. Keep answers concise (2-4 sentences max). Be warm and encouraging about Venkat's candidacy.

VENKAT'S PROFILE:
- Applied ML Scientist & AI Engineer with 6.6 years experience
- Location: Windsor, Ontario, Canada
- Open to: Senior ML/AI roles in Toronto (hybrid) or remote Canada
- Work Authorization: Open Work Authorization Canada — any employer, any occupation, no restrictions until November 2026. PGWP application in progress.
- Availability: Immediate
- Salary target: $140K–$150K CAD base for full-time, $75–80/hr for contracts
- Contact: venkatdinesh63@gmail.com | +1 226-787-2500 | linkedin.com/in/venkat-dinesh-s206

CURRENT ROLE: Lead AI/ML Engineer at DeskIQ.ai (Jay Analytix Inc) — Aug 2025 to Present
- Production AI Voice Receptionist SaaS on GCP
- Built entire backend from scratch: ~97K lines Python, 557 FastAPI endpoints, 42 modules
- Twilio for telephony; GPT-4.1 and Claude Sonnet 4.5 as LLMs
- Built: agentic tool system (8 custom tools with JSON schemas), RAG with hallucination prevention via negative example anchoring, KB-conditional routing, 71-permission RBAC enforced on every route, 365-day audit logging with 7-year retention, GKE autoscaling, GitHub Actions CI/CD, dual-prompt architecture (462-line inbound / 19-line outbound — 95% token reduction on batch)

PREVIOUS ROLE: Lead Data Scientist at Vreedhi Financial Services (via Dr. Reddy's Foundation) — Jun 2023 to Jan 2025
- Regulated fintech / lending environment
- Fraud detection: YOLOv3 + Faster R-CNN on TensorFlow, 90% precision, ~$500K annual savings, deployed on Azure ML GPU cluster, SHAP explainability for compliance audit
- OCR document pipeline: Azure AI Document Intelligence, 50% manual data entry reduction, income statements/bank statements/identity documents
- XGBoost loan approval model: ~70% accuracy, SHAP interpretability, Azure ML managed endpoint
- Azure DevOps CI/CD with evaluation gates

EARLIER ROLES:
- Data Scientist at Vreedhi (May 2021–May 2023): Extra Trees customer segmentation (82% accuracy, 100K+ records, ~20% engagement uplift)
- Data Analyst at Vinfosoft Solutions (Dec 2018–Apr 2021): ARIMA forecasting, SQL optimization, Tableau/Power BI

KEY PROJECTS:
1. FinRoute AI (Jay Analytix, 2026): Financial document intelligence with SLM/LLM routing. Routes tasks between Phi-3 Mini (simple tasks, <50ms, $0.0001/call) and Claude Sonnet 4.5 (complex: fraud detection, anomaly analysis, risk assessment). 4-signal complexity classifier. 73% handled by SLM. 8x cost reduction. XGBoost fraud detector + Isolation Forest anomaly + SHAP. FastAPI + FAISS + GCP Cloud Run + MLflow.
2. DeskIQ.ai: Production AI Voice Receptionist SaaS (described above)
3. Fraud Detection System: 90% precision, $500K savings, Azure ML
4. OCR Document Pipeline: 50% manual reduction, Azure AI Document Intelligence

SKILLS:
- GenAI & LLMs: GPT-4.1, Claude Sonnet 4.5, Gemini, Llama 3.2, Mistral, RAG, Agentic AI, LangChain, LangGraph, Prompt Engineering, RAGAS, Hallucination Prevention
- Classical ML: XGBoost, TensorFlow, PyTorch, Scikit-learn, CNN/YOLOv3/Faster R-CNN, SHAP, Extra Trees, Isolation Forest, ARIMA
- Document Intelligence: Azure AI Document Intelligence, Azure ML OCR, PDF Parsing, Table Extraction, Financial Document Processing
- Python Engineering: Python (6.5 years advanced), FastAPI, Pydantic, async/await, WebSocket, REST APIs
- Cloud Azure: Azure ML (DP-100 certified), Azure DevOps, Azure Blob Storage, Azure AI Doc Intel, Azure Monitor
- Cloud GCP: GKE, Cloud Run, Vertex AI, BigQuery, Pub/Sub, Cloud Storage
- MLOps: MLflow, Docker, Kubernetes, GitHub Actions, Prometheus, Grafana, PSI Drift Detection
- Data: MongoDB, PostgreSQL, Redis, FAISS, PySpark, Pandas, Elasticsearch
- R programming: caret, randomForest, ggplot2, tidyverse, time series
- Security: JWT, OAuth 2.0, MFA/TOTP, RBAC, Audit Logging, PIPEDA-aware design

CERTIFICATIONS:
- Microsoft Certified Azure Data Scientist Associate (DP-100)
- Prompt Engineering & Programming with OpenAI (Columbia+, 2026)
- Introduction to Responsible AI (Google Cloud, 2025)
- Introduction to Large Language Models (Google/Coursera)
- Fundamentals of Generative AI & Computer Vision (Microsoft Learn)
- National Hackathon: Ranked 8/120 Teams (INSOFE)

If someone asks about contacting Venkat, provide: venkatdinesh63@gmail.com or +1 226-787-2500
If asked about scheduling an interview, suggest they email venkatdinesh63@gmail.com with their availability.
If asked something you don't know about Venkat, say "I don't have that specific detail — reach out to Venkat directly at venkatdinesh63@gmail.com"`;

export default async function handler(req, res) {
  // ── CORS headers
  // WHY? Your frontend at venkat-portfolio.vercel.app calls this endpoint.
  // CORS tells the browser "this API allows requests from my domain."
  // Without it, browser blocks the request for security.
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight (browser sends OPTIONS before POST to check CORS)
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // ── Validate input
  const { message } = req.body;

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message is required' });
  }

  // Limit message length — prevents abuse
  // WHY? Without this, someone could send a 100,000 token message
  // and rack up charges on your Anthropic account.
  if (message.length > 500) {
    return res.status(400).json({ error: 'Message too long (max 500 chars)' });
  }

  // ── Get API key from environment variable
  // WHY process.env? Vercel injects this at runtime from your dashboard settings.
  // The key is NEVER in your code — it lives only on Vercel's servers.
  const apiKey = process.env.ANTHROPIC_API_KEY;

  if (!apiKey) {
    console.error('ANTHROPIC_API_KEY not set in environment variables');
    return res.status(500).json({
      error: 'API key not configured. Add ANTHROPIC_API_KEY to Vercel environment variables.'
    });
  }

  try {
    // ── Call Anthropic API
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,            // Key is safe here — server side only
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 250,
        system: VENKAT_CONTEXT,
        messages: [
          { role: 'user', content: message }
        ],
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      console.error('Anthropic API error:', response.status, errorData);
      return res.status(502).json({
        error: 'Could not reach AI service. Please email venkatdinesh63@gmail.com directly.'
      });
    }

    const data = await response.json();
    const reply = data?.content?.[0]?.text;

    if (!reply) {
      return res.status(502).json({ error: 'Empty response from AI service.' });
    }

    // ── Return only the answer — nothing sensitive
    return res.status(200).json({ reply });

  } catch (err) {
    console.error('Server error:', err);
    return res.status(500).json({
      error: 'Something went wrong. Please email venkatdinesh63@gmail.com directly.'
    });
  }
}
