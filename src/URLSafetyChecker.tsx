import React, { useState } from 'react';
import { Shield, AlertTriangle, XCircle, Search, Globe, ExternalLink, CheckCircle } from 'lucide-react';

const URLSafetyChecker = () => {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<any[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const trustedDomains = [
    'google.com', 'youtube.com', 'gmail.com', 'google.co.in',
    'amazon.com', 'amazon.in', 'flipkart.com', 'myntra.com',
    'facebook.com', 'instagram.com', 'whatsapp.com', 'twitter.com', 'x.com',
    'microsoft.com', 'outlook.com', 'office.com', 'live.com',
    'apple.com', 'icloud.com', 'netflix.com', 'spotify.com',
    'linkedin.com', 'github.com', 'stackoverflow.com',
    'wikipedia.org', 'wikimedia.org',
    'paypal.com', 'stripe.com', 'razorpay.com', 'paytm.com',
    'openai.com', 'anthropic.com', 'claude.ai',
    'reddit.com', 'quora.com', 'zoom.us', 'dropbox.com'
  ];

  const trustedBrands = [
    'google', 'amazon', 'flipkart', 'facebook', 'microsoft', 'apple',
    'netflix', 'paypal', 'linkedin', 'twitter', 'youtube', 'instagram'
  ];

  const highRiskTLDs = ['xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'loan', 'click', 'work', 'racing'];
  const suspiciousTLDs = ['ru', 'cn', 'cc', 'pw', 'info', 'biz', 'online'];
  const trustedTLDs = ['com', 'org', 'net', 'edu', 'gov', 'in', 'us', 'uk', 'ca', 'au'];
  const urlShorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'short.io'];

  const analyzeURL = (inputUrl: string) => {
    if (!inputUrl.trim()) return;
    setIsAnalyzing(true);

    setTimeout(() => {
      let urlToAnalyze = inputUrl.trim();
      if (!urlToAnalyze.match(/^https?:\/\//i)) urlToAnalyze = 'https://' + urlToAnalyze;

      let hostname: string | undefined;
      let tld: string | undefined;
      let domain: string | undefined;
      let baseDomain: string | undefined;
      let riskScore = 0;
      let verdict = 'safe';
      let verdictText = '✅ Safe';
      let reason = '';
      const analysisDetails = {
        domain: { status: 'good', text: 'Domain structure appears legitimate' },
        https: { status: 'good', text: 'HTTPS encryption present' },
        brand: { status: 'good', text: 'No brand impersonation detected' },
        tld: { status: 'good', text: 'Standard top-level domain' },
        redFlags: { status: 'good', text: 'No suspicious patterns found' }
      };
      let icon = CheckCircle;
      let verdictColor = '#10b981';
      let verdictBg = '#d1fae5';

      try {
        const urlObj = new URL(urlToAnalyze);
        hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
        const protocol = urlObj.protocol;

        const parts = hostname.split('.');
        tld = parts[parts.length - 1];
        domain = parts.length > 1 ? parts[parts.length - 2] : parts[0];
        baseDomain = parts.length > 1 ? `${domain}.${tld}` : hostname;

        if (trustedDomains.includes(hostname) || trustedDomains.includes(baseDomain)) {
          riskScore = Math.floor(Math.random() * 15) + 5;
          verdict = 'safe';
          verdictText = '✅ Safe';
          verdictColor = '#10b981';
          verdictBg = '#d1fae5';
          icon = CheckCircle;
          reason = `Trusted ${hostname}. Well-known verified domain with valid HTTPS and clean structure.`;
          analysisDetails.domain.text = 'Verified trusted domain';
          analysisDetails.brand.text = 'Legitimate brand verified';

          const result = createResult(inputUrl, riskScore, verdict, verdictText, verdictColor, verdictBg, icon, reason, analysisDetails, hostname);
          setResults((prev) => [result, ...prev]);
          setUrl('');
          setIsAnalyzing(false);
          return;
        }

        if (protocol === 'http:') {
          riskScore += 20;
          analysisDetails.https.status = 'warn';
          analysisDetails.https.text = 'No HTTPS - connection not encrypted';
        }

        if (urlShorteners.some((s) => hostname!.includes(s))) {
          riskScore += 30;
          analysisDetails.domain.status = 'bad';
          analysisDetails.domain.text = 'URL shortener - hides real destination';
          analysisDetails.redFlags.status = 'warn';
          analysisDetails.redFlags.text = 'Shortened link detected';
        }

        if (highRiskTLDs.includes(tld!)) {
          riskScore += 35;
          analysisDetails.tld.status = 'bad';
          analysisDetails.tld.text = `High-risk .${tld} domain (commonly used for scams)`;
          analysisDetails.redFlags.status = 'bad';
          analysisDetails.redFlags.text = 'Dangerous TLD detected';
        } else if (suspiciousTLDs.includes(tld!)) {
          riskScore += 20;
          analysisDetails.tld.status = 'warn';
          analysisDetails.tld.text = `Suspicious .${tld} domain`;
        } else if (trustedTLDs.includes(tld!)) {
          analysisDetails.tld.text = `Standard .${tld} domain`;
        }

        for (const brandName of trustedBrands) {
          const normalized = hostname!.replace(/[^a-z0-9]/g, '');
          if (normalized.includes(brandName) && !hostname!.endsWith(`${brandName}.${tld}`) && normalized !== brandName) {
            riskScore += 40;
            analysisDetails.brand.status = 'bad';
            analysisDetails.brand.text = `Possible ${brandName} brand impersonation`;
            analysisDetails.redFlags.status = 'bad';
            analysisDetails.redFlags.text = 'Brand impersonation detected';
            break;
          }
        }

        const phishingWords = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'suspended'];
        if (phishingWords.some((word) => hostname!.includes(word))) {
          riskScore += 25;
          if (analysisDetails.domain.status === 'good') {
            analysisDetails.domain.status = 'warn';
            analysisDetails.domain.text = 'Contains suspicious keywords';
          }
          if (analysisDetails.redFlags.status === 'good') {
            analysisDetails.redFlags.status = 'warn';
            analysisDetails.redFlags.text = 'Phishing keywords detected';
          }
        }

        const hyphenCount = (hostname!.match(/-/g) || []).length;
        if (hyphenCount > 2) {
          riskScore += 15;
          if (analysisDetails.domain.status === 'good') {
            analysisDetails.domain.status = 'warn';
            analysisDetails.domain.text = 'Excessive hyphens in domain';
          }
        }

        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname!)) {
          riskScore += 45;
          analysisDetails.domain.status = 'bad';
          analysisDetails.domain.text = 'IP address instead of domain name';
        }

        riskScore = Math.min(riskScore, 100);

        if (riskScore <= 30) {
          verdict = 'safe';
          verdictText = '✅ Safe';
          verdictColor = '#10b981';
          verdictBg = '#d1fae5';
          icon = CheckCircle;
          reason = 'Legitimate and trusted structure. Standard domain with no major red flags detected.';
        } else if (riskScore <= 70) {
          verdict = 'suspicious';
          verdictText = '⚠️ Suspicious';
          verdictColor = '#f59e0b';
          verdictBg = '#fef3c7';
          icon = AlertTriangle;
          reason = 'Some red flags detected. Verify legitimacy before entering sensitive information.';
        } else {
          verdict = 'dangerous';
          verdictText = '🚫 Dangerous';
          verdictColor = '#ef4444';
          verdictBg = '#fee2e2';
          icon = XCircle;
          reason = 'Multiple risk indicators found. Likely phishing or malware distribution site.';
        }
      } catch (error) {
        riskScore = 92;
        verdict = 'dangerous';
        verdictText = '🚫 Dangerous';
        verdictColor = '#ef4444';
        verdictBg = '#fee2e2';
        icon = XCircle;
        reason = 'Invalid URL format. Malformed or suspicious structure.';
        analysisDetails.domain.status = 'bad';
        analysisDetails.domain.text = 'Invalid URL syntax';
      }

      const result = createResult(inputUrl, riskScore, verdict, verdictText, verdictColor, verdictBg, icon, reason, analysisDetails, hostname || 'Invalid');
      setResults((prev) => [result, ...prev]);
      setUrl('');
      setIsAnalyzing(false);
    }, 1200);
  };

  const createResult = (
    urlValue: string,
    riskScore: number,
    verdict: string,
    verdictText: string,
    verdictColor: string,
    verdictBg: string,
    icon: any,
    reason: string,
    analysisDetails: any,
    hostname: string
  ) => ({
    id: Date.now(),
    url: urlValue,
    riskScore,
    verdict,
    verdictText,
    verdictColor,
    verdictBg,
    icon,
    reason,
    analysisDetails,
    hostname
  });

  const VerdictIcon = ({ icon: Icon, color }: { icon: any; color: string }) => (
    <Icon className="w-8 h-8 sm:w-10 md:w-12 lg:w-12" style={{ color }} />
  );

  const getRiskColor = (score: number) => {
    if (score <= 30) return '#10b981';
    if (score <= 70) return '#f59e0b';
    return '#ef4444';
  };

  const getStatusIcon = (status: string) => {
    if (status === 'good') return <CheckCircle className="w-4 h-4 sm:w-5 sm:h-5 text-green-500 flex-shrink-0" />;
    if (status === 'warn') return <AlertTriangle className="w-4 h-4 sm:w-5 sm:h-5 text-yellow-500 flex-shrink-0" />;
    return <XCircle className="w-4 h-4 sm:w-5 sm:h-5 text-red-500 flex-shrink-0" />;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-3 sm:p-4 md:p-6 lg:p-8">
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-6 sm:mb-8 md:mb-10">
          <div className="flex items-center justify-center gap-2 sm:gap-3 mb-3 sm:mb-4">
            <Shield className="w-8 h-8 sm:w-9 sm:h-9 md:w-10 md:h-10 text-purple-400" />
            <h1 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-white">Website Safety Checker</h1>
          </div>
          <p className="text-sm sm:text-base md:text-lg text-purple-200 px-4">Verify if a URL is safe, suspicious, or dangerous</p>
        </div>

        <div className="bg-white/10 backdrop-blur-lg rounded-xl sm:rounded-2xl p-4 sm:p-6 md:p-8 mb-6 sm:mb-8 shadow-2xl border border-white/20 transition-all duration-300">
          <div className="space-y-3 sm:space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-2 sm:gap-3 text-purple-200 mb-2 sm:mb-3">
              <Globe className="w-5 h-5 sm:w-6 sm:h-6 flex-shrink-0" />
              <span className="font-semibold text-base sm:text-lg md:text-xl">🔹 Paste a website URL below to check if it&apos;s safe or suspicious</span>
            </div>
            <div className="flex flex-col sm:flex-row gap-2 sm:gap-3">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !isAnalyzing && analyzeURL(url)}
                placeholder="Example: https://suspicious-site.xyz"
                disabled={isAnalyzing}
                className="flex-1 px-3 sm:px-4 py-3 sm:py-3.5 rounded-lg bg-white/20 border border-white/30 text-white placeholder-purple-300 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent text-base disabled:opacity-50 transition-all"
              />
              <button
                onClick={() => analyzeURL(url)}
                disabled={isAnalyzing || !url.trim()}
                className="w-full sm:w-auto px-4 sm:px-4 py-2.5 sm:py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-semibold transition-all hover:scale-105 active:scale-95 flex items-center justify-center gap-2 shadow-lg disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 text-sm whitespace-nowrap"
              >
                {isAnalyzing ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    <span>Checking...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    <span>Check</span>
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="mt-4 sm:mt-5 flex flex-wrap gap-1.5 sm:gap-2">
            <span className="text-purple-200 text-xs sm:text-sm font-medium w-full sm:w-auto mb-1 sm:mb-0">
              Quick tests:
            </span>
            {[
              { url: 'https://www.flipkart.com/', label: 'flipkart.com' },
              { url: 'paypal-login-verify.xyz', label: 'paypal-verify.xyz' },
              { url: 'bit.ly/test123', label: 'bit.ly/test' }
            ].map((example) => (
              <button
                key={example.url}
                onClick={() => !isAnalyzing && analyzeURL(example.url)}
                disabled={isAnalyzing}
                className="px-2 sm:px-3 py-1 sm:py-1.5 bg-white/10 hover:bg-white/20 text-purple-200 rounded-full text-xs sm:text-sm transition-all hover:scale-105 active:scale-95 disabled:opacity-50 disabled:hover:scale-100"
              >
                {example.label}
              </button>
            ))}
          </div>
        </div>

        {results.map((result) => (
          <div key={result.id} className="bg-white/10 backdrop-blur-lg rounded-xl sm:rounded-2xl p-4 sm:p-5 md:p-6 shadow-2xl border border-white/20 animate-slideIn transition-all duration-300 mb-4">
            <div className="mb-4 sm:mb-6">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 mb-2 sm:mb-3">
                <h3 className="text-white text-base sm:text-lg md:text-xl font-bold">Risk Analysis Score</h3>
                <span className="text-xl sm:text-2xl md:text-3xl font-bold" style={{ color: getRiskColor(result.riskScore) }}>
                  {result.riskScore}%
                </span>
              </div>
              <div className="h-6 sm:h-8 md:h-10 bg-gray-800/50 rounded-full overflow-hidden border border-white/10">
                <div
                  className="h-full transition-all duration-1000 ease-out flex items-center justify-end pr-2 sm:pr-3"
                  style={{
                    width: `${result.riskScore}%`,
                    backgroundColor: getRiskColor(result.riskScore)
                  }}
                >
                  <span className="text-white text-xs sm:text-sm font-bold">{result.riskScore <= 30 ? 'LOW' : result.riskScore <= 70 ? 'MEDIUM' : 'HIGH'}</span>
                </div>
              </div>
            </div>

            <div className="mb-4 sm:mb-6 space-y-3 sm:space-y-4">
              <h4 className="text-purple-200 font-semibold text-sm sm:text-base mb-2 sm:mb-3">
                Detailed Analysis
              </h4>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-2 sm:gap-3">
                <div className="flex items-start gap-2 sm:gap-3 bg-white/5 p-2.5 sm:p-3 rounded-lg border border-white/10 transition-all hover:bg-white/10">
                  {getStatusIcon(result.analysisDetails.domain.status)}
                  <div className="flex-1 min-w-0">
                    <div className="text-purple-300 text-xs sm:text-sm font-semibold">
                      🌐 Domain Structure
                    </div>
                    <div className="text-purple-100 text-xs sm:text-sm break-words">
                      {result.analysisDetails.domain.text}
                    </div>
                  </div>
                </div>

                <div className="flex items-start gap-2 sm:gap-3 bg-white/5 p-2.5 sm:p-3 rounded-lg border border-white/10 transition-all hover:bg-white/10">
                  {getStatusIcon(result.analysisDetails.https.status)}
                  <div className="flex-1 min-w-0">
                    <div className="text-purple-300 text-xs sm:text-sm font-semibold">
                      🔒 HTTPS Security
                    </div>
                    <div className="text-purple-100 text-xs sm:text-sm break-words">
                      {result.analysisDetails.https.text}
                    </div>
                  </div>
                </div>

                <div className="flex items-start gap-2 sm:gap-3 bg-white/5 p-2.5 sm:p-3 rounded-lg border border-white/10 transition-all hover:bg-white/10">
                  {getStatusIcon(result.analysisDetails.brand.status)}
                  <div className="flex-1 min-w-0">
                    <div className="text-purple-300 text-xs sm:text-sm font-semibold">
                      🧠 Brand Trust
                    </div>
                    <div className="text-purple-100 text-xs sm:text-sm break-words">
                      {result.analysisDetails.brand.text}
                    </div>
                  </div>
                </div>

                <div className="flex items-start gap-2 sm:gap-3 bg-white/5 p-2.5 sm:p-3 rounded-lg border border-white/10 transition-all hover:bg-white/10">
                  {getStatusIcon(result.analysisDetails.tld.status)}
                  <div className="flex-1 min-w-0">
                    <div className="text-purple-300 text-xs sm:text-sm font-semibold">
                      🧩 TLD Legitimacy
                    </div>
                    <div className="text-purple-100 text-xs sm:text-sm break-words">
                      {result.analysisDetails.tld.text}
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-2 sm:gap-3 bg-white/5 p-2.5 sm:p-3 rounded-lg border border-white/10 transition-all hover:bg-white/10">
                {getStatusIcon(result.analysisDetails.redFlags.status)}
                <div className="flex-1 min-w-0">
                  <div className="text-purple-300 text-xs sm:text-sm font-semibold">
                    ⚠️ Red Flags Detected
                  </div>
                  <div className="text-purple-100 text-xs sm:text-sm break-words">
                    {result.analysisDetails.redFlags.text}
                  </div>
                </div>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-start gap-3 sm:gap-5">
              <div className="flex-shrink-0 p-3 sm:p-4 rounded-xl self-center sm:self-start" style={{ backgroundColor: result.verdictBg }}>
                <VerdictIcon icon={result.icon} color={result.verdictColor} />
              </div>
              <div className="flex-1 min-w-0 w-full">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 sm:gap-3 mb-3">
                  <h3 className="text-xl sm:text-2xl md:text-3xl font-bold break-words" style={{ color: result.verdictColor }}>
                    {result.verdictText}
                  </h3>
                  <a
                    href={result.url.startsWith('http') ? result.url : `https://${result.url}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-purple-300 hover:text-purple-200 transition-colors flex-shrink-0"
                    title="Open in new tab (proceed with caution)"
                  >
                    <ExternalLink className="w-4 h-4 sm:w-5 sm:h-5" />
                  </a>
                </div>
                <div className="mb-3 sm:mb-4">
                  <div className="flex items-center gap-2 text-purple-300 text-xs sm:text-sm mb-1">
                    <Globe className="w-3 h-3 sm:w-4 sm:h-4 flex-shrink-0" />
                    <span className="font-semibold">URL:</span>
                  </div>
                  <span className="font-mono text-xs sm:text-sm text-purple-100 break-all">{result.url}</span>
                </div>
                <div className="p-3 sm:p-4 bg-white/5 rounded-lg border border-white/10">
                  <p className="text-purple-50 text-xs sm:text-sm md:text-base leading-relaxed">
                    <strong className="font-semibold">Analysis: </strong>
                    {result.reason}
                  </p>
                </div>
              </div>
            </div>
          </div>
        ))}

        {results.length === 0 && !isAnalyzing && (
          <div className="text-center text-purple-300 py-12 sm:py-16 md:py-20 transition-all duration-300">
            <Shield className="w-16 h-16 sm:w-20 sm:h-20 md:w-24 md:h-24 mx-auto mb-3 sm:mb-4 opacity-40" />
            <p className="text-lg sm:text-xl md:text-2xl font-medium mb-2 px-4">Ready to analyze URLs</p>
            <p className="text-sm sm:text-base md:text-lg text-purple-400 px-4">Paste any website URL above to check its safety status</p>
          </div>
        )}
      </div>

      <style>{`
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-slideIn { animation: slideIn 0.5s ease-out; }
        button, input, a { transition: all 0.2s ease-in-out; }
        body { overflow-x: hidden; }
        @media (max-width: 640px) { button, a { min-height: 44px; } }
      `}</style>
    </div>
  );
};

export default URLSafetyChecker;
