"use client";

import { useState, useEffect, useRef } from "react";
import { ScanResult } from "./lib/types";

export default function Home() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const terminalRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalOutput]);

  const addOutput = (
    text: string,
    type: "info" | "success" | "error" | "warning" = "info"
  ) => {
    const colors = {
      info: "#e8e8e8",
      success: "#00ff00",
      error: "#ff0055",
      warning: "#8b5cf6",
    };
    setTerminalOutput((prev) => [
      ...prev,
      `<span style="color: ${colors[type]}">${text}</span>`,
    ]);
  };

  const startScan = async () => {
    if (!url) {
      addOutput("[ERROR] Please enter a valid URL", "error");
      return;
    }

    setScanning(true);
    setScanResult(null);
    setTerminalOutput([]);

    addOutput(
      "╔══════════════════════════════════════════════════════╗",
      "warning"
    );
    addOutput(
      "║            TEKTON VULNERABILITY SCANNER              ║",
      "warning"
    );
    addOutput(
      "╚══════════════════════════════════════════════════════╝",
      "warning"
    );
    addOutput("");
    addOutput(`[*] Target: ${url}`, "info");
    addOutput("[*] Initializing scan...", "info");

    try {
      // Lancer le scan
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const { scanId } = await response.json();
      addOutput(`[+] Scan ID: ${scanId}`, "success");
      addOutput("[*] Scan started successfully", "success");
      addOutput("");

      // Polling pour suivre la progression
      const interval = setInterval(async () => {
        const statusResponse = await fetch(`/api/scan/${scanId}`);
        const scan: ScanResult = await statusResponse.json();

        if (scan.currentStep) {
          addOutput(`[${scan.progress}%] ${scan.currentStep}`, "warning");
        }

        if (scan.status === "completed" || scan.status === "failed") {
          clearInterval(interval);
          setScanning(false);
          setScanResult(scan);

          if (scan.status === "completed") {
            addOutput("");
            addOutput(
              "═══════════════════ SCAN COMPLETED ═══════════════════",
              "success"
            );
            displayResults(scan);
          } else {
            addOutput("");
            addOutput("[!] Scan failed: " + scan.error, "error");
          }
        }
      }, 2000);
    } catch (error) {
      addOutput("[!] Error: " + (error as Error).message, "error");
      setScanning(false);
    }
  };

  const displayResults = (scan: ScanResult) => {
    addOutput("");

    // Ports
    if (scan.results.ports && scan.results.ports.length > 0) {
      addOutput("▼ OPEN PORTS", "warning");
      scan.results.ports.forEach((port) => {
        addOutput(`  ├─ Port ${port.port} (${port.service})`, "success");
      });
      addOutput("");
    }

    // Technologies
    if (scan.results.technologies && scan.results.technologies.length > 0) {
      addOutput("▼ TECHNOLOGIES DETECTED", "warning");
      scan.results.technologies.forEach((tech) => {
        const version = tech.version ? ` v${tech.version}` : "";
        addOutput(`  ├─ ${tech.name}${version} [${tech.category}]`, "info");
      });
      addOutput("");
    }
    //hidden Files
    if (scan.results.hiddenFiles && scan.results.hiddenFiles.length > 0) {
      addOutput("▼ EXPOSED HIDDEN FILES", "error");
      addOutput("");
      scan.results.hiddenFiles.forEach((file, index) => {
        const severityColor = {
          critical: "#ff0055",
          high: "#ff6b6b",
          medium: "#ffd93d",
          low: "#a0d2db",
        }[file.severity];

        addOutput(`  [${index + 1}] ${file.title}`, "error");
        addOutput(
          `      Severity: <span style="color: ${severityColor}; font-weight: bold">${file.severity.toUpperCase()}</span>`,
          "error"
        );
        addOutput(`Path: ${file.path}`, "warning");
        addOutput(`Description: ${file.description}`, "info");
        addOutput(`Evidence: ${file.evidence}`, "info");
        addOutput(`Recommendation: ${file.recommendation}`, "info");
        addOutput("");
      });
    } else {
      addOutput("[+] No HiddenFIles found!", "success");
    }

    // Vulnérabilités
    if (
      scan.results.vulnerabilities &&
      scan.results.vulnerabilities.length > 0
    ) {
      addOutput("▼ VULNERABILITIES FOUND", "error");
      addOutput("");
      scan.results.vulnerabilities.forEach((vuln, index) => {
        const severityColor = {
          critical: "#ff0055",
          high: "#ff6b6b",
          medium: "#ffd93d",
          low: "#a0d2db",
          info: "#e8e8e8",
        }[vuln.severity];

        addOutput(`  [${index + 1}] ${vuln.title}`, "error");
        addOutput(
          `      Severity: <span style="color: ${severityColor}; font-weight: bold">${vuln.severity.toUpperCase()}</span>`,
          "error"
        );
        addOutput(`      Type: ${vuln.type.toUpperCase()}`, "info");
        addOutput(`      Description: ${vuln.description}`, "info");
        if (vuln.location) {
          addOutput(`      Location: ${vuln.location}`, "info");
        }
        addOutput("");
      });
    } else {
      addOutput("[+] No vulnerabilities found!", "success");
    }

    addOutput(
      "═══════════════════════════════════════════════════════",
      "success"
    );
  };

  return (
    <div className="min-h-screen p-8 flex flex-col items-center justify-center">
      {/* Header */}
      <div className="w-full max-w-4xl mb-8 text-center">
        <h1 className="text-5xl font-bold mb-2 glow-purple">
          ╔══════════════════════════╗
        </h1>
        <h1 className="text-5xl font-bold mb-2 glow-purple">
          ║ TEKTON SCANNER ║
        </h1>
        <h1 className="text-5xl font-bold mb-4 glow-purple">
          ╚══════════════════════════╝
        </h1>
        <p className="text-sm opacity-70">
          Automated Web Vulnerability Scanner
        </p>
      </div>

      {/* Input Section */}
      <div className="w-full max-w-4xl mb-6">
        <div className="terminal-border p-6 bg-black/50 backdrop-blur">
          <label className="block mb-2 text-sm glow-purple">
            &gt; ENTER TARGET URL:
          </label>
          <div className="flex gap-4">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && !scanning && startScan()}
              placeholder="http://example.com"
              disabled={scanning}
              className="flex-1 bg-black border-2 border-purple-600 text-green-400 px-4 py-3
                       font-mono focus:outline-none focus:border-purple-400
                       disabled:opacity-50 disabled:cursor-not-allowed"
            />
            <button
              onClick={startScan}
              disabled={scanning || !url}
              className="px-8 py-3 bg-purple-600 hover:bg-purple-500 disabled:bg-gray-600
                       disabled:cursor-not-allowed border-2 border-purple-400
                       font-bold transition-all glow-purple"
            >
              {scanning ? "[SCANNING...]" : "[SCAN]"}
            </button>
          </div>
        </div>
      </div>

      {/* Terminal Output */}
      <div className="w-full max-w-4xl">
        <div className="terminal-border bg-black/80 backdrop-blur">
          {/* Terminal Header */}
          <div className="bg-purple-900/30 px-4 py-2 border-b-2 border-purple-600 flex items-center justify-between">
            <span className="text-sm glow-purple">TERMINAL OUTPUT</span>
            <div className="flex gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
            </div>
          </div>

          {/* Terminal Content */}
          <div
            ref={terminalRef}
            className="p-6 h-96 overflow-y-auto font-mono text-sm leading-relaxed"
          >
            {terminalOutput.length === 0 ? (
              <div className="text-gray-500 flex flex-col items-center justify-center h-full">
                <span className="text-6xl mb-4">⚡</span>
                <span>Waiting for scan to start...</span>
                <span className="text-xs mt-2 opacity-50">
                  Enter a URL and click [SCAN]
                </span>
              </div>
            ) : (
              terminalOutput.map((line, index) => (
                <div
                  key={index}
                  dangerouslySetInnerHTML={{ __html: line }}
                  className="mb-1"
                />
              ))
            )}
            {scanning && (
              <span className="inline-block w-2 h-4 bg-purple-500 animate-pulse ml-1"></span>
            )}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="mt-8 text-center text-xs opacity-50">
        <p>
          ⚠ For educational purposes only. Do not scan websites without
          permission.
        </p>
        <p className="mt-2">Master 2 - Cloud Computing Project</p>
      </div>
    </div>
  );
}
