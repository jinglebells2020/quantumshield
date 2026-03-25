import * as vscode from 'vscode';
import { execFile } from 'child_process';
import * as path from 'path';

interface Finding {
    file_path: string;
    line_start: number;
    line_end: number;
    column_start: number;
    column_end: number;
    severity: number;
    algorithm: string;
    quantum_threat: number;
    description: string;
    replacement_algo: string;
    fix_diff: string;
    code_snippet: string;
    confidence: number;
}

interface ScanResult {
    findings: Finding[];
    summary: { total_findings: number; quantum_readiness: number };
}

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let lastScanResult: ScanResult | null = null;
let scanTimeout: NodeJS.Timeout | null = null;

export function activate(context: vscode.ExtensionContext) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('quantumshield');
    context.subscriptions.push(diagnosticCollection);

    // Status bar
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'quantumshield.scan';
    statusBarItem.text = '$(shield) QS: --/100';
    statusBarItem.tooltip = 'QuantumShield Quantum Readiness Score';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('quantumshield.scan', () => scanWorkspace()),
        vscode.commands.registerCommand('quantumshield.scanFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) scanFile(editor.document.uri);
        })
    );

    // Auto-scan on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((doc) => {
            const config = vscode.workspace.getConfiguration('quantumshield');
            if (config.get('autoScan', true)) {
                debouncedScan(doc.uri);
            }
        })
    );

    // CodeLens provider
    context.subscriptions.push(
        vscode.languages.registerCodeLensProvider(
            [{ scheme: 'file', language: 'go' }, { scheme: 'file', language: 'python' },
             { scheme: 'file', language: 'javascript' }, { scheme: 'file', language: 'typescript' },
             { scheme: 'file', language: 'java' }],
            new QuantumShieldCodeLensProvider()
        )
    );

    // Code action provider (quick fixes)
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            [{ scheme: 'file' }],
            new QuantumShieldCodeActionProvider(),
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        )
    );

    // Hover provider
    context.subscriptions.push(
        vscode.languages.registerHoverProvider(
            [{ scheme: 'file', language: 'go' }, { scheme: 'file', language: 'python' },
             { scheme: 'file', language: 'javascript' }, { scheme: 'file', language: 'java' }],
            new QuantumShieldHoverProvider()
        )
    );

    // Initial scan
    scanWorkspace();
}

function debouncedScan(uri: vscode.Uri) {
    if (scanTimeout) clearTimeout(scanTimeout);
    scanTimeout = setTimeout(() => scanFile(uri), 1000);
}

function getQSPath(): string {
    return vscode.workspace.getConfiguration('quantumshield').get('path', 'qs');
}

function scanWorkspace() {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders) return;

    const qsPath = getQSPath();
    const cwd = folders[0].uri.fsPath;

    statusBarItem.text = '$(loading~spin) QS: scanning...';

    execFile(qsPath, ['scan', cwd, '--quiet', '--format', 'json'], { maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
        if (err && !stdout) {
            statusBarItem.text = '$(shield) QS: error';
            return;
        }
        try {
            const result: ScanResult = JSON.parse(stdout);
            lastScanResult = result;
            updateDiagnostics(result);
            const score = Math.round(result.summary.quantum_readiness);
            statusBarItem.text = `$(shield) QS: ${score}/100`;
            if (score < 20) statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            else if (score < 50) statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            else statusBarItem.backgroundColor = undefined;
        } catch (e) {
            statusBarItem.text = '$(shield) QS: --/100';
        }
    });
}

function scanFile(uri: vscode.Uri) {
    const qsPath = getQSPath();
    execFile(qsPath, ['scan', uri.fsPath, '--quiet', '--format', 'json'], { maxBuffer: 5 * 1024 * 1024 }, (err, stdout) => {
        if (err && !stdout) return;
        try {
            const result: ScanResult = JSON.parse(stdout);
            updateDiagnosticsForFile(uri, result.findings);
        } catch (e) { /* ignore parse errors */ }
    });
}

function updateDiagnostics(result: ScanResult) {
    diagnosticCollection.clear();
    const diagMap = new Map<string, vscode.Diagnostic[]>();

    for (const f of result.findings) {
        const uri = vscode.Uri.file(f.file_path);
        const key = uri.toString();
        if (!diagMap.has(key)) diagMap.set(key, []);

        const line = Math.max(0, f.line_start - 1);
        const range = new vscode.Range(line, 0, line, 1000);

        const severity = f.severity <= 1 ? vscode.DiagnosticSeverity.Error
            : f.severity === 2 ? vscode.DiagnosticSeverity.Warning
            : vscode.DiagnosticSeverity.Information;

        const threatName = f.quantum_threat === 0 ? "Shor's algorithm" : f.quantum_threat === 1 ? "Grover's algorithm" : "N/A";
        const msg = `${f.algorithm}: ${f.description}${f.replacement_algo ? ` → Replace with ${f.replacement_algo}` : ''}`;

        const diag = new vscode.Diagnostic(range, msg, severity);
        diag.source = 'QuantumShield';
        diag.code = f.algorithm;

        diagMap.get(key)!.push(diag);
    }

    for (const [key, diags] of diagMap) {
        diagnosticCollection.set(vscode.Uri.parse(key), diags);
    }
}

function updateDiagnosticsForFile(uri: vscode.Uri, findings: Finding[]) {
    const diags: vscode.Diagnostic[] = [];
    for (const f of findings) {
        const line = Math.max(0, f.line_start - 1);
        const range = new vscode.Range(line, 0, line, 1000);
        const severity = f.severity <= 1 ? vscode.DiagnosticSeverity.Error
            : f.severity === 2 ? vscode.DiagnosticSeverity.Warning
            : vscode.DiagnosticSeverity.Information;
        const msg = `${f.algorithm}: ${f.description}${f.replacement_algo ? ` → ${f.replacement_algo}` : ''}`;
        const diag = new vscode.Diagnostic(range, msg, severity);
        diag.source = 'QuantumShield';
        diag.code = f.algorithm;
        diags.push(diag);
    }
    diagnosticCollection.set(uri, diags);
}

class QuantumShieldCodeLensProvider implements vscode.CodeLensProvider {
    provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
        if (!lastScanResult) return [];
        const lenses: vscode.CodeLens[] = [];
        for (const f of lastScanResult.findings) {
            if (f.file_path !== document.uri.fsPath) continue;
            const line = Math.max(0, f.line_start - 1);
            const range = new vscode.Range(line, 0, line, 0);
            const repl = f.replacement_algo || 'PQC alternative';
            lenses.push(new vscode.CodeLens(range, {
                title: `⚡ Quantum-vulnerable: ${f.algorithm} → ${repl}`,
                command: '',
            }));
        }
        return lenses;
    }
}

class QuantumShieldCodeActionProvider implements vscode.CodeActionProvider {
    provideCodeActions(document: vscode.TextDocument, range: vscode.Range): vscode.CodeAction[] {
        if (!lastScanResult) return [];
        const actions: vscode.CodeAction[] = [];
        for (const f of lastScanResult.findings) {
            if (f.file_path !== document.uri.fsPath) continue;
            if (f.line_start - 1 !== range.start.line) continue;
            if (!f.replacement_algo) continue;

            const action = new vscode.CodeAction(
                `Replace ${f.algorithm} with ${f.replacement_algo}`,
                vscode.CodeActionKind.QuickFix
            );
            action.diagnostics = [];
            action.isPreferred = true;
            actions.push(action);
        }
        return actions;
    }
}

class QuantumShieldHoverProvider implements vscode.HoverProvider {
    provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | null {
        if (!lastScanResult) return null;
        for (const f of lastScanResult.findings) {
            if (f.file_path !== document.uri.fsPath) continue;
            if (f.line_start - 1 !== position.line) continue;

            const threatName = f.quantum_threat === 0 ? "Shor's algorithm (complete break)"
                : f.quantum_threat === 1 ? "Grover's algorithm (weakened)" : "Not directly threatened";
            const sevName = ['Critical', 'High', 'Medium', 'Low'][f.severity] || 'Unknown';

            const md = new vscode.MarkdownString();
            md.appendMarkdown(`### ⚠️ QuantumShield: ${f.algorithm}\n\n`);
            md.appendMarkdown(`| Property | Value |\n|---|---|\n`);
            md.appendMarkdown(`| Severity | **${sevName}** |\n`);
            md.appendMarkdown(`| Quantum Threat | ${threatName} |\n`);
            md.appendMarkdown(`| Replacement | ${f.replacement_algo || 'See migration guide'} |\n`);
            md.appendMarkdown(`| Confidence | ${(f.confidence * 100).toFixed(0)}% |\n`);
            if (f.replacement_algo) {
                md.appendMarkdown(`\n---\n**Migrate to ${f.replacement_algo}** for quantum safety.\n`);
            }
            return new vscode.Hover(md);
        }
        return null;
    }
}

export function deactivate() {
    if (diagnosticCollection) diagnosticCollection.dispose();
    if (statusBarItem) statusBarItem.dispose();
}
