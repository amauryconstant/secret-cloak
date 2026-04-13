import type { GitleaksFinding } from './types'

let cachedPath: string | null = null

export async function findGitleaks(): Promise<string | null> {
    if (cachedPath !== null) return cachedPath
    try {
        const proc = Bun.spawn(['sh', '-c', 'command -v gitleaks'], {
            stdio: ['pipe', 'pipe', 'pipe'],
        })
        const exitCode = await proc.exited
        if (exitCode !== 0) {
            cachedPath = null
            return null
        }
        const out = await proc.stdout.text()
        cachedPath = out.trim() || null
        return cachedPath
    } catch {
        cachedPath = null
        return null
    }
}

export function lineColToOffset(
    text: string,
    line: number,
    col: number
): number {
    const lines = text.split(/\r?\n/)
    let offset = 0
    for (let i = 0; i < line - 1 && i < lines.length; i++) {
        const lineEnd = offset + lines[i].length
        if (text[lineEnd] === '\r') {
            offset += lines[i].length + 2
        } else {
            offset += lines[i].length + 1
        }
    }
    return offset + col - 1
}

export function parseGitleaksOutput(
    jsonText: string,
    text: string
): GitleaksFinding[] {
    const findings = JSON.parse(jsonText)
    const results: GitleaksFinding[] = []
    for (const f of findings) {
        const start = lineColToOffset(text, f.StartLine, f.StartColumn)
        const end = lineColToOffset(text, f.EndLine, f.EndColumn)
        results.push({
            start,
            end,
            match: f.Match,
            category: f.RuleID,
            secret: f.Secret,
        })
    }
    return results
}

export async function scanWithGitleaks(
    text: string,
    gitleaksPath?: string | null,
    exclude: string[] = [],
    debug = false
): Promise<GitleaksFinding[]> {
    const path = gitleaksPath ?? (await findGitleaks())
    if (!path) return []

    const timeoutMs = 30000

    const proc = Bun.spawn(
        [
            path,
            'stdin',
            '-r',
            '-',
            '-f',
            'json',
            '--redact=0',
            '--no-banner',
            '--log-level=warn',
        ],
        { stdio: ['pipe', 'pipe', 'pipe'] }
    )

    void proc.stdin.write(text)
    void proc.stdin.end()

    let killed = false

    const timeoutId = setTimeout(() => {
        killed = true
        proc.kill()
    }, timeoutMs)

    let exitCode = -1
    let stdoutText = ''

    try {
        exitCode = await proc.exited
    } catch {
        clearTimeout(timeoutId)
        if (debug) console.error(`[secret-cloak] gitleaks: spawn error`)
        return []
    }

    try {
        stdoutText = await proc.stdout.text()
    } catch {
        clearTimeout(timeoutId)
        return []
    }

    clearTimeout(timeoutId)

    if (killed) return []

    if (exitCode !== 0) {
        if (debug)
            console.error(`[secret-cloak] gitleaks: exit code ${exitCode}`)
        return []
    }

    if (stdoutText.trim()) {
        try {
            const results = parseGitleaksOutput(stdoutText.trim(), text)
            return results.filter((f) => !exclude.includes(f.category))
        } catch {
            return []
        }
    }

    return []
}
