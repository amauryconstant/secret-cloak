import path from 'node:path'
import type { SecretCloakConfig } from './types'

function fileExists(path: string): Promise<boolean> {
    return Bun.file(path).exists()
}

async function readTextFile(path: string): Promise<string | null> {
    const file = Bun.file(path)
    if (!(await file.exists())) return null
    try {
        return await file.text()
    } catch {
        return null
    }
}

function homedir(): string {
    return (
        process.env.HOME ??
        process.env.USERPROFILE ??
        process.env.HOMEPATH ??
        '/'
    )
}

function clamp(value: number, min: number, max: number): number {
    return Math.max(min, Math.min(value, max))
}

async function readJson(filepath: string): Promise<unknown> {
    const text = await readTextFile(filepath)
    if (!text) return null
    try {
        return JSON.parse(text)
    } catch {
        return null
    }
}

function normalizeConfig(raw: unknown): SecretCloakConfig {
    const cfg =
        raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}

    const enabled = Boolean(cfg.enabled ?? true)
    const debug = Boolean(cfg.debug ?? false)

    const sessionRaw =
        cfg.session && typeof cfg.session === 'object'
            ? (cfg.session as Record<string, unknown>)
            : {}
    const ttlMs =
        typeof sessionRaw.ttlMs === 'number' &&
        Number.isFinite(sessionRaw.ttlMs)
            ? clamp(sessionRaw.ttlMs, 1000, 86400000)
            : 3600000
    const maxSessions =
        typeof sessionRaw.maxSessions === 'number' &&
        Number.isFinite(sessionRaw.maxSessions)
            ? clamp(sessionRaw.maxSessions, 1, 10000)
            : 1000
    const maxMappings =
        typeof sessionRaw.maxMappings === 'number' &&
        Number.isFinite(sessionRaw.maxMappings)
            ? clamp(sessionRaw.maxMappings, 100, 1_000_000)
            : 100000

    const gitleaksRaw =
        cfg.gitleaks && typeof cfg.gitleaks === 'object'
            ? (cfg.gitleaks as Record<string, unknown>)
            : {}
    const gitleaksPath =
        typeof gitleaksRaw.path === 'string' ? gitleaksRaw.path : null

    const patternsRaw =
        gitleaksRaw.patterns && typeof gitleaksRaw.patterns === 'object'
            ? (gitleaksRaw.patterns as Record<string, unknown>)
            : {}
    const patternsExclude = Array.isArray(patternsRaw.exclude)
        ? (patternsRaw.exclude as string[])
        : []

    return {
        enabled,
        debug,
        session: { ttlMs, maxSessions, maxMappings },
        gitleaks: {
            path: gitleaksPath,
            patterns: {
                exclude: patternsExclude,
            },
        },
    }
}

export function getConfigCandidates(directory: string): string[] {
    const dir = String(directory ?? process.cwd())
    const home = homedir()
    const globalConfig = path.join(
        home,
        '.config',
        'opencode',
        'secret-cloak.config.json'
    )
    const projectRoot = path.join(dir, 'secret-cloak.config.json')
    const projectLocal = path.join(dir, '.opencode', 'secret-cloak.config.json')

    const env = process.env.OPENCODE_SECRET_CLOAK_CONFIG
    if (env)
        return [path.resolve(dir, env), projectRoot, projectLocal, globalConfig]

    return [projectRoot, projectLocal, globalConfig]
}

export async function loadConfig(
    directory: string
): Promise<SecretCloakConfig & { loadedFrom: string }> {
    const candidates = getConfigCandidates(directory)
    for (const file of candidates) {
        if (!file) continue
        if (!(await fileExists(file))) continue
        const raw = await readJson(file)
        if (!raw) continue
        const cfg = normalizeConfig(raw)
        return { ...cfg, loadedFrom: file }
    }
    return {
        enabled: false,
        debug: false,
        session: { ttlMs: 3600000, maxSessions: 1000, maxMappings: 100000 },
        gitleaks: { path: null, patterns: { exclude: [] } },
        loadedFrom: '',
    }
}
