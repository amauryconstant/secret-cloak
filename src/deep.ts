import { getPlaceholderRegex } from './session'
import { redactWithMatches } from './engine'
import { scanWithGitleaks } from './detector'
import type { PlaceholderSession } from './types'

export function restoreText(
    input: string,
    session: { lookup(ph: string): string | undefined }
): string {
    const text = String(input ?? '')
    if (!text) return text
    const re = getPlaceholderRegex()
    return text.replace(re, (ph) => session.lookup(ph) ?? ph)
}

function isPlainObject(value: unknown): boolean {
    if (!value || typeof value !== 'object') return false
    if (Array.isArray(value)) return false
    const proto = Object.getPrototypeOf(value)
    return proto === Object.prototype || proto === null
}

export function restoreDeep(
    value: unknown,
    session: { lookup(ph: string): string | undefined }
): void {
    const seen = new WeakSet()

    const walk = (node: unknown): void => {
        if (!node || typeof node !== 'object') return
        if (seen.has(node)) return
        seen.add(node)

        if (Array.isArray(node)) {
            for (let i = 0; i < node.length; i++) {
                const v = node[i]
                if (typeof v === 'string') node[i] = restoreText(v, session)
                if (v && typeof v === 'object') walk(v)
            }
            return
        }

        if (!isPlainObject(node)) return

        for (const key of Object.keys(node)) {
            const v = (node as Record<string, unknown>)[key]
            if (typeof v === 'string')
                (node as Record<string, unknown>)[key] = restoreText(v, session)
            if (v && typeof v === 'object') walk(v)
        }
    }

    walk(value)
}

export async function redactDeep(
    value: unknown,
    session: PlaceholderSession,
    gitleaksPath?: string | null
): Promise<void> {
    const seen = new WeakSet()

    const walk = async (node: unknown): Promise<void> => {
        if (!node || typeof node !== 'object') return
        if (seen.has(node)) return
        seen.add(node)

        if (Array.isArray(node)) {
            for (let i = 0; i < node.length; i++) {
                const v = node[i]
                if (v && typeof v === 'object') {
                    await walk(v)
                } else if (typeof v === 'string') {
                    const findings = await scanWithGitleaks(v, gitleaksPath)
                    if (findings.length) {
                        const { text } = redactWithMatches(v, session, findings)
                        node[i] = text
                    }
                }
            }
            return
        }

        if (!isPlainObject(node)) return

        for (const key of Object.keys(node)) {
            const v = (node as Record<string, unknown>)[key]
            if (v && typeof v === 'object') {
                await walk(v)
            } else if (typeof v === 'string') {
                const findings = await scanWithGitleaks(v, gitleaksPath)
                if (findings.length) {
                    const { text } = redactWithMatches(v, session, findings)
                    ;(node as Record<string, unknown>)[key] = text
                }
            }
        }
    }

    await walk(value)
}
