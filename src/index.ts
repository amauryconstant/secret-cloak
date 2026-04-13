import type { Plugin } from '@opencode-ai/plugin'
import { loadConfig } from './config'
import { scanWithGitleaks } from './detector'
import { PlaceholderSession } from './session'
import type { GitleaksFinding } from './types'
import { redactWithMatches } from './engine'
import { redactDeep, restoreDeep, restoreText } from './deep'

export const SecretCloak: Plugin = async ({ directory }) => {
    const config = await loadConfig(directory)
    const debug =
        Boolean(process.env.OPENCODE_SECRET_CLOAK_DEBUG) || config.debug

    if (debug) {
        const from = config.loadedFrom || 'not found (plugin will no-op)'
        console.log(`[secret-cloak] config: ${from} enabled=${config.enabled}`)
    }

    if (!config.enabled) return {}

    const sessions = new Map<
        string,
        { session: PlaceholderSession; lastAccessed: number }
    >()
    let lastPeriodicCleanup = 0

    const cleanupSessions = () => {
        const now = Date.now()
        for (const [id, entry] of sessions.entries()) {
            if (now - entry.lastAccessed > config.session.ttlMs) {
                entry.session.destroy()
                sessions.delete(id)
            }
        }
    }

    const getSession = (sessionID: string): PlaceholderSession | null => {
        if (!sessionID) return null

        const existing = sessions.get(sessionID)
        if (existing) {
            existing.lastAccessed = Date.now()
            existing.session.cleanup()
            return existing.session
        }

        const now = Date.now()
        if (now - lastPeriodicCleanup > config.session.ttlMs) {
            cleanupSessions()
            lastPeriodicCleanup = now
        }

        if (sessions.size >= config.session.maxSessions) {
            let oldestID = ''
            let oldestTime = Infinity
            for (const [id, entry] of sessions.entries()) {
                if (entry.lastAccessed < oldestTime) {
                    oldestTime = entry.lastAccessed
                    oldestID = id
                }
            }
            if (oldestID) {
                sessions.get(oldestID)?.session.destroy()
                sessions.delete(oldestID)
            }
        }
        const created = new PlaceholderSession({
            ttlMs: config.session.ttlMs,
            maxMappings: config.session.maxMappings,
        })
        sessions.set(sessionID, { session: created, lastAccessed: Date.now() })
        return created
    }

    return {
        'experimental.chat.messages.transform': async (_input, output) => {
            const msgs = output?.messages
            if (!Array.isArray(msgs) || msgs.length === 0) return

            const sessionID = msgs[0]?.info?.sessionID ?? ''
            const session = getSession(sessionID)
            if (!session) return

            let changed = 0

            for (const msg of msgs) {
                const parts = Array.isArray(msg?.parts) ? msg.parts : []
                for (const part of parts) {
                    if (!part) continue

                    if (part.type === 'text') {
                        if (
                            part.ignored ||
                            !part.text ||
                            typeof part.text !== 'string'
                        )
                            continue
                        let findings
                        try {
                            findings = await scanWithGitleaks(
                                part.text,
                                config.gitleaks.path,
                                config.gitleaks.patterns.exclude,
                                debug
                            )
                        } catch {
                            continue
                        }
                        if (!findings.length) continue
                        const { text } = redactWithMatches(
                            part.text,
                            session,
                            findings
                        )
                        if (text !== part.text) {
                            part.text = text
                            changed++
                        }
                        continue
                    }

                    if (part.type === 'reasoning') {
                        if (!part.text || typeof part.text !== 'string')
                            continue
                        let findings
                        try {
                            findings = await scanWithGitleaks(
                                part.text,
                                config.gitleaks.path,
                                config.gitleaks.patterns.exclude,
                                debug
                            )
                        } catch {
                            continue
                        }
                        if (!findings.length) continue
                        const { text } = redactWithMatches(
                            part.text,
                            session,
                            findings
                        )
                        if (text !== part.text) {
                            part.text = text
                            changed++
                        }
                        continue
                    }

                    if (part.type === 'tool') {
                        const state = part.state
                        if (!state || typeof state !== 'object') continue

                        if (state.input && typeof state.input === 'object') {
                            try {
                                await redactDeep(
                                    state.input,
                                    session,
                                    config.gitleaks.path
                                )
                            } catch {}
                        }

                        if (
                            state.status === 'completed' &&
                            typeof state.output === 'string'
                        ) {
                            let findings: GitleaksFinding[] = []
                            try {
                                findings = await scanWithGitleaks(
                                    state.output,
                                    config.gitleaks.path,
                                    config.gitleaks.patterns.exclude,
                                    debug
                                )
                            } catch {
                                findings = []
                            }
                            if (findings.length) {
                                const { text } = redactWithMatches(
                                    state.output,
                                    session,
                                    findings
                                )
                                state.output = text
                                changed++
                            }
                        }
                        if (
                            state.status === 'error' &&
                            typeof state.error === 'string'
                        ) {
                            let findings: GitleaksFinding[] = []
                            try {
                                findings = await scanWithGitleaks(
                                    state.error,
                                    config.gitleaks.path,
                                    config.gitleaks.patterns.exclude,
                                    debug
                                )
                            } catch {
                                findings = []
                            }
                            if (findings.length) {
                                const { text } = redactWithMatches(
                                    state.error,
                                    session,
                                    findings
                                )
                                state.error = text
                                changed++
                            }
                        }
                        if (
                            state.status === 'pending' &&
                            typeof state.raw === 'string'
                        ) {
                            let findings: GitleaksFinding[] = []
                            try {
                                findings = await scanWithGitleaks(
                                    state.raw,
                                    config.gitleaks.path,
                                    config.gitleaks.patterns.exclude,
                                    debug
                                )
                            } catch {
                                findings = []
                            }
                            if (findings.length) {
                                const { text } = redactWithMatches(
                                    state.raw,
                                    session,
                                    findings
                                )
                                state.raw = text
                                changed++
                            }
                        }
                    }
                }
            }

            if (debug && changed > 0) {
                console.log(
                    `[secret-cloak] redacted ${changed} text parts before LLM request`
                )
            }
        },

        'experimental.text.complete': async (input, output) => {
            if (!output || typeof output !== 'object') return
            if (typeof output.text !== 'string' || !output.text) return
            const session = getSession(input?.sessionID ?? '')
            if (!session) return
            const before = output.text
            const after = restoreText(before, session)
            if (after !== before) {
                output.text = after
                if (debug)
                    console.log(
                        '[secret-cloak] restored placeholders in LLM response'
                    )
            }
        },

        'tool.execute.before': async (input, output) => {
            const session = getSession(input?.sessionID ?? '')
            if (!session) return
            if (output?.args && typeof output.args === 'object') {
                restoreDeep(output.args, session)
            }
        },
    }
}
