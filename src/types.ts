export interface SessionConfig {
    ttlMs: number
    maxSessions: number
    maxMappings: number
}

export interface GitleaksPatternsConfig {
    exclude: string[]
}

export interface GitleaksConfig {
    path: string | null
    patterns: GitleaksPatternsConfig
}

export interface PlaceholderMapping {
    placeholder: string
    original: string
    createdAt: number
}

export interface SessionStore {
    forward: Map<string, string>
    reverse: Map<string, string>
    created: Map<string, number>
}

export interface SecretCloakConfig {
    enabled: boolean
    debug: boolean
    session: SessionConfig
    gitleaks: GitleaksConfig
}

export interface RedactResult {
    text: string
    matches: Array<{
        start: number
        end: number
        original: string
        category: string
        placeholder: string
    }>
}

export type Message = {
    info: {
        id: string
        sessionID: string
        role: string
    }
    parts: Part[]
}

export type Part = TextPart | ReasoningPart | ToolPart

export interface TextPart {
    type: 'text'
    text: string
    ignored?: boolean
}

export interface ReasoningPart {
    type: 'reasoning'
    text: string
}

export interface ToolPart {
    type: 'tool'
    state: {
        input?: Record<string, unknown>
        output?: string
        error?: string
        raw?: string
        status?: 'pending' | 'completed' | 'error'
    }
}

export interface ChatMessagesTransformOutput {
    messages: Message[]
}

export interface GitleaksFinding {
    start: number
    end: number
    match: string
    category: string
    secret: string
}

export interface PlannedMatch {
    start: number
    end: number
    original: string
    category: string
    placeholder: string
}

export interface PlaceholderSession {
    lookup(ph: string): string | undefined
    getOrCreatePlaceholder(original: string, category: string): string
    cleanup(now?: number): void
    destroy(): void
}
