import type { SessionStore } from './types'
import { createHmac, randomBytes } from 'node:crypto'

function sanitizeCategory(input: unknown): string {
    // eslint-disable-next-line no-base-to-string
    const raw = input == null ? '' : String(input).trim()
    if (!raw) return 'TEXT'
    const upper = raw.toUpperCase()
    const safe = upper
        .replace(/[^A-Z0-9_]/g, '_')
        .replace(/_+/g, '_')
        .replace(/^_+|_+$/g, '')
    return safe || 'TEXT'
}

function toHexLower(buffer: Uint8Array): string {
    return Buffer.from(buffer).toString('hex')
}

function createHmacSha256(secret: Uint8Array, data: string): Uint8Array {
    const h = createHmac('sha256', secret)
    h.update(data)
    return h.digest()
}

export class PlaceholderSession {
    private readonly prefix = '__SC_'
    private readonly ttlMs: number
    private readonly maxMappings: number
    private readonly secret: Uint8Array
    private store: SessionStore = {
        forward: new Map(),
        reverse: new Map(),
        created: new Map(),
    }

    constructor(
        options: {
            ttlMs?: number
            maxMappings?: number
            secret?: Uint8Array
        } = {}
    ) {
        this.ttlMs =
            options.ttlMs && Number.isFinite(options.ttlMs) && options.ttlMs > 0
                ? options.ttlMs
                : 60 * 60 * 1000
        this.maxMappings =
            options.maxMappings &&
            Number.isFinite(options.maxMappings) &&
            options.maxMappings > 0
                ? options.maxMappings
                : 100000
        this.secret = options.secret ?? randomBytes(32)
    }

    cleanup(now = Date.now()): void {
        if (this.ttlMs <= 0) return
        for (const [placeholder, createdAt] of this.store.created.entries()) {
            if (now - createdAt > this.ttlMs) {
                const original = this.store.forward.get(placeholder)
                this.store.forward.delete(placeholder)
                this.store.created.delete(placeholder)
                if (original !== undefined) this.store.reverse.delete(original)
            }
        }
    }

    evictOldest(): void {
        let oldestPlaceholder = ''
        let oldestTime = Infinity
        for (const [placeholder, createdAt] of this.store.created.entries()) {
            if (createdAt < oldestTime) {
                oldestTime = createdAt
                oldestPlaceholder = placeholder
            }
        }
        if (!oldestPlaceholder) return
        const original = this.store.forward.get(oldestPlaceholder)
        this.store.forward.delete(oldestPlaceholder)
        this.store.created.delete(oldestPlaceholder)
        if (original !== undefined) this.store.reverse.delete(original)
    }

    evictIfNeeded(): void {
        while (this.store.forward.size >= this.maxMappings) {
            this.evictOldest()
        }
    }

    destroy(): void {
        this.store.forward.clear()
        this.store.reverse.clear()
        this.store.created.clear()
    }

    lookup(placeholder: string): string | undefined {
        return this.store.forward.get(placeholder)
    }

    lookupReverse(original: string): string | undefined {
        return this.store.reverse.get(original)
    }

    private generatePlaceholder(original: string, category: string): string {
        const cat = sanitizeCategory(category)
        const hash = createHmacSha256(this.secret, original)
        const hash20 = toHexLower(hash).slice(0, 20)
        return `${this.prefix}${cat}_${hash20}__`
    }

    getOrCreatePlaceholder(original: string, category: string): string {
        const existing = this.store.reverse.get(original)
        if (existing) return existing

        this.cleanup()

        while (this.store.forward.size >= this.maxMappings) {
            this.evictOldest()
        }

        const base = this.generatePlaceholder(original, category)
        if (!this.store.forward.has(base)) {
            const now = Date.now()
            this.store.forward.set(base, original)
            this.store.reverse.set(original, base)
            this.store.created.set(base, now)
            return base
        }

        if (this.store.forward.get(base) === original) {
            const now = Date.now()
            this.store.reverse.set(original, base)
            this.store.created.set(base, now)
            return base
        }

        const withoutSuffix = base.slice(0, -2)
        for (let i = 2; ; i++) {
            if (i > 10000) {
                this.evictOldest()
                break
            }
            const candidate = `${withoutSuffix}_${i}__`
            if (!this.store.forward.has(candidate)) {
                const now = Date.now()
                this.store.forward.set(candidate, original)
                this.store.reverse.set(original, candidate)
                this.store.created.set(candidate, now)
                return candidate
            }
            if (this.store.forward.get(candidate) === original) {
                const now = Date.now()
                this.store.reverse.set(original, candidate)
                this.store.created.set(candidate, now)
                return candidate
            }
        }
        return this.getOrCreatePlaceholder(original, category)
    }
}

export function getPlaceholderRegex(): RegExp {
    return /__SC_[A-Za-z0-9_]+_[a-f0-9]{20}(?:_\d+)?__/g
}
